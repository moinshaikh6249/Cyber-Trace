import hashlib
import mimetypes
import os
import re
import shutil
import sqlite3
import stat
import sys
from datetime import datetime

from PySide6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    QSettings,
    QSize,
    QRectF,
    QTimer,
    Qt,
    QThread,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QIcon, QBrush, QPen, QPainter, QFontMetrics
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGraphicsOpacityEffect,
    QGraphicsLineItem,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsTextItem,
    QGraphicsView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QListWidget,
    QListWidgetItem,
    QSlider,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QCheckBox,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from evidence.file_analysis import get_file_analysis
from database.db import (
    add_custody_event,
    create_analysis,
    create_case,
    create_evidence_with_custody,
    create_note,
    delete_case,
    delete_note,
    get_active_case_count,
    get_analyses_for_case,
    get_analyses_for_evidence,
    get_automated_case_summary,
    get_case,
    get_case_health,
    get_case_lifecycle_stage,
    get_cases,
    get_correlation_findings,
    get_custody_events,
    get_evidence,
    get_evidence_attention_flags,
    get_evidence_by_id,
    get_evidence_count,
    get_evidence_for_case,
    get_evidence_relationship_data,
    get_forensic_analytics_summary,
    get_current_evidence_status,
    get_next_case_id,
    get_notes,
    get_verified_evidence_count,
    initialize_database,
    replace_correlation_findings,
    update_case,
    verify_custody_chain,
)
from evidence.correlation import CorrelationConfig, analyze_evidence



# =========================================================
# PATH & SECURITY HELPERS
# =========================================================

def get_app_dir():
    """Return root directory for writable application data."""
    if getattr(sys, "frozen", False):
        local_appdata = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        return os.path.join(local_appdata, "CyberTrace")
    return os.path.dirname(os.path.abspath(__file__))


def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and invalid characters."""
    clean_name = os.path.basename(filename)
    clean_name = re.sub(r'[\\/*?:"<>|]', "_", clean_name)
    clean_name = clean_name.strip(" .")
    return clean_name or "evidence_file"


def protect_evidence_file(file_path):
    """Set Windows read-only attribute on preserved evidence copy."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            "The preserved evidence copy could not be found for protection."
        )

    os.chmod(file_path, stat.S_IREAD)
    if os.stat(file_path).st_mode & stat.S_IWRITE:
        raise PermissionError(
            "The preserved evidence copy remains writable after protection."
        )


def unprotect_evidence_file(file_path):
    """Temporarily remove read-only attribute if cleanup is required."""
    try:
        if os.path.exists(file_path):
            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            return True
    except Exception:
        return False
    return True


def cleanup_acquisition_copy(file_path, copy_created):
    """Remove only a preserved copy created by the current acquisition attempt."""
    if not copy_created or not os.path.exists(file_path):
        return None

    if not unprotect_evidence_file(file_path):
        return "The failed preserved copy could not be made writable for cleanup."

    try:
        os.remove(file_path)
    except OSError as error:
        return str(error)
    return None


def calculate_sha256(file_path):
    """Calculate SHA-256 using 1 MB chunks in read-only binary mode."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


# =========================================================
# ASYNCHRONOUS WORKERS FOR LARGE FILE OPERATIONS
# =========================================================

class AcquisitionWorker(QThread):
    """Worker thread for hashing and copying evidence files without freezing GUI."""
    progress_signal = Signal(str)
    finished_signal = Signal(dict)
    error_signal = Signal(str)

    def __init__(self, original_path, preserved_path, parent=None):
        super().__init__(parent)
        self.original_path = original_path
        self.preserved_path = preserved_path
        self.copy_created = False

    def run(self):
        try:
            if self.isInterruptionRequested():
                return
            self.progress_signal.emit("Calculating original SHA-256 hash...")
            original_hash = calculate_sha256(self.original_path)

            if self.isInterruptionRequested():
                return
            self.progress_signal.emit("Creating controlled evidence copy...")
            if os.path.exists(self.preserved_path):
                raise FileExistsError(
                    "The planned preserved evidence path already exists."
                )
            shutil.copy2(self.original_path, self.preserved_path)
            self.copy_created = True
            protect_evidence_file(self.preserved_path)

            if self.isInterruptionRequested():
                cleanup_acquisition_copy(self.preserved_path, self.copy_created)
                return
            self.progress_signal.emit("Verifying preserved copy SHA-256 hash...")
            preserved_hash = calculate_sha256(self.preserved_path)

            if self.isInterruptionRequested():
                return

            if original_hash != preserved_hash:
                raise ValueError(
                    "The SHA-256 hash of the preserved copy does not match the original file."
                )

            if not self.isInterruptionRequested():
                self.finished_signal.emit({
                    "original_hash": original_hash,
                    "preserved_hash": preserved_hash,
                })
        except Exception as error:
            cleanup_acquisition_copy(self.preserved_path, self.copy_created)
            if not self.isInterruptionRequested():
                self.error_signal.emit(str(error))

class AnalysisWorker(QThread):
    """Worker thread for analyzing preserved evidence copies off main GUI thread."""
    finished_signal = Signal(dict)
    error_signal = Signal(str)

    def __init__(self, preserved_path, parent=None):
        super().__init__(parent)
        self.preserved_path = preserved_path

    def run(self):
        try:
            if self.isInterruptionRequested():
                return
            result = get_file_analysis(self.preserved_path)
            if not self.isInterruptionRequested():
                self.finished_signal.emit(result)
        except Exception as error:
            if not self.isInterruptionRequested():
                self.error_signal.emit(str(error))


class CorrelationWorker(QThread):
    """Run deterministic cross-evidence correlation away from the GUI thread."""
    finished_signal = Signal(dict)
    error_signal = Signal(str)

    def __init__(self, case_id, include_contextual=False, parent=None):
        super().__init__(parent)
        self.case_id = case_id
        self.include_contextual = include_contextual

    def run(self):
        try:
            if self.isInterruptionRequested():
                return
            evidence_items = get_evidence_for_case(self.case_id)
            result = analyze_evidence(
                evidence_items,
                CorrelationConfig(include_contextual=self.include_contextual),
            )
            if self.isInterruptionRequested():
                return
            replace_correlation_findings(self.case_id, result["findings"])
            result["case_id"] = self.case_id
            if not self.isInterruptionRequested():
                self.finished_signal.emit(result)
        except Exception as error:
            if not self.isInterruptionRequested():
                self.error_signal.emit(str(error))


# =========================================================
# IMPACT LAYER UI COMPONENTS
# =========================================================

class ForensicBarMeter(QWidget):
    """Custom PySide6 bar meter displaying category distribution metrics."""

    def __init__(self, title, items, theme="dark", parent=None):
        super().__init__(parent)
        self.items = items
        self.theme = theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        text_title_color = "#1f2328" if theme == "light" else "#ecf0f1"
        text_label_color = "#656d76" if theme == "light" else "#bdc3c7"
        bar_bg_color = "#e1e4e8" if theme == "light" else "#1a252f"
        bar_border_color = "#d0d7de" if theme == "light" else "#2c3e50"

        if title:
            lbl_title = QLabel(title)
            lbl_title.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {text_title_color};")
            layout.addWidget(lbl_title)

        total_count = sum(item.get("count", 0) for item in items)

        for item in items:
            row = QHBoxLayout()
            row.setSpacing(10)

            name_lbl = QLabel(item["label"])
            name_lbl.setMinimumWidth(150)
            name_lbl.setStyleSheet(f"color: {text_label_color}; font-size: 12px;")

            bar = QProgressBar()
            bar.setRange(0, total_count if total_count > 0 else 1)
            bar.setValue(item.get("count", 0))
            bar.setTextVisible(False)
            bar.setFixedHeight(12)

            color = item.get("color", "#3498db")
            if theme == "light":
                if color == "#2ecc71":
                    color = "#1a7f37"
                elif color == "#3498db":
                    color = "#0969da"
                elif color == "#f1c40f":
                    color = "#d97706"
                elif color == "#e74c3c":
                    color = "#cf222e"

            bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: {bar_bg_color};
                    border: 1px solid {bar_border_color};
                    border-radius: 6px;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 5px;
                }}
            """)

            cnt = item.get("count", 0)
            pct = (cnt / total_count * 100) if total_count > 0 else 0
            val_lbl = QLabel(f"{cnt} ({pct:.1f}%)")
            val_lbl.setMinimumWidth(85)
            val_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            val_lbl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px;")

            row.addWidget(name_lbl)
            row.addWidget(bar, 1)
            row.addWidget(val_lbl)

            layout.addLayout(row)

        min_h = 35 + len(items) * 32
        self.setMinimumHeight(min_h)

    def sizeHint(self):
        min_h = 35 + len(self.items) * 32
        return QSize(400, min_h)

    def minimumSizeHint(self):
        min_h = 35 + len(self.items) * 32
        return QSize(300, min_h)


class LifecycleWidget(QWidget):
    """Visual 8-stage investigation lifecycle stage tracker."""

    def __init__(self, stages, theme="dark", parent=None):
        super().__init__(parent)
        self.stages = stages
        self.theme = theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        title_color = "#1f2328" if theme == "light" else "#ecf0f1"
        step_color = "#656d76" if theme == "light" else "#95a5a6"
        name_color = "#1f2328" if theme == "light" else "#ffffff"
        detail_color = "#57606a" if theme == "light" else "#bdc3c7"

        title = QLabel("8-Stage Investigation Lifecycle Tracker")
        title.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {title_color};")
        layout.addWidget(title)

        grid = QHBoxLayout()
        grid.setSpacing(6)

        for i, s in enumerate(stages, 1):
            card = QFrame()
            card.setObjectName("panel")
            card.setMinimumHeight(165)

            st = s.get("status", "pending")
            if st == "completed":
                border_color = "#2da44e" if theme == "light" else "#2ecc71"
                bg_color = "#dafbe1" if theme == "light" else "#1b3a2b"
                icon = "✓"
            elif st == "attention":
                border_color = "#cf222e" if theme == "light" else "#e74c3c"
                bg_color = "#ffebe9" if theme == "light" else "#3a1b1b"
                icon = "⚠"
            else:
                border_color = "#d0d7de" if theme == "light" else "#4a5568"
                bg_color = "#f6f8fa" if theme == "light" else "#1e293b"
                icon = "⏳"

            card.setStyleSheet(f"""
                QFrame#panel {{
                    background-color: {bg_color};
                    border: 1px solid {border_color};
                    border-radius: 8px;
                    padding: 6px;
                }}
            """)

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(6, 8, 6, 8)
            card_layout.setSpacing(4)

            step_lbl = QLabel(f"Stage 0{i}")
            step_lbl.setStyleSheet(f"font-size: 10px; color: {step_color}; font-weight: bold;")
            step_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

            icon_lbl = QLabel(f"{icon}")
            icon_lbl.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {border_color};")
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

            name_lbl = QLabel(s["stage"])
            name_lbl.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {name_color};")
            name_lbl.setWordWrap(True)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

            detail_lbl = QLabel(s.get("details", ""))
            detail_lbl.setStyleSheet(f"font-size: 9px; color: {detail_color};")
            detail_lbl.setWordWrap(True)
            detail_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

            card_layout.addWidget(step_lbl)
            card_layout.addWidget(icon_lbl)
            card_layout.addWidget(name_lbl)
            card_layout.addWidget(detail_lbl)

            grid.addWidget(card, 1)

        layout.addLayout(grid)
        self.setMinimumHeight(220)

    def sizeHint(self):
        return QSize(800, 220)

    def minimumSizeHint(self):
        return QSize(600, 220)


class HealthScoreWidget(QFrame):
    """Case Investigation Health Score display card with factor breakdown & disclaimers."""

    def __init__(self, health_data, theme="dark", parent=None):
        super().__init__(parent)
        self.setObjectName("panel")
        self.theme = theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        header_layout = QHBoxLayout()

        score_box = QVBoxLayout()
        score_val = QLabel(f"{health_data['score']}")

        score_color = health_data['color']
        if theme == "light":
            if score_color == "#2ecc71":
                score_color = "#1a7f37"
            elif score_color == "#3498db":
                score_color = "#0969da"
            elif score_color == "#f1c40f":
                score_color = "#d97706"
            elif score_color == "#e74c3c":
                score_color = "#cf222e"

        score_val.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {score_color};")

        max_color = "#656d76" if theme == "light" else "#95a5a6"
        score_max = QLabel("/ 100")
        score_max.setStyleSheet(f"font-size: 14px; color: {max_color}; font-weight: bold;")

        score_sub = QHBoxLayout()
        score_sub.addWidget(score_val)
        score_sub.addWidget(score_max)
        score_sub.addStretch()

        score_box.addLayout(score_sub)

        label_lbl = QLabel(health_data['label'])
        label_lbl.setStyleSheet(f"""
            background-color: {score_color};
            color: #ffffff;
            font-weight: bold;
            font-size: 12px;
            padding: 4px 12px;
            border-radius: 12px;
        """)
        score_box.addWidget(label_lbl)

        header_layout.addLayout(score_box)
        header_layout.addStretch()

        bd_title_color = "#1f2328" if theme == "light" else "#ecf0f1"
        f_name_color = "#57606a" if theme == "light" else "#bdc3c7"
        f_pts_color = "#0969da" if theme == "light" else "#3498db"

        breakdown_layout = QVBoxLayout()
        breakdown_layout.setSpacing(4)
        breakdown_title = QLabel("Factor Score Breakdown:")
        breakdown_title.setStyleSheet(f"font-weight: bold; font-size: 12px; color: {bd_title_color};")
        breakdown_layout.addWidget(breakdown_title)

        for factor in health_data.get("breakdown", []):
            f_row = QHBoxLayout()
            f_name = QLabel(f"• {factor['factor']}:")
            f_name.setStyleSheet(f"font-size: 11px; color: {f_name_color};")

            f_pts = QLabel(f"{factor['pts']} / {factor['max_pts']} pts ({factor['status']})")
            f_pts.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {f_pts_color};")

            f_row.addWidget(f_name)
            f_row.addWidget(f_pts)
            f_row.addStretch()

            breakdown_layout.addLayout(f_row)

        header_layout.addLayout(breakdown_layout, 1)
        layout.addLayout(header_layout)

        if health_data.get("risk_flags"):
            risk_box = QFrame()
            rb_bg = "#ffebe9" if theme == "light" else "#3a1b1b"
            rb_border = "#ff8182" if theme == "light" else "#e74c3c"
            risk_box.setStyleSheet(f"background-color: {rb_bg}; border: 1px solid {rb_border}; border-radius: 6px; padding: 8px;")
            rb_layout = QVBoxLayout(risk_box)
            rb_layout.setContentsMargins(6, 6, 6, 6)

            rt_color = "#cf222e" if theme == "light" else "#e74c3c"
            ri_color = "#d97706" if theme == "light" else "#f39c12"

            r_title = QLabel("⚠ ATTENTION & RISK WARNINGS DETECTED:")
            r_title.setStyleSheet(f"color: {rt_color}; font-weight: bold; font-size: 11px;")
            rb_layout.addWidget(r_title)

            for rf in health_data["risk_flags"]:
                r_item = QLabel(f"• {rf}")
                r_item.setStyleSheet(f"color: {ri_color}; font-size: 11px;")
                r_item.setWordWrap(True)
                rb_layout.addWidget(r_item)

            layout.addWidget(risk_box)

        disc_color = "#656d76" if theme == "light" else "#7f8c8d"
        disc = QLabel(health_data.get("disclaimer", ""))
        disc.setWordWrap(True)
        disc.setStyleSheet(f"font-size: 10px; color: {disc_color}; font-style: italic; margin-top: 4px;")
        layout.addWidget(disc)


class EvidenceRelationshipWidget(QWidget):
    """Visual flow map for evidence relationships."""

    def __init__(self, rel_data, theme="dark", parent=None):
        super().__init__(parent)
        self.theme = theme
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        title_color = "#1f2328" if theme == "light" else "#ecf0f1"
        node_bg = "#ffffff" if theme == "light" else "#1e293b"
        ntype_color = "#656d76" if theme == "light" else "#95a5a6"
        ntitle_color = "#1f2328" if theme == "light" else "#ffffff"
        arrow_color = "#656d76" if theme == "light" else "#7f8c8d"

        title = QLabel(f"Evidence Lifecycle Relationship Flow ({rel_data.get('case_id', 'Case')})")
        title.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {title_color};")
        layout.addWidget(title)

        nodes = rel_data.get("nodes", [])
        flow_layout = QHBoxLayout()
        flow_layout.setSpacing(8)

        for idx, node in enumerate(nodes):
            n_frame = QFrame()
            n_color = node.get("color", "#3498db")
            if theme == "light":
                if n_color == "#3498db":
                    n_color = "#0969da"
                elif n_color == "#2ecc71":
                    n_color = "#1a7f37"
                elif n_color == "#e74c3c":
                    n_color = "#cf222e"

            n_frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {node_bg};
                    border: 1px solid {n_color};
                    border-radius: 6px;
                    padding: 6px;
                }}
            """)
            nf_layout = QVBoxLayout(n_frame)
            nf_layout.setContentsMargins(6, 6, 6, 6)

            ntype = QLabel(node.get("type", ""))
            ntype.setStyleSheet(f"font-size: 9px; font-weight: bold; color: {ntype_color};")

            ntitle = QLabel(node.get("title", ""))
            ntitle.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {ntitle_color};")
            ntitle.setWordWrap(True)

            nstatus = QLabel(node.get("status", ""))
            nstatus.setStyleSheet(f"font-size: 10px; font-weight: bold; color: {n_color};")

            nf_layout.addWidget(ntype)
            nf_layout.addWidget(ntitle)
            nf_layout.addWidget(nstatus)

            if "children" in node:
                for child in node["children"]:
                    c_color = child.get("color", "#3498db")
                    if theme == "light":
                        if c_color == "#3498db":
                            c_color = "#0969da"
                        elif c_color == "#2ecc71":
                            c_color = "#1a7f37"
                        elif c_color == "#e74c3c":
                            c_color = "#cf222e"
                    c_lbl = QLabel(f"└ {child['type']}: {child['status']}")
                    c_lbl.setStyleSheet(f"font-size: 9px; color: {c_color};")
                    c_lbl.setWordWrap(True)
                    nf_layout.addWidget(c_lbl)

            flow_layout.addWidget(n_frame, 1)

            if idx < len(nodes) - 1:
                arrow = QLabel("➔")
                arrow.setStyleSheet(f"font-size: 16px; color: {arrow_color}; font-weight: bold;")
                flow_layout.addWidget(arrow)

        layout.addLayout(flow_layout)


class RelationshipGraphNode(QGraphicsObject):
    """Custom-painted, selectable evidence card for the read-only graph."""

    WIDTH = 264
    HEIGHT = 142

    def __init__(self, evidence, status, graph_dialog, x, y):
        super().__init__()
        self.evidence = evidence
        self.evidence_id = evidence["id"]
        self.status = status
        self.graph_dialog = graph_dialog
        self.setPos(x, y)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setData(0, self.evidence_id)
        self.hovered = False

    def boundingRect(self):
        return self.graph_dialog.node_rect(self)

    def paint(self, painter, option, widget=None):
        rect = self.boundingRect()
        selected = self.isSelected()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(
            self.graph_dialog.node_selected_border if selected else self.graph_dialog.node_border,
            2.2 if selected else 1.2,
        ))
        painter.setBrush(QBrush(
            self.graph_dialog.node_selected_background if selected
            else self.graph_dialog.node_background
        ))
        painter.drawRoundedRect(rect, 12, 12)

        status_color = self.graph_dialog.status_color(self.status)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(status_color))
        painter.drawRoundedRect(16, 14, 96, 24, 12, 12)
        painter.setPen(QPen(self.graph_dialog.card_text))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(27, 30, f"● {self.status}")

        painter.setPen(QPen(self.graph_dialog.card_text))
        painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        painter.drawText(16, 58, f"EV-{self.evidence_id:04d}")
        painter.setFont(QFont("Segoe UI", 10))
        filename = QFontMetrics(painter.font()).elidedText(
            str(self.evidence["evidence_name"]),
            Qt.TextElideMode.ElideRight,
            self.WIDTH - 32,
        )
        painter.drawText(16, 79, filename)

        painter.setPen(QPen(self.graph_dialog.muted_text))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(16, 101, "SHA-256")
        painter.setFont(QFont("Consolas", 8))
        digest = str(self.evidence["sha256"] or "Not recorded")
        painter.drawText(16, 118, digest[:16] + ("..." if self.evidence["sha256"] else ""))

    def hoverEnterEvent(self, event):
        self.hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    def mouseDoubleClickEvent(self, event):
        self.graph_dialog.select_evidence_row(self.evidence_id)
        super().mouseDoubleClickEvent(event)


class RelationshipGraphEdge(QGraphicsLineItem):
    """Selectable grouped edge containing all findings for one evidence pair."""

    def __init__(self, first_id, second_id, findings, graph_dialog, line):
        super().__init__(*line)
        self.first_id = first_id
        self.second_id = second_id
        self.findings = findings
        self.graph_dialog = graph_dialog
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setData(0, (first_id, second_id))
        self.setZValue(0)
        labels = {finding["strength_label"] for finding in findings}
        if "Strongest Deterministic" in labels:
            color, width, style = graph_dialog.edge_colors["Strongest Deterministic"], 4, Qt.PenStyle.SolidLine
        elif "Moderate" in labels:
            color, width, style = graph_dialog.edge_colors["Moderate"], 3, Qt.PenStyle.DashLine
        elif "Contextual" in labels:
            color, width, style = graph_dialog.edge_colors["Contextual"], 2, Qt.PenStyle.DashLine
        else:
            color, width, style = graph_dialog.edge_colors["Weak"], 1, Qt.PenStyle.DotLine
        pen = QPen(color, width, style)
        self.setPen(pen)

    def mousePressEvent(self, event):
        self.graph_dialog.show_edge_details(self)
        super().mousePressEvent(event)


class RelationshipBadge(QGraphicsObject):
    """Compact grouped-finding badge positioned beside an edge."""

    def __init__(self, text, subtitle, color, graph_dialog, x, y):
        super().__init__()
        self.text = text
        self.subtitle = subtitle
        self.color = color
        self.graph_dialog = graph_dialog
        self.setPos(x, y)
        self.setZValue(3)

    def boundingRect(self):
        return self.graph_dialog.badge_rect

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(self.color, 1))
        painter.setBrush(QBrush(self.graph_dialog.badge_background))
        painter.drawRoundedRect(self.boundingRect(), 7, 7)
        painter.setPen(QPen(self.graph_dialog.card_text))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(10, 16, self.text)
        painter.setPen(QPen(self.graph_dialog.muted_text))
        painter.setFont(QFont("Segoe UI", 7))
        painter.drawText(10, 31, self.subtitle)


class RelationshipGraphDialog(QDialog):
    """Professional read-only visualization of persisted case findings."""

    DISCLAIMER = (
        "Edge appearance represents deterministic comparison classification only. "
        "It does not represent probability, guilt, attribution, or legal significance."
    )

    def __init__(self, case_id, theme="dark", parent=None, select_evidence_callback=None):
        super().__init__(parent)
        self.case_id = case_id
        self.theme = theme
        self.select_evidence_callback = select_evidence_callback
        self.node_items = {}
        self.edge_items = {}
        self.edge_labels = {}
        self.findings = get_correlation_findings(case_id)
        self.evidence_items = sorted(get_evidence_for_case(case_id), key=lambda evidence: int(evidence["id"]))
        self.case = get_case(case_id) or {}
        dark = theme != "light"
        self.node_background = QColor("#172033" if dark else "#ffffff")
        self.node_selected_background = QColor("#203451" if dark else "#eaf4ff")
        self.node_border = QColor("#3f6f9f" if dark else "#8ab4dc")
        self.node_selected_border = QColor("#48c7e8" if dark else "#0969da")
        self.card_text = QColor("#f4f7fb" if dark else "#1f2328")
        self.muted_text = QColor("#91a4b8" if dark else "#57606a")
        self.badge_background = QColor("#101827" if dark else "#f6f8fa")
        self.edge_colors = {
            "Strongest Deterministic": QColor("#4ade80"),
            "Moderate": QColor("#60a5fa"),
            "Contextual": QColor("#a78bfa"),
            "Weak": QColor("#94a3b8"),
        }
        self.badge_rect = QRectF(0, 0, 132, 42)
        self.setWindowTitle("Forensic Evidence Relationship Graph")
        self.setMinimumSize(1180, 760)
        self._build_ui()
        self._build_graph()

    def node_rect(self, node):
        return QRectF(0, 0, node.WIDTH, node.HEIGHT)

    def status_color(self, status):
        if status == "VERIFIED":
            return QColor("#247a55")
        if status == "MISMATCH":
            return QColor("#a63d40")
        return QColor("#64748b")

    def _build_ui(self):
        dark = self.theme != "light"
        background = "#0b1220" if dark else "#f6f8fa"
        panel = "#111b2d" if dark else "#ffffff"
        border = "#263a55" if dark else "#d0d7de"
        self.setStyleSheet(f"""
            QDialog {{ background: {background}; color: {self.card_text.name()}; }}
            QFrame#graphPanel {{ background: {panel}; border: 1px solid {border}; border-radius: 10px; }}
            QLabel#graphTitle {{ color: {self.card_text.name()}; font-size: 18px; font-weight: 700; }}
            QLabel#graphSubtitle, QLabel#graphMuted {{ color: {self.muted_text.name()}; }}
            QLabel#statValue {{ color: #48c7e8; font-size: 18px; font-weight: 700; }}
            QLabel#statLabel {{ color: {self.muted_text.name()}; font-size: 9px; font-weight: 700; }}
            QPlainTextEdit#details {{ background: {panel}; border: none; color: {self.card_text.name()}; padding: 10px; }}
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("FORENSIC EVIDENCE\nRELATIONSHIP GRAPH")
        title.setObjectName("graphTitle")
        subtitle = QLabel("Visualize deterministic relationships between digital evidence.")
        subtitle.setObjectName("graphSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        case_text = f"Case: {self.case['case_id'] if self.case else self.case_id}"
        case_name = QLabel(case_text)
        case_name.setObjectName("graphMuted")
        header.addWidget(case_name)
        root.addLayout(header)

        toolbar = QHBoxLayout()
        for label, callback in (
            ("Zoom In", lambda: self.graph_view.scale(1.2, 1.2)),
            ("Zoom Out", lambda: self.graph_view.scale(0.8, 0.8)),
            ("Fit View", self.fit_graph),
            ("Reset View", self.reset_view),
        ):
            button = QPushButton(label)
            button.setObjectName("secondary_button")
            button.clicked.connect(callback)
            toolbar.addWidget(button)
        toolbar.addStretch()
        root.addLayout(toolbar)

        body = QHBoxLayout()
        graph_panel = QFrame()
        graph_panel.setObjectName("graphPanel")
        graph_layout = QVBoxLayout(graph_panel)
        self.graph_scene = QGraphicsScene(self)
        self.graph_view = QGraphicsView(self.graph_scene)
        self.graph_view.setMinimumHeight(430)
        self.graph_view.setStyleSheet("QGraphicsView { border: none; background: transparent; }")
        graph_layout.addWidget(self.graph_view)
        body.addWidget(graph_panel, 7)

        detail_panel = QFrame()
        detail_panel.setObjectName("graphPanel")
        detail_layout = QVBoxLayout(detail_panel)
        detail_title = QLabel("INSPECTION DETAILS")
        detail_title.setObjectName("graphTitle")
        detail_title.setStyleSheet("font-size: 12px;")
        detail_layout.addWidget(detail_title)
        self.details = QPlainTextEdit()
        self.details.setObjectName("details")
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select an evidence node or relationship.")
        detail_layout.addWidget(self.details, 1)
        body.addWidget(detail_panel, 3)
        root.addLayout(body, 1)

        stats = QHBoxLayout()
        verified = sum(get_current_evidence_status(item) == "VERIFIED" for item in self.evidence_items)
        self._add_stat(stats, str(len(self.evidence_items)), "EVIDENCE ITEMS")
        self.relationship_stat_value = self._add_stat(stats, "0", "RELATIONSHIPS")
        percent = round((verified / len(self.evidence_items)) * 100) if self.evidence_items else 0
        self._add_stat(stats, f"{percent}%", "VERIFIED")
        root.addLayout(stats)

        footer = QHBoxLayout()
        legend = QLabel(
            "RELATIONSHIP STRENGTH  "
            "━━ Strongest Deterministic   ┄ Moderate   - - Contextual   ··· Weak"
        )
        legend.setObjectName("graphMuted")
        legend.setWordWrap(True)
        footer.addWidget(legend, 2)
        tips = QLabel("Tip: select a node or edge to inspect persisted forensic details.")
        tips.setObjectName("graphMuted")
        tips.setWordWrap(True)
        footer.addWidget(tips, 1)
        root.addLayout(footer)
        disclaimer = QLabel(self.DISCLAIMER)
        disclaimer.setObjectName("graphMuted")
        disclaimer.setWordWrap(True)
        root.addWidget(disclaimer)
        self.status_label = QLabel()
        self.status_label.setObjectName("graphMuted")
        root.addWidget(self.status_label)
        self.graph_scene.selectionChanged.connect(self._selection_changed)

    def _add_stat(self, layout, value, label):
        frame = QFrame()
        frame.setObjectName("graphPanel")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(14, 7, 14, 7)
        value_label = QLabel(value)
        value_label.setObjectName("statValue")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label_widget = QLabel(label)
        label_widget.setObjectName("statLabel")
        label_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        frame_layout.addWidget(value_label)
        frame_layout.addWidget(label_widget)
        layout.addWidget(frame, 1)
        return value_label

    def _build_graph(self):
        if not self.evidence_items:
            self.status_label.setText("No evidence items are available for this case.")
            return
        positions = {}
        count = len(self.evidence_items)
        if count == 3:
            positions = {self.evidence_items[0]["id"]: (240, 20), self.evidence_items[1]["id"]: (20, 245), self.evidence_items[2]["id"]: (460, 245)}
        else:
            columns = 2 if count <= 4 else 3
            for index, evidence in enumerate(self.evidence_items):
                row, column = divmod(index, columns)
                positions[evidence["id"]] = (column * 350, row * 205)
        for evidence in self.evidence_items:
            status = get_current_evidence_status(evidence)
            node = RelationshipGraphNode(evidence, status, self, *positions[evidence["id"]])
            self.graph_scene.addItem(node)
            self.node_items[evidence["id"]] = node

        grouped = {}
        evidence_ids = set(positions)
        for finding in self.findings:
            pair = (min(int(finding["evidence_a_id"]), int(finding["evidence_b_id"])), max(int(finding["evidence_a_id"]), int(finding["evidence_b_id"])))
            if pair[0] in evidence_ids and pair[1] in evidence_ids:
                grouped.setdefault(pair, []).append(finding)
        for pair, findings in grouped.items():
            first = positions[pair[0]]
            second = positions[pair[1]]
            line = (
                first[0] + RelationshipGraphNode.WIDTH / 2,
                first[1] + RelationshipGraphNode.HEIGHT / 2,
                second[0] + RelationshipGraphNode.WIDTH / 2,
                second[1] + RelationshipGraphNode.HEIGHT / 2,
            )
            edge = RelationshipGraphEdge(pair[0], pair[1], findings, self, line)
            self.graph_scene.addItem(edge)
            self.edge_items[pair] = edge
            types = {finding["relationship_type"] for finding in findings}
            subtitle = next(iter(types)) if len(types) == 1 else "Multiple Relationships"
            midpoint_x, midpoint_y = (line[0] + line[2]) / 2, (line[1] + line[3]) / 2
            badge = RelationshipBadge(
                f"{len(findings)} FINDING{'S' if len(findings) != 1 else ''}",
                subtitle,
                edge.pen().color(),
                self,
                midpoint_x - 66,
                midpoint_y - 21,
            )
            self.graph_scene.addItem(badge)
            self.edge_labels[pair] = badge
        if len(self.evidence_items) == 1:
            self.status_label.setText("No cross-evidence relationships recorded.")
        elif not grouped:
            self.status_label.setText("Evidence items are available, but no persisted cross-evidence relationships are recorded.")
        else:
            self.status_label.setText(f"{len(self.evidence_items)} evidence item(s) shown; {len(grouped)} grouped relationship(s) shown.")
        self.relationship_stat_value.setText(str(len(self.edge_items)))
        self.graph_scene.setSceneRect(self.graph_scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))
        self.reset_view()

    def fit_graph(self):
        if self.graph_scene.items():
            self.graph_view.fitInView(self.graph_scene.itemsBoundingRect().adjusted(-30, -30, 30, 30), Qt.AspectRatioMode.KeepAspectRatio)

    def reset_view(self):
        self.graph_view.resetTransform()
        self.fit_graph()

    def _selection_changed(self):
        selected = self.graph_scene.selectedItems()
        if not selected:
            return
        if isinstance(selected[0], RelationshipGraphNode):
            self.show_node_details(selected[0])
        elif isinstance(selected[0], RelationshipGraphEdge):
            self.show_edge_details(selected[0])

    def show_node_details(self, node):
        evidence = get_evidence_by_id(node.evidence_id)
        if not evidence:
            self.details.setPlainText("The selected evidence could not be found.")
            return
        related = []
        for edge in self.edge_items.values():
            if node.evidence_id in (edge.first_id, edge.second_id):
                other_id = edge.second_id if edge.first_id == node.evidence_id else edge.first_id
                related.append(f"EV-{other_id:04d} | {self.node_items[other_id].evidence['evidence_name']} | {len(edge.findings)} finding(s)")
        lines = [
            "EVIDENCE DETAILS",
            f"EV-{evidence['id']:04d}  {evidence['evidence_name']}",
            f"Case: {evidence['case_number']} | {evidence['case_name']}",
            f"Verification status: {get_current_evidence_status(evidence)}",
            f"Acquired: {evidence['acquired_at'] or 'Not recorded'}",
            f"SHA-256: {evidence['sha256'] or 'Not recorded'}",
            "",
            "RELATED EVIDENCE",
            *(related or ["No persisted relationships for this evidence."]),
        ]
        self.details.setPlainText("\n".join(lines))

    def show_edge_details(self, edge):
        lines = [
            "RELATIONSHIP DETAILS",
            f"Evidence A: EV-{edge.first_id:04d} | {self.node_items[edge.first_id].evidence['evidence_name']}",
            f"Evidence B: EV-{edge.second_id:04d} | {self.node_items[edge.second_id].evidence['evidence_name']}",
            "",
        ]
        for index, finding in enumerate(edge.findings, 1):
            lines.extend([
                f"Finding {index}",
                f"Relationship: {finding['relationship_type']}",
                f"Indicator: {finding['indicator_display'] or 'N/A'}",
                f"Strength: {finding['strength_label']}",
                f"Explanation: {finding['explanation']}",
                f"Detected: {finding['detected_at']}",
                "Review status: Requires investigator review.",
                "",
            ])
        self.details.setPlainText("\n".join(lines).rstrip())

    def select_evidence_row(self, evidence_id):
        if self.select_evidence_callback:
            self.select_evidence_callback(evidence_id)


class InvestigationReplayDialog(QDialog):
    """Read-only playback of the existing persisted investigation timeline."""

    def __init__(self, case_id, theme="dark", parent=None):
        super().__init__(parent)
        self.case_id = case_id
        self.theme = theme
        self.case = get_case(case_id)
        self.replay_events = list(get_timeline_events(case_id))
        self.current_index = 0
        self.replay_timer = QTimer(self)
        self.replay_timer.setInterval(1000)
        self.replay_timer.timeout.connect(self.next_event)
        self.setWindowTitle("Investigation Replay")
        self.setMinimumSize(980, 650)
        self._build_ui()
        self._refresh_replay_view()

    def _build_ui(self):
        dark = self.theme != "light"
        background = "#0b1220" if dark else "#f6f8fa"
        panel = "#111b2d" if dark else "#ffffff"
        text = "#f4f7fb" if dark else "#1f2328"
        muted = "#91a4b8" if dark else "#57606a"
        self.setStyleSheet(f"""
            QDialog {{ background: {background}; color: {text}; }}
            QFrame#replayPanel {{ background: {panel}; border: 1px solid {'#263a55' if dark else '#d0d7de'}; border-radius: 10px; }}
            QLabel#replayTitle {{ color: {text}; font-size: 18px; font-weight: 700; }}
            QLabel#replayMuted {{ color: {muted}; }}
            QPlainTextEdit#replayDetails {{ background: {panel}; border: none; color: {text}; padding: 12px; }}
            QListWidget {{ background: {panel}; border: none; color: {text}; padding: 8px; }}
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("INVESTIGATION REPLAY")
        title.setObjectName("replayTitle")
        subtitle = QLabel("Step through the recorded investigation timeline.")
        subtitle.setObjectName("replayMuted")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        case_text = self.case["case_id"] if self.case else str(self.case_id)
        case_label = QLabel(
            f"{case_text}\n{self.case['case_name'] if self.case else 'Case unavailable'}\n"
            f"{len(self.replay_events)} Recorded Event(s)"
        )
        case_label.setObjectName("replayMuted")
        header.addWidget(case_label)
        root.addLayout(header)

        body = QHBoxLayout()
        event_panel = QFrame()
        event_panel.setObjectName("replayPanel")
        event_layout = QVBoxLayout(event_panel)
        event_title = QLabel("RECORDED EVENTS")
        event_title.setObjectName("replayTitle")
        event_title.setStyleSheet("font-size: 12px;")
        event_layout.addWidget(event_title)
        self.event_list = QListWidget()
        self.event_list.currentRowChanged.connect(self._select_event)
        event_layout.addWidget(self.event_list, 1)
        body.addWidget(event_panel, 2)

        detail_panel = QFrame()
        detail_panel.setObjectName("replayPanel")
        detail_layout = QVBoxLayout(detail_panel)
        active_title = QLabel("ACTIVE EVENT")
        active_title.setObjectName("replayTitle")
        active_title.setStyleSheet("font-size: 12px;")
        detail_layout.addWidget(active_title)
        self.active_event_label = QLabel()
        self.active_event_label.setObjectName("replayTitle")
        self.active_event_label.setWordWrap(True)
        detail_layout.addWidget(self.active_event_label)
        self.replay_details = QPlainTextEdit()
        self.replay_details.setObjectName("replayDetails")
        self.replay_details.setReadOnly(True)
        detail_layout.addWidget(self.replay_details, 1)
        body.addWidget(detail_panel, 3)
        root.addLayout(body, 1)

        self.progress_label = QLabel()
        self.progress_label.setObjectName("replayMuted")
        root.addWidget(self.progress_label)
        self.progress_slider = QSlider(Qt.Orientation.Horizontal)
        self.progress_slider.valueChanged.connect(self._select_event)
        root.addWidget(self.progress_slider)

        controls = QHBoxLayout()
        self.play_button = QPushButton("Play")
        self.pause_button = QPushButton("Pause")
        self.previous_button = QPushButton("Previous")
        self.next_button = QPushButton("Next")
        self.reset_button = QPushButton("Reset")
        self.play_button.clicked.connect(self.play_replay)
        self.pause_button.clicked.connect(self.pause_replay)
        self.previous_button.clicked.connect(self.previous_event)
        self.next_button.clicked.connect(self.next_event)
        self.reset_button.clicked.connect(self.reset_replay)
        for button in (self.play_button, self.pause_button, self.previous_button, self.next_button, self.reset_button):
            button.setObjectName("secondary_button")
            controls.addWidget(button)
        controls.addStretch()
        root.addLayout(controls)
        notice = QLabel("Replay is a read-only presentation of recorded events and does not establish causation.")
        notice.setObjectName("replayMuted")
        notice.setWordWrap(True)
        root.addWidget(notice)

    def closeEvent(self, event):
        self.pause_replay()
        super().closeEvent(event)

    def _refresh_replay_view(self):
        self.event_list.blockSignals(True)
        self.event_list.clear()
        for event in self.replay_events:
            self.event_list.addItem(f"{event['timestamp']}  |  {event['event']}")
        self.event_list.blockSignals(False)
        has_events = bool(self.replay_events)
        self.progress_slider.setEnabled(has_events)
        self.progress_slider.setRange(0, max(len(self.replay_events) - 1, 0))
        self.play_button.setEnabled(has_events)
        self.pause_button.setEnabled(has_events)
        self.previous_button.setEnabled(has_events and self.current_index > 0)
        self.next_button.setEnabled(has_events and self.current_index < len(self.replay_events) - 1)
        self.reset_button.setEnabled(has_events)
        if has_events:
            self.event_list.setCurrentRow(self.current_index)
            self.progress_slider.setValue(self.current_index)
        else:
            self.active_event_label.setText("No recorded timeline events are available for this case.")
            self.replay_details.clear()
            self.progress_label.setText("Event 0 of 0")

    def _select_event(self, index):
        if not self.replay_events or index < 0:
            return
        self.current_index = min(index, len(self.replay_events) - 1)
        event = self.replay_events[self.current_index]
        self.event_list.blockSignals(True)
        self.event_list.setCurrentRow(self.current_index)
        self.event_list.blockSignals(False)
        self.progress_slider.blockSignals(True)
        self.progress_slider.setValue(self.current_index)
        self.progress_slider.blockSignals(False)
        self.active_event_label.setText(f"EVENT {self.current_index + 1:02d}\n{event['event']}")
        self.replay_details.setPlainText(
            "\n".join([
                f"Timestamp: {event['timestamp']}",
                f"Source: {event['source']}",
                f"Person: {event['person']}" if event.get("person") else "",
                f"Details: {event['details']}" if event.get("details") else "",
            ]).strip()
        )
        self.progress_label.setText(f"Event {self.current_index + 1} of {len(self.replay_events)}")
        self.previous_button.setEnabled(self.current_index > 0)
        self.next_button.setEnabled(self.current_index < len(self.replay_events) - 1)

    def play_replay(self):
        if self.replay_events:
            self.replay_timer.start()

    def pause_replay(self):
        self.replay_timer.stop()

    def next_event(self):
        if not self.replay_events:
            return
        if self.current_index >= len(self.replay_events) - 1:
            self.replay_timer.stop()
            self._select_event(self.current_index)
            return
        self._select_event(self.current_index + 1)

    def previous_event(self):
        self.pause_replay()
        if self.replay_events:
            self._select_event(max(self.current_index - 1, 0))

    def reset_replay(self):
        self.pause_replay()
        if self.replay_events:
            self._select_event(0)


class ExecutiveSummaryDialog(QDialog):
    """Dialog displaying automated deterministic investigation summary narrative."""

    def __init__(self, case_id, summary_text, theme="dark", parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Executive Investigation Summary - {case_id}")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        lbl_color = "#1f2328" if theme == "light" else "#ecf0f1"
        lbl = QLabel(f"Automated Forensic Investigation Summary ({case_id})")
        lbl.setStyleSheet(f"font-weight: bold; font-size: 15px; color: {lbl_color};")
        layout.addWidget(lbl)

        txt = QPlainTextEdit()
        txt.setReadOnly(True)
        txt.setFont(QFont("Consolas", 10))
        txt.setPlainText(summary_text)
        layout.addWidget(txt, 1)

        btn_box = QHBoxLayout()

        btn_copy = QPushButton("Copy to Clipboard")
        btn_copy.setObjectName("secondary_button")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(summary_text))

        btn_save = QPushButton("Save Summary to File...")
        btn_save.setObjectName("primary_button")
        btn_save.clicked.connect(lambda: self.save_summary(case_id, summary_text))

        btn_close = QPushButton("Close")
        btn_close.setObjectName("secondary_button")
        btn_close.clicked.connect(self.accept)

        btn_box.addWidget(btn_copy)
        btn_box.addWidget(btn_save)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)

        layout.addLayout(btn_box)

    def save_summary(self, case_id, text):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Investigation Summary",
            f"Summary_{case_id}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                QMessageBox.information(self, "Success", f"Summary saved to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")


# =========================================================
# CASE DIALOG
# =========================================================


class CaseDialog(QDialog):

    def __init__(self, parent=None, case=None):
        super().__init__(parent)
        self.case = case

        if case:
            self.setWindowTitle("Edit Investigation Case")
        else:
            self.setWindowTitle("New Investigation Case")

        self.setMinimumWidth(520)
        self.setup_ui()

        if self.case:
            self.load_case_data()
        else:
            self.prepare_new_case_id()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        title = QLabel("Case Information")
        title.setObjectName("dialog_title")

        description = QLabel(
            "Enter the details of the digital forensic investigation."
        )
        description.setObjectName("dialog_description")

        layout.addWidget(title)
        layout.addWidget(description)

        form = QFormLayout()
        form.setSpacing(12)

        self.case_id_input = QLineEdit()
        self.case_id_input.setPlaceholderText("Example: CT-2026-001")

        self.case_name_input = QLineEdit()
        self.case_name_input.setPlaceholderText("Example: Suspicious Email Investigation")

        self.investigator_input = QLineEdit()
        self.investigator_input.setPlaceholderText("Investigator name")

        self.status_input = QComboBox()
        self.status_input.addItems([
            "Open",
            "Under Investigation",
            "Closed",
        ])

        self.description_input = QPlainTextEdit()
        self.description_input.setPlaceholderText("Brief description of the investigation...")
        self.description_input.setMaximumHeight(120)

        form.addRow("Case ID (Auto)", self.case_id_input)
        form.addRow("Case Name *", self.case_name_input)
        form.addRow("Investigator *", self.investigator_input)
        form.addRow("Status", self.status_input)
        form.addRow("Description", self.description_input)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

    def prepare_new_case_id(self):
        try:
            self.case_id_input.setText(get_next_case_id())
            self.case_id_input.setReadOnly(True)
            self.case_id_input.setToolTip("CyberTrace automatically generates a unique Case ID.")
        except Exception as error:
            QMessageBox.critical(
                self,
                "Unable to Generate Case ID",
                f"CyberTrace could not generate the Case ID automatically.\n\nError: {error}"
            )

    def load_case_data(self):
        self.case_id_input.setText(self.case["case_id"])
        self.case_id_input.setEnabled(False)
        self.case_name_input.setText(self.case["case_name"])
        self.investigator_input.setText(self.case["investigator"])
        self.description_input.setPlainText(self.case["description"] or "")

        index = self.status_input.findText(self.case["status"])
        if index >= 0:
            self.status_input.setCurrentIndex(index)

    def validate_and_accept(self):
        case_id = self.case_id_input.text().strip()
        case_name = self.case_name_input.text().strip()
        investigator = self.investigator_input.text().strip()

        if not case_id:
            QMessageBox.warning(self, "Missing Information", "Please enter a Case ID.")
            return

        if not case_name:
            QMessageBox.warning(self, "Missing Information", "Please enter a Case Name.")
            return

        if not investigator:
            QMessageBox.warning(self, "Missing Information", "Please enter the Investigator name.")
            return

        self.accept()

    def get_data(self):
        return {
            "case_id": self.case_id_input.text().strip(),
            "case_name": self.case_name_input.text().strip(),
            "investigator": self.investigator_input.text().strip(),
            "description": self.description_input.toPlainText().strip(),
            "status": self.status_input.currentText(),
        }


# =========================================================
# EVIDENCE DIALOG
# =========================================================

class EvidenceDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Digital Evidence")
        self.setMinimumWidth(650)
        self.selected_file = ""
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        title = QLabel("Digital Evidence Acquisition")
        title.setObjectName("dialog_title")

        description = QLabel(
            "Select an original evidence file. CyberTrace will create a controlled copy and calculate its SHA-256 hash."
        )
        description.setObjectName("dialog_description")
        description.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(description)

        form = QFormLayout()
        form.setSpacing(12)

        self.case_input = QComboBox()
        cases = get_cases()
        for case in cases:
            self.case_input.addItem(
                f"{case['case_id']} - {case['case_name']}",
                case["id"]
            )

        form.addRow("Investigation Case *", self.case_input)

        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        self.file_input.setPlaceholderText("Select evidence file...")

        browse_button = QPushButton("Browse")
        browse_button.setObjectName("secondary_button")
        browse_button.clicked.connect(self.browse_file)

        file_layout.addWidget(self.file_input)
        file_layout.addWidget(browse_button)

        form.addRow("Original File *", file_layout)

        self.info_label = QLabel("No evidence file selected.")
        self.info_label.setObjectName("evidence_info")
        self.info_label.setWordWrap(True)

        form.addRow("File Information", self.info_label)
        layout.addLayout(form)

        notice = QLabel(
            "🔐 Original evidence will not be modified. "
            "A controlled copy will be stored inside the CyberTrace evidence directory and write-protected."
        )
        notice.setObjectName("forensic_notice")
        notice.setWordWrap(True)
        layout.addWidget(notice)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Digital Evidence")
        if not file_path:
            return

        self.selected_file = file_path
        self.file_input.setText(file_path)

        try:
            size = os.path.getsize(file_path)
            modified = datetime.fromtimestamp(
                os.path.getmtime(file_path)
            ).strftime("%Y-%m-%d %H:%M:%S")
            size_mb = size / (1024 * 1024)

            self.info_label.setText(
                f"File name: {os.path.basename(file_path)}\n"
                f"Size: {size_mb:.2f} MB\n"
                f"Last modified: {modified}"
            )
        except OSError as error:
            self.info_label.setText(f"Unable to read file information: {error}")

    def validate_and_accept(self):
        if self.case_input.count() == 0:
            QMessageBox.warning(
                self,
                "No Case Available",
                "Please create an investigation case first."
            )
            return

        if not self.selected_file:
            QMessageBox.warning(
                self,
                "Evidence Required",
                "Please select an evidence file."
            )
            return

        if not os.path.isfile(self.selected_file):
            QMessageBox.warning(
                self,
                "File Not Found",
                "The selected evidence file no longer exists."
            )
            return

        self.accept()

    def get_data(self):
        return {
            "case_id": self.case_input.currentData(),
            "file_path": self.selected_file,
        }


# =========================================================
# CUSTODY EVENT DIALOG
# =========================================================

class CustodyDialog(QDialog):

    def __init__(self, parent=None, evidence=None):
        super().__init__(parent)
        self.evidence = evidence
        self.setWindowTitle("Add Chain of Custody Event")
        self.setMinimumWidth(550)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        title = QLabel("Chain of Custody Event")
        title.setObjectName("dialog_title")

        description = QLabel("Record the movement or handling of the selected digital evidence.")
        description.setObjectName("dialog_description")
        description.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(description)

        evidence_info = QLabel(
            f"Evidence: {self.evidence['evidence_name']}\n"
            f"Case: {self.evidence['case_number']}"
        )
        evidence_info.setObjectName("evidence_info")
        layout.addWidget(evidence_info)

        form = QFormLayout()
        form.setSpacing(12)

        self.action_input = QComboBox()
        self.action_input.addItems([
            "Received",
            "Transferred",
            "Examined",
            "Stored",
            "Released",
        ])

        self.person_input = QLineEdit()
        self.person_input.setPlaceholderText("Person responsible for this action")

        self.remarks_input = QPlainTextEdit()
        self.remarks_input.setPlaceholderText("Optional remarks...")
        self.remarks_input.setMaximumHeight(100)

        form.addRow("Action *", self.action_input)
        form.addRow("Person *", self.person_input)
        form.addRow("Remarks", self.remarks_input)

        layout.addLayout(form)

        notice = QLabel(
            "🔒 Custody events are append-only. "
            "Each new event is linked to the previous event using a SHA-256 integrity hash."
        )
        notice.setObjectName("forensic_notice")
        notice.setWordWrap(True)
        layout.addWidget(notice)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

    def validate_and_accept(self):
        person = self.person_input.text().strip()
        if not person:
            QMessageBox.warning(
                self,
                "Person Required",
                "Please enter the responsible person's name."
            )
            return
        self.accept()

    def get_data(self):
        return {
            "action": self.action_input.currentText(),
            "person": self.person_input.text().strip(),
            "remarks": self.remarks_input.toPlainText().strip(),
        }


# =========================================================
# NOTES DIALOG
# =========================================================

class NoteDialog(QDialog):

    def __init__(self, parent=None, case=None):
        super().__init__(parent)
        self.case = case
        self.setWindowTitle("Add Investigation Note")
        self.setMinimumWidth(650)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        title = QLabel("Investigation Note")
        title.setObjectName("dialog_title")

        description = QLabel(
            "Record an observation, finding, or important investigation detail for the selected case."
        )
        description.setObjectName("dialog_description")
        description.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(description)

        case_info = QLabel(f"Case: {self.case['case_id']} - {self.case['case_name']}")
        case_info.setObjectName("evidence_info")
        case_info.setWordWrap(True)

        layout.addWidget(case_info)

        self.note_input = QPlainTextEdit()
        self.note_input.setPlaceholderText(
            "Example: SHA-256 verification matched the stored evidence hash.\n"
            "Record observations, findings, suspicious indicators, or conclusions..."
        )
        self.note_input.setMinimumHeight(180)

        layout.addWidget(self.note_input)

        notice = QLabel("📝 Notes are linked to the investigation case and timestamped when saved.")
        notice.setObjectName("forensic_notice")
        notice.setWordWrap(True)
        layout.addWidget(notice)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

    def validate_and_accept(self):
        if not self.note_input.toPlainText().strip():
            QMessageBox.warning(
                self,
                "Note Required",
                "Please enter an investigation note or finding."
            )
            return
        self.accept()

    def get_note(self):
        return self.note_input.toPlainText().strip()


# =========================================================
# REPORT GENERATION HELPER
# =========================================================

def get_timeline_events(case_db_id):
    """Build the case timeline from the same persisted records used by the Timeline view."""
    case = get_case(case_db_id)
    if not case:
        return []

    events = [{
        "timestamp": case["created_at"],
        "event": "Case Created",
        "source": "Case Management",
        "person": case["investigator"],
        "details": case["case_name"],
    }]

    for evidence in get_evidence_for_case(case_db_id):
        events.append({
            "timestamp": evidence["acquired_at"],
            "event": "Evidence Acquired",
            "source": "Evidence Management",
            "person": case["investigator"],
            "details": f"{evidence['evidence_name']} | SHA-256: {evidence['sha256']}",
        })

        for custody in get_custody_events(evidence["id"]):
            events.append({
                "timestamp": custody["timestamp"],
                "event": f"Custody: {custody['action']}",
                "source": "Chain of Custody",
                "person": custody["person"],
                "details": custody["remarks"] or "No remarks recorded.",
            })

    for analysis in get_analyses_for_case(case_db_id):
        events.append({
            "timestamp": analysis["analyzed_at"],
            "event": "File Analysis / Examination",
            "source": "File Analysis",
            "person": analysis["analyst"] or case["investigator"],
            "details": (
                f"{analysis['file_name']} | SHA-256: {analysis['sha256']} | "
                f"Integrity: {analysis['integrity_status']}"
            ),
        })

    for note in get_notes(case_db_id):
        events.append({
            "timestamp": note["created_at"],
            "event": "Investigation Note / Finding",
            "source": "Notes & Findings",
            "person": case["investigator"],
            "details": note["note"] or "No note text recorded.",
        })

    for order, event in enumerate(events):
        event["_order"] = order
    events.sort(key=lambda item: (item["timestamp"], item["_order"]))
    return events


def build_html_report(case_db_id):
    case = get_case(case_db_id)
    if not case:
        return "", None

    evidence_records = get_evidence_for_case(case_db_id)
    analyses = get_analyses_for_case(case_db_id)
    notes = get_notes(case_db_id)
    health = get_case_health(case_db_id)
    stages = get_case_lifecycle_stage(case_db_id)
    correlation_findings = get_correlation_findings(case_db_id)
    timeline_events = get_timeline_events(case_db_id)

    evidence_statuses = {
        evidence["id"]: get_current_evidence_status(evidence)
        for evidence in evidence_records
    }
    custody_count = sum(
        len(get_custody_events(evidence["id"]))
        for evidence in evidence_records
    )

    def escape_html(val):
        val_str = str(val or "")
        return (
            val_str.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    # 1. Investigation Health Breakdown rows
    health_breakdown_rows = ""
    for factor in health.get("breakdown", []):
        f_status = factor["status"]
        if f_status in ("COMPLETE", "VERIFIED MATCH", "VERIFIED INTACT", "GENERATED"):
            status_style = "color: #2ecc71; font-weight: bold;"
        elif "MISMATCH" in f_status or "BROKEN" in f_status:
            status_style = "color: #e74c3c; font-weight: bold;"
        else:
            status_style = "color: #f39c12; font-weight: bold;"

        health_breakdown_rows += (
            "<tr>"
            f"<td><strong>{escape_html(factor['factor'])}</strong></td>"
            f"<td>{factor['pts']} / {factor['max_pts']} pts</td>"
            f"<td><span style='{status_style}'>{escape_html(f_status)}</span></td>"
            f"<td>{escape_html(factor['details'])}</td>"
            "</tr>"
        )

    if not health_breakdown_rows:
        health_breakdown_rows = '<tr><td colspan="4">No health factors evaluated.</td></tr>'

    risk_flags_html = ""
    if health.get("risk_flags"):
        flag_items = "".join(f"<li>{escape_html(rf)}</li>" for rf in health["risk_flags"])
        risk_flags_html = (
            f'<div class="notice" style="background: #fdf3f2; border-color: #e74c3c; margin-top: 12px;">'
            f'<strong>&#9888; Risk Warnings:</strong>'
            f'<ul style="margin: 6px 0 0 18px; padding: 0;">{flag_items}</ul>'
            f'</div>'
        )

    # 2. 8-Stage Lifecycle rows
    lifecycle_rows = ""
    for index, stage in enumerate(stages, 1):
        st_status = stage["status"]
        if st_status == "completed":
            s_style = "color: #2ecc71; font-weight: bold;"
        elif st_status == "attention":
            s_style = "color: #e74c3c; font-weight: bold;"
        else:
            s_style = "color: #7f8c8d; font-weight: bold;"

        state_label = "Completed" if stage["completed"] else "Pending"

        lifecycle_rows += (
            "<tr>"
            f"<td>Stage {index}</td>"
            f"<td><strong>{escape_html(stage['stage'])}</strong></td>"
            f"<td><span style='{s_style}'>{escape_html(st_status.upper())}</span></td>"
            f"<td>{escape_html(state_label)}</td>"
            f"<td>{escape_html(stage['details'])}</td>"
            "</tr>"
        )

    if not lifecycle_rows:
        lifecycle_rows = '<tr><td colspan="5">No lifecycle stage information available.</td></tr>'

    # 3. Digital Evidence rows
    evidence_rows = ""
    for evidence in evidence_records:
        st = evidence_statuses[evidence["id"]]
        if st == "VERIFIED":
            ev_style = "color: #2ecc71; font-weight: bold;"
        elif st in ("MISMATCH", "MISSING"):
            ev_style = "color: #e74c3c; font-weight: bold;"
        else:
            ev_style = "color: #f39c12; font-weight: bold;"

        evidence_rows += (
            "<tr>"
            f"<td>EV-{evidence['id']:04d}</td>"
            f"<td>{escape_html(evidence['evidence_name'])}</td>"
            f"<td>{escape_html(evidence['sha256'])}</td>"
            f"<td><span style='{ev_style}'>{escape_html(st)}</span></td>"
            f"<td>{escape_html(evidence['acquired_at'])}</td>"
            f"<td>{escape_html(evidence['preserved_path'])}</td>"
            "</tr>"
        )

    if not evidence_rows:
        evidence_rows = '<tr><td colspan="6">No evidence records available.</td></tr>'

    # 4. Chain of Custody rows
    custody_rows = ""
    for evidence in evidence_records:
        for event in get_custody_events(evidence["id"]):
            custody_rows += (
                "<tr>"
                f"<td>{escape_html(evidence['evidence_name'])}</td>"
                f"<td>{escape_html(event['timestamp'])}</td>"
                f"<td>{escape_html(event['action'])}</td>"
                f"<td>{escape_html(event['person'])}</td>"
                f"<td>{escape_html(event['remarks'])}</td>"
                "</tr>"
            )

    if not custody_rows:
        custody_rows = '<tr><td colspan="5">No custody events available.</td></tr>'

    # 5. Analysis rows
    analysis_rows = ""
    for analysis in analyses:
        status_style = (
            'color: #2ecc71; font-weight: bold;'
            if analysis["integrity_status"] == "MATCH"
            else 'color: #e74c3c; font-weight: bold;'
        )
        analysis_rows += (
            "<tr>"
            f"<td>{escape_html(analysis['analyzed_at'])}</td>"
            f"<td>{escape_html(analysis['file_name'])}</td>"
            f"<td>{escape_html(analysis['file_size'])} bytes</td>"
            f"<td>{escape_html(analysis['mime_type'])}</td>"
            f"<td>{escape_html(analysis['sha256'])}</td>"
            f"<td><span style='{status_style}'>{escape_html(analysis['integrity_status'])}</span></td>"
            "</tr>"
        )

    if not analysis_rows:
        analysis_rows = '<tr><td colspan="6">No file analysis examinations performed yet.</td></tr>'

    correlation_rows = ""
    for finding in correlation_findings:
        correlation_rows += (
            "<tr>"
            f"<td>EV-{finding['evidence_a_id']:04d} - {escape_html(finding['evidence_a_name'])}</td>"
            f"<td>EV-{finding['evidence_b_id']:04d} - {escape_html(finding['evidence_b_name'])}</td>"
            f"<td>{escape_html(finding['relationship_type'])}</td>"
            f"<td>{escape_html(finding['indicator_display'] or 'N/A')}</td>"
            f"<td>{escape_html(finding['strength_label'])}</td>"
            f"<td>{escape_html(finding['explanation'])}</td>"
            f"<td>{escape_html(finding['detected_at'])}</td>"
            "</tr>"
        )
    if not correlation_rows:
        correlation_rows = '<tr><td colspan="7">No potential cross-evidence relationships recorded for this case.</td></tr>'

    timeline_rows = ""
    for event in timeline_events:
        timeline_rows += (
            "<tr>"
            f"<td>{escape_html(event['timestamp'])}</td>"
            f"<td>{escape_html(event['event'])}</td>"
            f"<td>{escape_html(event['source'])}</td>"
            f"<td>{escape_html(event['person'])}</td>"
            f"<td>{escape_html(event['details'])}</td>"
            "</tr>"
        )
    if not timeline_rows:
        timeline_rows = '<tr><td colspan="5">No investigation timeline events recorded for this case.</td></tr>'

    incomplete_correlation = any(
        evidence_statuses[evidence["id"]] != "VERIFIED"
        for evidence in evidence_records
    )
    correlation_warning_html = ""
    if incomplete_correlation:
        correlation_warning_html = (
            '<div class="notice" style="background: #fdf3f2; border-color: #e2c044;">'
            "Correlation results may be incomplete because one or more current preserved evidence copies "
            "are missing, changed, or unverified."
            "</div>"
        )

    # 6. Note rows
    note_rows = ""
    for note in notes:
        note_rows += (
            "<tr>"
            f"<td>{escape_html(note['created_at'])}</td>"
            f"<td>{escape_html(note['note'])}</td>"
            "</tr>"
        )

    if not note_rows:
        note_rows = '<tr><td colspan="2">No investigation notes or findings recorded.</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyberTrace Forensic Report - {escape_html(case['case_id'])}</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 40px; color: #20252b; background-color: #fcfcfc; }}
h1 {{ color: #0f2b48; border-bottom: 2px solid #0f2b48; padding-bottom: 8px; }}
h2 {{ color: #16436f; margin-top: 30px; border-bottom: 1px solid #c0c9d2; padding-bottom: 6px; }}
h3 {{ color: #16436f; margin-top: 20px; font-size: 15px; margin-bottom: 8px; }}
.meta {{ background: #eef3f8; padding: 18px; border-radius: 8px; border: 1px solid #d0d9e2; }}
.health-score-box {{ background: #ffffff; border-left: 4px solid {health['color']}; padding: 14px 18px; margin: 16px 0; border-radius: 6px; border-top: 1px solid #e0e0e0; border-right: 1px solid #e0e0e0; border-bottom: 1px solid #e0e0e0; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; table-layout: fixed; }}
th, td {{ border: 1px solid #c9ced4; padding: 10px; text-align: left; vertical-align: top; word-break: break-word; overflow-wrap: break-word; }}
th {{ background: #e2e9f0; color: #1c324a; }}
.footer {{ margin-top: 40px; font-size: 12px; color: #666; border-top: 1px solid #ddd; padding-top: 12px; }}
.notice {{ background: #fdf8e6; border: 1px solid #e2c044; padding: 10px; border-radius: 6px; font-size: 12px; margin-top: 10px; }}
.disclaimer-text {{ font-size: 12px; color: #555; font-style: italic; margin-top: 8px; }}
</style>
</head>
<body>
<h1>CyberTrace — Digital Forensics Investigation Report</h1>
<div class="meta">
<strong>Case ID:</strong> {escape_html(case['case_id'])}<br>
<strong>Case Name:</strong> {escape_html(case['case_name'])}<br>
<strong>Investigator:</strong> {escape_html(case['investigator'])}<br>
<strong>Status:</strong> {escape_html(case['status'])}<br>
<strong>Created:</strong> {escape_html(case['created_at'])}<br>
<strong>Description:</strong> {escape_html(case['description'] or 'No description recorded.')}
</div>

<h2>Investigation Health &amp; Workflow Integrity</h2>
<div class="health-score-box">
<strong>Health Score:</strong> {health['score']} / 100 &nbsp;|&nbsp; <strong>Status:</strong> <span style="color: {health['color']}; font-weight: bold;">{escape_html(health['label'])}</span>
</div>
<h3>Factor Score Breakdown</h3>
<table><tr><th style="width: 25%;">Factor</th><th style="width: 15%;">Score</th><th style="width: 20%;">Status</th><th style="width: 40%;">Details</th></tr>{health_breakdown_rows}</table>
{risk_flags_html}
<p class="disclaimer-text"><strong>Disclaimer:</strong> {escape_html(health['disclaimer'])}</p>

<h2>8-Stage Investigation Lifecycle</h2>
<table><tr><th style="width: 12%;">Stage #</th><th style="width: 25%;">Stage Name</th><th style="width: 15%;">Status</th><th style="width: 15%;">State</th><th style="width: 33%;">Details</th></tr>{lifecycle_rows}</table>

<h2>Digital Evidence Inventory</h2>
<table><tr><th style="width: 12%;">ID</th><th style="width: 20%;">Evidence Name</th><th style="width: 25%;">SHA-256 Hash</th><th style="width: 15%;">Current Verification</th><th style="width: 15%;">Acquired</th><th style="width: 13%;">Preserved Path</th></tr>{evidence_rows}</table>

<h2>Chain of Custody History</h2>
<table><tr><th style="width: 20%;">Evidence</th><th style="width: 20%;">Timestamp</th><th style="width: 15%;">Action</th><th style="width: 20%;">Person</th><th style="width: 25%;">Remarks</th></tr>{custody_rows}</table>

<h2>File Analysis &amp; Examination Results</h2>
<table><tr><th style="width: 18%;">Analyzed At</th><th style="width: 20%;">File Name</th><th style="width: 12%;">Size</th><th style="width: 15%;">MIME Type</th><th style="width: 23%;">Examined SHA-256</th><th style="width: 12%;">Integrity</th></tr>{analysis_rows}</table>

<h2>Cross-Evidence Correlation Analysis</h2>
<p><strong>Evidence Items Analyzed:</strong> {len(evidence_records)} &nbsp;|&nbsp; <strong>Potential Relationships:</strong> {len(correlation_findings)}</p>
{correlation_warning_html}
<table><tr><th>Evidence A</th><th>Evidence B</th><th>Relationship</th><th>Indicator</th><th>Strength</th><th>Explanation</th><th>Detected</th></tr>{correlation_rows}</table>
<p class="disclaimer-text">Correlation findings are deterministic indicators of potential relationships between evidence items in this case. They do not establish common origin, criminal activity, user identity, intent, or legal significance. Investigator review is required.</p>

<h2>Investigation Timeline</h2>
<table><tr><th>Date &amp; Time</th><th>Event</th><th>Source</th><th>Person</th><th>Details</th></tr>{timeline_rows}</table>

<h2>Investigation Notes &amp; Findings</h2>
<table><tr><th style="width: 22%;">Created</th><th style="width: 78%;">Note / Finding</th></tr>{note_rows}</table>

<h2>Summary &amp; Conclusion</h2>
<p><strong>Recorded Facts:</strong> {escape_html("Current preserved-evidence verification statuses are listed in the evidence inventory." if evidence_records else "No evidence items were recorded; preservation and SHA-256 verification were not performed.")}</p>
<p><strong>Recorded Custody:</strong> {escape_html(f"{custody_count} custody event(s) are recorded." if custody_count else "No custody events are recorded.")}</p>
<p><strong>Investigator Findings:</strong> Documented in the analysis and notes sections of this report.</p>

<div class="notice">
<strong>Disclaimer:</strong> CyberTrace is an academic computer forensics software project demonstrating digital evidence lifecycle management.
</div>

<div class="footer">Generated by CyberTrace — Digital Forensics Investigation System<br>Report Generated: {escape_html(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
</body>
</html>"""

    return html, case


# =========================================================
# MAIN WINDOW
# =========================================================

class CyberTraceWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.settings = QSettings("CyberTrace", "CyberTraceApp")
        self.current_theme = self.settings.value("theme", "dark")
        self.active_tab = "dashboard"
        self.active_workers = []
        self.is_closing = False

        self.setWindowTitle("CyberTrace - Digital Forensics Investigation System")
        base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        icon_path = os.path.join(base_dir, "assets", "cybertrace.ico")
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "cybertrace.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setMinimumSize(1150, 720)
        self.setup_ui()
        self.apply_theme(self.current_theme)
        self.show_dashboard()

    def _track_worker(self, worker):
        if worker not in self.active_workers:
            self.active_workers.append(worker)
        worker.finished.connect(lambda: self._untrack_worker(worker))
        worker.finished.connect(worker.deleteLater)

    def _untrack_worker(self, worker):
        if worker in self.active_workers:
            self.active_workers.remove(worker)

    def closeEvent(self, event):
        self.is_closing = True
        running_workers = [w for w in list(self.active_workers) if w.isRunning()]
        if running_workers:
            for worker in running_workers:
                worker.requestInterruption()
            for worker in running_workers:
                if worker.isRunning():
                    worker.wait(2000)
            QApplication.processEvents()

        event.accept()

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.settings.setValue("theme", self.current_theme)
        self.apply_theme(self.current_theme)

    def apply_theme(self, theme_name):
        app = QApplication.instance()
        if app:
            app.setStyleSheet(get_theme_stylesheet(theme_name))

        if hasattr(self, "theme_button"):
            if theme_name == "light":
                self.theme_button.setText("🌙 Dark Mode")
            else:
                self.theme_button.setText("☀ Light Mode")

        if hasattr(self, "active_tab"):
            if self.active_tab == "dashboard":
                self.show_dashboard()
            elif self.active_tab == "cases":
                self.show_cases()
            elif self.active_tab == "evidence":
                self.show_evidence()
            elif self.active_tab == "custody":
                self.show_custody()
            elif self.active_tab == "analysis":
                self.show_analysis()
            elif self.active_tab == "timeline":
                self.show_timeline()
            elif self.active_tab == "notes":
                self.show_notes()
            elif self.active_tab == "reports":
                self.show_reports()

    # =====================================================
    # UI SETUP
    # =====================================================

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 25, 20, 20)
        sidebar_layout.setSpacing(8)

        logo = QLabel("CYBERTRACE")
        logo.setObjectName("logo")

        subtitle = QLabel("DIGITAL FORENSICS")
        subtitle.setObjectName("subtitle")

        sidebar_layout.addWidget(logo)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(30)

        self.dashboard_button = self.create_nav_button("Dashboard")
        self.cases_button = self.create_nav_button("Cases")
        self.evidence_button = self.create_nav_button("Evidence")
        self.custody_button = self.create_nav_button("Chain of Custody")
        self.analysis_button = self.create_nav_button("File Analysis")
        self.timeline_button = self.create_nav_button("Timeline")
        self.notes_button = self.create_nav_button("Notes & Findings")
        self.reports_button = self.create_nav_button("Reports")

        buttons = [
            self.dashboard_button,
            self.cases_button,
            self.evidence_button,
            self.custody_button,
            self.analysis_button,
            self.timeline_button,
            self.notes_button,
            self.reports_button,
        ]

        for button in buttons:
            sidebar_layout.addWidget(button)

        sidebar_layout.addStretch()

        self.theme_button = QPushButton()
        self.theme_button.setObjectName("theme_toggle_button")
        self.theme_button.setMinimumHeight(38)
        self.theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_button.clicked.connect(self.toggle_theme)

        sidebar_layout.addWidget(self.theme_button)
        sidebar_layout.addSpacing(15)

        # Nav connections
        self.dashboard_button.clicked.connect(self.show_dashboard)
        self.cases_button.clicked.connect(self.show_cases)
        self.evidence_button.clicked.connect(self.show_evidence)
        self.custody_button.clicked.connect(self.show_custody)
        self.analysis_button.clicked.connect(self.show_analysis)
        self.timeline_button.clicked.connect(self.show_timeline)
        self.notes_button.clicked.connect(self.show_notes)
        self.reports_button.clicked.connect(self.show_reports)

        # Content Frame
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setStyleSheet("QScrollArea { background-color: transparent; border: none; }")

        self.content = QFrame()
        self.content.setObjectName("content")

        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(35, 30, 35, 30)
        self.content_layout.setSpacing(20)

        scroll_area.setWidget(self.content)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(scroll_area, 1)

    # =====================================================
    # NAVIGATION HELPERS
    # =====================================================

    def create_empty_state(self, icon_str, title_text, description_text, action_text=None, action_slot=None):
        container = QFrame()
        container.setObjectName("panel")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(40, 50, 40, 50)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_icon = QLabel(icon_str)
        lbl_icon.setStyleSheet("font-size: 38px; color: #38bdf8;")
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_title = QLabel(title_text)
        lbl_title.setObjectName("section_title")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 700;")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_desc = QLabel(description_text)
        lbl_desc.setObjectName("section_description")
        lbl_desc.setStyleSheet("font-size: 13px; max-width: 480px;")
        lbl_desc.setWordWrap(True)
        lbl_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(lbl_icon)
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_desc)

        if action_text and action_slot:
            btn = QPushButton(action_text)
            btn.setObjectName("primary_button")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(action_slot)
            layout.addSpacing(8)
            layout.addWidget(btn, 0, Qt.AlignmentFlag.AlignCenter)

        return container

    def create_nav_button(self, text):
        button = QPushButton(text)
        button.setObjectName("nav_button")
        button.setMinimumHeight(42)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        return button

    def create_stat_card(self, title, value, description):
        card = QFrame()
        card.setObjectName("stat_card")
        card.setMinimumHeight(120)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(6)

        lbl_title = QLabel(title)
        lbl_title.setObjectName("card_title")

        lbl_val = QLabel("0")
        lbl_val.setObjectName("card_value")

        lbl_desc = QLabel(description)
        lbl_desc.setObjectName("card_description")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        layout.addWidget(lbl_desc)

        try:
            target_num = int(value)
            anim = QVariantAnimation(card)
            anim.setDuration(500)
            anim.setStartValue(0)
            anim.setEndValue(target_num)
            anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            anim.valueChanged.connect(lambda v: lbl_val.setText(str(int(v))))
            anim.start(QVariantAnimation.DeletionPolicy.DeleteWhenStopped)
            card._anim = anim
        except (ValueError, TypeError):
            lbl_val.setText(str(value))

        return card

    def animate_content_fade_in(self):
        if not hasattr(self, "content"):
            return
        opacity = QGraphicsOpacityEffect(self.content)
        opacity.setOpacity(1.0)
        self.content.setGraphicsEffect(opacity)
        anim = QPropertyAnimation(opacity, b"opacity", self)
        anim.setDuration(180)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        self._page_anim = anim

    def clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            child_layout = item.layout()

            if widget:
                widget.setParent(None)
                widget.deleteLater()
            elif child_layout:
                self.clear_layout(child_layout)
                child_layout.deleteLater()

    def clear_content(self):
        self.content.setMinimumHeight(0)
        self.clear_layout(self.content_layout)
        if self.statusBar():
            self.statusBar().clearMessage()
        self.animate_content_fade_in()

    def set_active_button(self, active):
        buttons = [
            self.dashboard_button,
            self.cases_button,
            self.evidence_button,
            self.custody_button,
            self.analysis_button,
            self.timeline_button,
            self.notes_button,
            self.reports_button,
        ]

        for button in buttons:
            if button == active:
                button.setObjectName("nav_button_active")
            else:
                button.setObjectName("nav_button")

            button.style().unpolish(button)
            button.style().polish(button)

    # =====================================================
    # DASHBOARD VIEW
    # =====================================================

    def show_dashboard(self):
        self.active_tab = "dashboard"
        self.clear_content()
        self.content.setMinimumHeight(1050)
        self.set_active_button(self.dashboard_button)

        header = QHBoxLayout()
        text_layout = QVBoxLayout()

        title = QLabel("Investigation Dashboard")
        title.setObjectName("page_title")

        description = QLabel("Manage digital evidence and forensic investigations")
        description.setObjectName("page_description")

        text_layout.addWidget(title)
        text_layout.addWidget(description)

        header.addLayout(text_layout)
        header.addStretch()

        status = QLabel("● SYSTEM READY")
        status.setObjectName("status")

        header.addWidget(status)
        self.content_layout.addLayout(header)

        cards = QHBoxLayout()
        cards.setSpacing(15)

        cards.addWidget(
            self.create_stat_card(
                "ACTIVE CASES",
                str(get_active_case_count()),
                "Cases currently under investigation"
            )
        )

        cards.addWidget(
            self.create_stat_card(
                "EVIDENCE ITEMS",
                str(get_evidence_count()),
                "Digital evidence registered"
            )
        )

        cards.addWidget(
            self.create_stat_card(
                "HASH VERIFIED",
                str(get_verified_evidence_count()),
                "Evidence with SHA-256 hash"
            )
        )

        cards.addWidget(
            self.create_stat_card(
                "CUSTODY EVENTS",
                str(len(get_custody_events())),
                "Evidence handling events"
            )
        )

        self.content_layout.addLayout(cards)

        # -----------------------------------------------------
        # FORENSIC ANALYTICS PANEL
        # -----------------------------------------------------
        analytics_frame = QFrame()
        analytics_frame.setObjectName("panel")
        analytics_frame.setMinimumHeight(260)
        analytics_layout = QVBoxLayout(analytics_frame)
        analytics_layout.setContentsMargins(20, 20, 20, 20)

        analytics_title = QLabel("Forensic System Analytics & Integrity Metrics")
        analytics_title.setObjectName("section_title")
        analytics_layout.addWidget(analytics_title)

        analytics_data = get_forensic_analytics_summary()

        analytics_meters_layout = QHBoxLayout()
        analytics_meters_layout.setSpacing(20)

        # Verification distribution meter
        ver_items = [
            {"label": "MATCH Verified", "count": analytics_data["verification_distribution"]["MATCH"], "color": "#2ecc71"},
            {"label": "MISMATCH Warning", "count": analytics_data["verification_distribution"]["MISMATCH"], "color": "#e74c3c"},
            {"label": "FILE MISSING", "count": analytics_data["verification_distribution"]["FILE MISSING"], "color": "#e67e22"},
            {"label": "UNVERIFIED Pending", "count": analytics_data["verification_distribution"]["UNVERIFIED"], "color": "#95a5a6"},
        ]
        ver_meter = ForensicBarMeter("SHA-256 Evidence Verification Distribution", ver_items, theme=self.current_theme)

        # MIME Category distribution meter
        mime_items = [
            {"label": "Text / Documents", "count": analytics_data["mime_distribution"]["Text / Documents"], "color": "#3498db"},
            {"label": "Images", "count": analytics_data["mime_distribution"]["Images"], "color": "#9b59b6"},
            {"label": "Binaries / Executables", "count": analytics_data["mime_distribution"]["Executables / Binaries"], "color": "#e74c3c"},
            {"label": "Archives", "count": analytics_data["mime_distribution"]["Archives"], "color": "#f1c40f"},
            {"label": "Other / System Files", "count": analytics_data["mime_distribution"]["Other / System"], "color": "#7f8c8d"},
        ]
        mime_meter = ForensicBarMeter("Evidence File Categories", mime_items, theme=self.current_theme)

        analytics_meters_layout.addWidget(ver_meter, 1)
        analytics_meters_layout.addWidget(mime_meter, 1)

        analytics_layout.addLayout(analytics_meters_layout)
        self.content_layout.addWidget(analytics_frame)

        # -----------------------------------------------------
        # ATTENTION & RISK ENGINE SUMMARY
        # -----------------------------------------------------
        attention_flags = get_evidence_attention_flags()
        if attention_flags:
            att_frame = QFrame()
            att_frame.setObjectName("panel")
            att_border = "#d4a72c" if self.current_theme == "light" else "#e67e22"
            att_bg = "#fff8c5" if self.current_theme == "light" else "#2c2219"
            att_frame.setStyleSheet(f"QFrame#panel {{ border: 1px solid {att_border}; background-color: {att_bg}; }}")
            att_layout = QVBoxLayout(att_frame)
            att_layout.setContentsMargins(18, 18, 18, 18)

            att_title_color = "#9a6700" if self.current_theme == "light" else "#f39c12"
            att_title = QLabel(f"Evidence Attention Engine ({len(attention_flags)} active workflow notification(s))")
            att_title.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {att_title_color};")
            att_layout.addWidget(att_title)

            desc_color = "#1f2328" if self.current_theme == "light" else "#ecf0f1"
            for flag in attention_flags[:4]:
                flag_row = QHBoxLayout()
                badge_bg = flag["color"]
                if self.current_theme == "light":
                    if badge_bg == "#e74c3c":
                        badge_bg = "#cf222e"
                    elif badge_bg == "#e67e22" or badge_bg == "#f39c12":
                        badge_bg = "#d97706"
                lvl_badge = QLabel(flag["level"])
                lvl_badge.setStyleSheet(f"background-color: {badge_bg}; color: #ffffff; font-weight: bold; font-size: 10px; padding: 2px 8px; border-radius: 8px;")
                desc_lbl = QLabel(f"<b>[{flag['case_id']} - {flag['evidence_name']}]</b> {flag['title']}: {flag['description']}")
                desc_lbl.setStyleSheet(f"color: {desc_color}; font-size: 11px;")
                desc_lbl.setWordWrap(True)

                flag_row.addWidget(lvl_badge)
                flag_row.addWidget(desc_lbl, 1)
                att_layout.addLayout(flag_row)

            self.content_layout.addWidget(att_frame)

        # -----------------------------------------------------
        # WORKFLOW & LIFECYCLE PANEL
        # -----------------------------------------------------
        workflow_frame = QFrame()
        workflow_frame.setObjectName("panel")
        workflow_frame.setMinimumHeight(280)

        workflow_layout = QVBoxLayout(workflow_frame)
        workflow_layout.setContentsMargins(25, 25, 25, 25)

        cases = get_cases()
        active_case_id = cases[0]["id"] if cases else None
        stages = get_case_lifecycle_stage(active_case_id)
        lifecycle_w = LifecycleWidget(stages, theme=self.current_theme)
        workflow_layout.addWidget(lifecycle_w)

        self.content_layout.addWidget(workflow_frame)

        action_frame = QFrame()
        action_frame.setObjectName("panel")

        action_layout = QVBoxLayout(action_frame)
        action_layout.setContentsMargins(25, 25, 25, 25)

        action_title = QLabel("Quick Actions")
        action_title.setObjectName("section_title")
        action_layout.addWidget(action_title)

        action_buttons = QHBoxLayout()

        new_case = QPushButton("+  New Investigation Case")
        new_case.setObjectName("primary_button")
        new_case.clicked.connect(self.new_case)

        add_evidence = QPushButton("+  Add Digital Evidence")
        add_evidence.setObjectName("secondary_button")
        add_evidence.clicked.connect(self.add_evidence)

        action_buttons.addWidget(new_case)
        action_buttons.addWidget(add_evidence)

        action_layout.addLayout(action_buttons)
        self.content_layout.addWidget(action_frame)
        self.content_layout.addStretch()


    # =====================================================
    # CASES VIEW
    # =====================================================

    def show_cases(self):
        self.active_tab = "cases"
        self.clear_content()
        self.set_active_button(self.cases_button)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("Case Management")
        title.setObjectName("page_title")

        description = QLabel("Create, review and manage digital forensic investigation cases")
        description.setObjectName("page_description")

        title_layout.addWidget(title)
        title_layout.addWidget(description)

        header.addLayout(title_layout)
        header.addStretch()

        new_button = QPushButton("+  New Investigation Case")
        new_button.setObjectName("primary_button")
        new_button.clicked.connect(self.new_case)

        header.addWidget(new_button)
        self.content_layout.addLayout(header)

        search_layout = QHBoxLayout()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Search by Case ID, Case Name, Investigator or Status..."
        )
        self.search_input.setMinimumHeight(42)
        self.search_input.textChanged.connect(self.load_cases)

        search_layout.addWidget(self.search_input)

        refresh = QPushButton("Refresh")
        refresh.setObjectName("secondary_button")
        refresh.clicked.connect(self.load_cases)

        search_layout.addWidget(refresh)
        self.content_layout.addLayout(search_layout)

        self.case_table = QTableWidget()
        self.case_table.setColumnCount(7)
        self.case_table.setHorizontalHeaderLabels([
            "Case ID",
            "Case Name",
            "Investigator",
            "Status",
            "Health Score",
            "Created",
            "Actions",
        ])

        self.case_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.case_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.case_table.setAlternatingRowColors(True)
        self.case_table.verticalHeader().setVisible(False)

        header_view = self.case_table.horizontalHeader()
        header_view.setMinimumSectionSize(60)
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)

        self.case_table.setColumnWidth(0, 95)
        self.case_table.setColumnWidth(2, 105)
        self.case_table.setColumnWidth(3, 75)
        self.case_table.setColumnWidth(4, 135)
        self.case_table.setColumnWidth(5, 125)
        self.case_table.setColumnWidth(6, 195)
        self.case_table.verticalHeader().setDefaultSectionSize(46)

        self.case_detail_container = QVBoxLayout()

        self.content_layout.addWidget(self.case_table)
        self.content_layout.addLayout(self.case_detail_container)

        self.case_table.itemSelectionChanged.connect(self.on_case_selected)
        self.load_cases()

    def load_cases(self):
        if not hasattr(self, "case_table"):
            return

        search = self.search_input.text() if hasattr(self, "search_input") else ""
        cases = get_cases(search)

        self.case_table.setRowCount(len(cases))
        table_height = max(180, 42 + len(cases) * 46 + 12)
        self.case_table.setMinimumHeight(table_height)

        for row, case in enumerate(cases):
            health = get_case_health(case["id"])

            values = [
                case["case_id"],
                case["case_name"],
                case["investigator"],
                case["status"],
                f"{health['score']}/100 {health['label']}",
                case["created_at"],
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                if column == 4:
                    item.setForeground(QColor(health['color']))
                self.case_table.setItem(row, column, item)

            actions = QWidget()
            action_layout = QHBoxLayout(actions)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setSpacing(6)
            action_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            summary_btn = QPushButton("Summary")
            summary_btn.setObjectName("small_button")

            edit = QPushButton("Edit")
            edit.setObjectName("small_button")

            delete = QPushButton("Delete")
            delete.setObjectName("danger_button")

            database_id = case["id"]
            case_code = case["case_id"]

            summary_btn.clicked.connect(
                lambda checked=False, c_id=database_id, c_code=case_code: self.show_executive_summary(c_id, c_code)
            )

            edit.clicked.connect(
                lambda checked=False, case_id=database_id: self.edit_case(case_id)
            )

            delete.clicked.connect(
                lambda checked=False, case_id=database_id: self.delete_case(case_id)
            )

            action_layout.addWidget(summary_btn)
            action_layout.addWidget(edit)
            action_layout.addWidget(delete)

            self.case_table.setCellWidget(row, 6, actions)

        if len(cases) > 0 and self.case_table.rowCount() > 0:
            self.case_table.selectRow(0)

    def show_executive_summary(self, case_db_id, case_code):
        summary_text = get_automated_case_summary(case_db_id)
        dlg = ExecutiveSummaryDialog(case_code, summary_text, self.current_theme, self)
        dlg.exec()

    def on_case_selected(self):
        selected = self.case_table.selectedItems()
        if not selected or not hasattr(self, "case_detail_container"):
            return

        row = selected[0].row()
        case_code_item = self.case_table.item(row, 0)
        if not case_code_item:
            return

        case_code = case_code_item.text()

        # Clear existing detail container widgets
        while self.case_detail_container.count():
            child = self.case_detail_container.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
            elif child.layout():
                # clear nested layout if any
                pass

        health_data = get_case_health(case_code)
        health_widget = HealthScoreWidget(health_data, theme=self.current_theme)

        stages = get_case_lifecycle_stage(case_code)
        lifecycle_widget = LifecycleWidget(stages, theme=self.current_theme)

        self.case_detail_container.addWidget(health_widget)
        self.case_detail_container.addWidget(lifecycle_widget)


    # =====================================================
    # EVIDENCE VIEW
    # =====================================================

    def show_evidence(self):
        self.active_tab = "evidence"
        self.clear_content()
        self.set_active_button(self.evidence_button)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("Evidence Management")
        title.setObjectName("page_title")

        description = QLabel("Acquire, preserve and verify digital evidence")
        description.setObjectName("page_description")

        title_layout.addWidget(title)
        title_layout.addWidget(description)

        header.addLayout(title_layout)
        header.addStretch()

        add_button = QPushButton("+  Add Digital Evidence")
        add_button.setObjectName("primary_button")
        add_button.clicked.connect(self.add_evidence)

        header.addWidget(add_button)
        self.content_layout.addLayout(header)

        search_layout = QHBoxLayout()

        self.evidence_search = QLineEdit()
        self.evidence_search.setPlaceholderText(
            "Search evidence name, Case ID, case name or SHA-256..."
        )
        self.evidence_search.setMinimumHeight(42)
        self.evidence_search.textChanged.connect(self.load_evidence)

        search_layout.addWidget(self.evidence_search)

        refresh = QPushButton("Refresh")
        refresh.setObjectName("secondary_button")
        refresh.clicked.connect(self.load_evidence)

        search_layout.addWidget(refresh)
        self.content_layout.addLayout(search_layout)

        self.evidence_table = QTableWidget()
        self.evidence_table.setColumnCount(6)
        self.evidence_table.setHorizontalHeaderLabels([
            "Evidence",
            "Case",
            "SHA-256",
            "Acquired",
            "Preserved Copy",
            "Status",
        ])

        self.evidence_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.evidence_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.evidence_table.setAlternatingRowColors(True)
        self.evidence_table.verticalHeader().setVisible(False)

        header_view = self.evidence_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.evidence_table.verticalHeader().setDefaultSectionSize(38)

        self.evidence_rel_container = QVBoxLayout()

        self.content_layout.addWidget(self.evidence_table)
        self.content_layout.addLayout(self.evidence_rel_container)

        correlation_panel = QFrame()
        correlation_panel.setObjectName("panel")
        correlation_layout = QVBoxLayout(correlation_panel)
        correlation_layout.setContentsMargins(18, 18, 18, 18)

        correlation_header = QHBoxLayout()
        correlation_title = QLabel("Cross-Evidence Forensic Correlation")
        correlation_title.setObjectName("section_title")
        correlation_header.addWidget(correlation_title)
        correlation_header.addStretch()

        self.correlation_case_context = QLabel("Select evidence to choose a case.")
        self.correlation_case_context.setObjectName("section_description")
        correlation_header.addWidget(self.correlation_case_context)
        correlation_layout.addLayout(correlation_header)

        correlation_controls = QHBoxLayout()
        self.correlation_contextual_checkbox = QCheckBox("Show contextual / weak relationships")
        self.correlation_contextual_checkbox.setChecked(False)
        run_correlation = QPushButton("Run Correlation")
        run_correlation.setObjectName("primary_button")
        run_correlation.clicked.connect(self.run_correlation)
        refresh_correlation = QPushButton("Refresh Results")
        refresh_correlation.setObjectName("secondary_button")
        refresh_correlation.clicked.connect(self.load_correlation_results)
        self.open_graph_button = QPushButton("Open Relationship Graph")
        self.open_graph_button.setObjectName("secondary_button")
        self.open_graph_button.clicked.connect(self.open_relationship_graph)
        correlation_controls.addWidget(self.correlation_contextual_checkbox)
        correlation_controls.addStretch()
        correlation_controls.addWidget(run_correlation)
        correlation_controls.addWidget(refresh_correlation)
        correlation_layout.addLayout(correlation_controls)

        graph_controls = QHBoxLayout()
        graph_controls.addWidget(self.open_graph_button)
        graph_controls.addStretch()
        correlation_layout.addLayout(graph_controls)

        self.correlation_table = QTableWidget()
        self.correlation_table.setColumnCount(7)
        self.correlation_table.setHorizontalHeaderLabels([
            "Evidence A",
            "Evidence B",
            "Relationship",
            "Indicator",
            "Strength",
            "Explanation",
            "Detected",
        ])
        self.correlation_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.correlation_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.correlation_table.setAlternatingRowColors(True)
        self.correlation_table.verticalHeader().setVisible(False)
        correlation_header_view = self.correlation_table.horizontalHeader()
        for column in range(5):
            correlation_header_view.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        correlation_header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        correlation_header_view.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        correlation_layout.addWidget(self.correlation_table)

        self.correlation_status = QLabel("No correlation run has been performed for the selected case.")
        self.correlation_status.setObjectName("section_description")
        self.correlation_status.setWordWrap(True)
        correlation_layout.addWidget(self.correlation_status)
        self.content_layout.addWidget(correlation_panel)

        self.evidence_table.itemSelectionChanged.connect(self.on_evidence_selected)
        self.load_evidence()


    def load_evidence(self):
        if not hasattr(self, "evidence_table"):
            return

        search = self.evidence_search.text() if hasattr(self, "evidence_search") else ""
        records = get_evidence(search)

        self.evidence_table.setRowCount(len(records))

        for row, evidence in enumerate(records):
            ev_name = QTableWidgetItem(evidence["evidence_name"])
            ev_name.setToolTip(evidence["evidence_name"])
            ev_name.setData(Qt.ItemDataRole.UserRole, evidence["id"])
            self.evidence_table.setItem(row, 0, ev_name)

            case_str = f"{evidence['case_number']} - {evidence['case_name']}"
            case_item = QTableWidgetItem(case_str)
            case_item.setToolTip(case_str)
            case_item.setData(Qt.ItemDataRole.UserRole, evidence["case_id"])
            self.evidence_table.setItem(row, 1, case_item)

            hash_str = evidence["sha256"] or ""
            hash_item = QTableWidgetItem(hash_str)
            hash_item.setToolTip(hash_str)
            self.evidence_table.setItem(row, 2, hash_item)

            acq_item = QTableWidgetItem(evidence["acquired_at"] or "")
            self.evidence_table.setItem(row, 3, acq_item)

            path_str = evidence["preserved_path"] or ""
            path_item = QTableWidgetItem(path_str)
            path_item.setToolTip(path_str)
            self.evidence_table.setItem(row, 4, path_item)

            status = QTableWidgetItem(
                get_current_evidence_status(evidence)
            )
            self.evidence_table.setItem(row, 5, status)

        if len(records) > 0 and self.evidence_table.rowCount() > 0:
            self.evidence_table.selectRow(0)

    def on_evidence_selected(self):
        selected = self.evidence_table.selectedItems()
        if not selected or not hasattr(self, "evidence_rel_container"):
            return

        row = selected[0].row()
        case_item = self.evidence_table.item(row, 1)
        if not case_item:
            return

        case_database_id = case_item.data(Qt.ItemDataRole.UserRole)
        if case_database_id is None:
            return

        while self.evidence_rel_container.count():
            child = self.evidence_rel_container.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        rel_data = get_evidence_relationship_data(case_database_id)
        if rel_data:
            rel_widget = EvidenceRelationshipWidget(rel_data, theme=self.current_theme)
            self.evidence_rel_container.addWidget(rel_widget)
        case = get_case(case_database_id)
        if case:
            self.current_correlation_case_id = case["id"]
            self.correlation_case_context.setText(f"Case: {case['case_id']} | {case['case_name']}")
            self.load_correlation_results()

    def load_correlation_results(self):
        """Display persisted correlation results without running analysis."""
        if not hasattr(self, "correlation_table"):
            return
        case_id = getattr(self, "current_correlation_case_id", None)
        if case_id is None:
            self.correlation_table.setRowCount(0)
            self.correlation_status.setText("Select evidence to choose a case.")
            return

        findings = get_correlation_findings(case_id)
        if not self.correlation_contextual_checkbox.isChecked():
            findings = [finding for finding in findings if finding["strength_score"] >= 45]
        self.correlation_table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            values = [
                f"EV-{finding['evidence_a_id']:04d} | {finding['evidence_a_name']}",
                f"EV-{finding['evidence_b_id']:04d} | {finding['evidence_b_name']}",
                finding["relationship_type"],
                finding["indicator_display"] or "N/A",
                finding["strength_label"],
                finding["explanation"],
                finding["detected_at"],
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.correlation_table.setItem(row, column, item)

        self.correlation_status.setText(
            f"{len(findings)} potential relationship(s) currently shown. "
            "Correlation findings are deterministic indicators and require investigator review."
        )

    def open_relationship_graph(self):
        """Show persisted case-scoped findings without running correlation."""
        case_id = getattr(self, "current_correlation_case_id", None)
        if case_id is None:
            QMessageBox.warning(
                self,
                "No Case Selected",
                "Select evidence from an investigation case first.",
            )
            return

        self.relationship_graph_dialog = RelationshipGraphDialog(
            case_id,
            theme=self.current_theme,
            parent=self,
            select_evidence_callback=self.select_evidence_row,
        )
        self.relationship_graph_dialog.show()

    def select_evidence_row(self, evidence_id):
        """Select an evidence row from a graph node double-click."""
        if not hasattr(self, "evidence_table"):
            return
        for row in range(self.evidence_table.rowCount()):
            name_item = self.evidence_table.item(row, 0)
            if name_item and name_item.data(Qt.ItemDataRole.UserRole) == evidence_id:
                self.evidence_table.selectRow(row)
                return

    def run_correlation(self):
        """Run and atomically persist correlation results for the selected case."""
        case_id = getattr(self, "current_correlation_case_id", None)
        if case_id is None:
            QMessageBox.warning(self, "No Case Selected", "Select evidence from an investigation case first.")
            return

        progress = QProgressDialog("Correlating preserved evidence copies...", "Cancel", 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Cross-Evidence Forensic Correlation")
        progress.show()
        worker = CorrelationWorker(
            case_id,
            self.correlation_contextual_checkbox.isChecked(),
            self,
        )

        def on_finished(result):
            if getattr(self, "is_closing", False) or worker.isInterruptionRequested():
                return
            progress.close()
            self.load_correlation_results()
            warning_text = ""
            if result.get("warnings"):
                warning_text = " " + " ".join(result["warnings"])
            self.correlation_status.setText(
                f"Correlation found {len(result['findings'])} potential relationship(s) across "
                f"{result['evidence_count']} evidence item(s). Requires investigator review.{warning_text}"
            )

        def on_error(error):
            if getattr(self, "is_closing", False) or worker.isInterruptionRequested():
                return
            progress.close()
            QMessageBox.critical(self, "Correlation Failed", f"Correlation could not be completed.\n\nError: {error}")

        progress.canceled.connect(worker.requestInterruption)
        progress.canceled.connect(progress.close)
        worker.finished_signal.connect(on_finished)
        worker.error_signal.connect(on_error)
        worker.finished_signal.connect(
            lambda result, active_worker=worker: self._untrack_worker(active_worker)
        )
        worker.error_signal.connect(
            lambda error, active_worker=worker: self._untrack_worker(active_worker)
        )
        self._track_worker(worker)
        worker.start()

    def add_evidence(self):

        dialog = EvidenceDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        data = dialog.get_data()
        original_path = data["file_path"]
        case_database_id = data["case_id"]

        case = get_case(case_database_id)
        if not case:
            QMessageBox.critical(
                self,
                "Case Error",
                "The selected investigation case could not be found."
            )
            return

        case_number = case["case_id"]
        raw_name = os.path.basename(original_path)
        clean_name = sanitize_filename(raw_name)

        evidence_root = os.path.join(get_app_dir(), "evidence")
        case_folder = os.path.join(evidence_root, case_number)
        os.makedirs(case_folder, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        preserved_name = f"{timestamp}_{clean_name}"
        preserved_path = os.path.join(case_folder, preserved_name)

        suffix = 1
        while os.path.exists(preserved_path):
            preserved_path = os.path.join(
                case_folder,
                f"{timestamp}_{suffix}_{clean_name}"
            )
            suffix += 1

        # Use progress dialog / worker for smooth experience
        progress = QProgressDialog("Acquiring digital evidence...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Evidence Acquisition")
        progress.show()

        worker = AcquisitionWorker(original_path, preserved_path, self)

        def on_progress(msg):
            if getattr(self, "is_closing", False) or worker.isInterruptionRequested():
                return
            progress.setLabelText(msg)

        def on_finished(result):
            if getattr(self, "is_closing", False) or worker.isInterruptionRequested():
                return
            progress.close()
            orig_hash = result["original_hash"]
            pres_hash = result["preserved_hash"]

            if orig_hash != pres_hash:
                unprotect_evidence_file(preserved_path)
                try:
                    os.remove(preserved_path)
                except OSError:
                    pass

                QMessageBox.critical(
                    self,
                    "Integrity Verification Failed",
                    "The SHA-256 hash of the preserved copy does not match the original file.\n\n"
                    "The evidence was NOT registered."
                )
                return

            acquired_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            try:
                evidence_id = create_evidence_with_custody(
                    case_database_id,
                    raw_name,
                    original_path,
                    preserved_path,
                    pres_hash,
                    acquired_at,
                    case["investigator"],
                    "Evidence acquired and controlled copy created."
                )

                QMessageBox.information(
                    self,
                    "Evidence Acquired",
                    f"Digital evidence acquired successfully.\n\n"
                    f"Evidence ID: EV-{evidence_id:04d}\n\n"
                    f"SHA-256:\n{pres_hash}\n\n"
                    f"Original file was not modified.\n"
                    f"Controlled copy created and write-protected successfully.\n\n"
                    f"Initial custody event recorded."
                )

                self.show_evidence()

            except Exception as db_err:
                cleanup_error = cleanup_acquisition_copy(
                    preserved_path,
                    worker.copy_created,
                )
                cleanup_message = (
                    f"\n\nCleanup warning: {cleanup_error}"
                    if cleanup_error
                    else ""
                )
                QMessageBox.critical(
                    self,
                    "Evidence Registration Failed",
                    f"Could not record evidence in database.\n\nError: {db_err}"
                    f"{cleanup_message}"
                )

        def on_error(err_msg):
            if getattr(self, "is_closing", False) or worker.isInterruptionRequested():
                return
            progress.close()
            cleanup_error = cleanup_acquisition_copy(
                preserved_path,
                worker.copy_created,
            )
            cleanup_message = ""
            if cleanup_error:
                cleanup_message = f"\n\nCleanup warning: {cleanup_error}"

            QMessageBox.critical(
                self,
                "Evidence Acquisition Failed",
                f"The evidence could not be acquired.\n\nError: {err_msg}"
                f"{cleanup_message}"
            )

        worker.progress_signal.connect(on_progress)
        worker.finished_signal.connect(on_finished)
        worker.error_signal.connect(on_error)
        worker.finished_signal.connect(
            lambda result, active_worker=worker: self._untrack_worker(active_worker)
        )
        worker.error_signal.connect(
            lambda error, active_worker=worker: self._untrack_worker(active_worker)
        )
        self._track_worker(worker)
        worker.start()

    # =====================================================
    # CHAIN OF CUSTODY VIEW
    # =====================================================

    def show_custody(self):
        self.active_tab = "custody"
        self.clear_content()
        self.set_active_button(self.custody_button)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("Chain of Custody")
        title.setObjectName("page_title")

        description = QLabel("Track the handling and movement of digital evidence")
        description.setObjectName("page_description")

        title_layout.addWidget(title)
        title_layout.addWidget(description)

        header.addLayout(title_layout)
        header.addStretch()

        self.content_layout.addLayout(header)

        selection_panel = QFrame()
        selection_panel.setObjectName("panel")

        selection_layout = QHBoxLayout(selection_panel)
        selection_layout.setContentsMargins(18, 18, 18, 18)

        selection_label = QLabel("Select Evidence:")
        selection_label.setObjectName("section_title")

        self.custody_evidence_combo = QComboBox()
        evidence_records = get_evidence()

        for evidence in evidence_records:
            self.custody_evidence_combo.addItem(
                f"EV-{evidence['id']:04d} | {evidence['case_number']} | {evidence['evidence_name']}",
                evidence["id"]
            )

        self.custody_evidence_combo.currentIndexChanged.connect(self.load_custody)

        add_event = QPushButton("+  Add Custody Event")
        add_event.setObjectName("primary_button")
        add_event.clicked.connect(self.add_custody_event)

        verify = QPushButton("Verify Chain Integrity")
        verify.setObjectName("secondary_button")
        verify.clicked.connect(self.verify_selected_chain)

        selection_layout.addWidget(selection_label)
        selection_layout.addWidget(self.custody_evidence_combo, 1)
        selection_layout.addWidget(add_event)
        selection_layout.addWidget(verify)

        self.content_layout.addWidget(selection_panel)

        self.custody_table = QTableWidget()
        self.custody_table.setColumnCount(7)
        self.custody_table.setHorizontalHeaderLabels([
            "Event",
            "Action",
            "Person",
            "Timestamp",
            "Remarks",
            "Previous Hash",
            "Event Hash",
        ])

        self.custody_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.custody_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.custody_table.setAlternatingRowColors(True)
        self.custody_table.verticalHeader().setVisible(False)

        header_view = self.custody_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.custody_table.verticalHeader().setDefaultSectionSize(38)

        self.content_layout.addWidget(self.custody_table)

        self.custody_status = QLabel("Select evidence to view its custody history.")
        self.custody_status.setObjectName("custody_status")
        self.custody_status.setWordWrap(True)

        self.content_layout.addWidget(self.custody_status)
        self.load_custody()

    def load_custody(self):
        if not hasattr(self, "custody_table"):
            return

        evidence_id = self.custody_evidence_combo.currentData()
        if evidence_id is None:
            self.custody_table.setRowCount(0)
            self.custody_status.setText("No digital evidence is available.")
            return

        events = get_custody_events(evidence_id)
        self.custody_table.setRowCount(len(events))

        for row, event in enumerate(events):
            self.custody_table.setItem(row, 0, QTableWidgetItem(f"#{event['id']}"))
            self.custody_table.setItem(row, 1, QTableWidgetItem(event["action"]))
            self.custody_table.setItem(row, 2, QTableWidgetItem(event["person"]))
            self.custody_table.setItem(row, 3, QTableWidgetItem(event["timestamp"]))

            remarks_item = QTableWidgetItem(event["remarks"] or "")
            remarks_item.setToolTip(event["remarks"] or "")
            self.custody_table.setItem(row, 4, remarks_item)

            prev_hash = event["previous_hash"] or "GENESIS"
            prev_item = QTableWidgetItem(prev_hash)
            prev_item.setToolTip(prev_hash)
            self.custody_table.setItem(row, 5, prev_item)

            event_hash = event["event_hash"] or ""
            hash_item = QTableWidgetItem(event_hash)
            hash_item.setToolTip(event_hash)
            self.custody_table.setItem(row, 6, hash_item)

        valid, message = verify_custody_chain(evidence_id)
        if valid:
            self.custody_status.setText(f"● CHAIN INTEGRITY VERIFIED  —  {message}")
            self.custody_status.setObjectName("integrity_success")
        else:
            self.custody_status.setText(f"● CHAIN VERIFICATION FAILED  —  {message}")
            self.custody_status.setObjectName("integrity_failed")

        self.custody_status.style().unpolish(self.custody_status)
        self.custody_status.style().polish(self.custody_status)

    def add_custody_event(self):
        evidence_id = self.custody_evidence_combo.currentData()
        if evidence_id is None:
            QMessageBox.warning(self, "No Evidence", "Please acquire digital evidence first.")
            return

        evidence = get_evidence_by_id(evidence_id)
        if not evidence:
            QMessageBox.warning(self, "Evidence Not Found", "The selected evidence could not be found.")
            return

        dialog = CustodyDialog(self, evidence)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        data = dialog.get_data()
        try:
            event_id = add_custody_event(
                evidence_id,
                data["action"],
                data["person"],
                data["remarks"]
            )

            QMessageBox.information(
                self,
                "Custody Event Added",
                f"Custody event #{event_id} was recorded successfully.\n\n"
                f"The event has been linked to the previous custody event using SHA-256."
            )
            self.load_custody()

        except Exception as error:
            QMessageBox.critical(
                self,
                "Custody Error",
                f"The custody event could not be recorded.\n\nError: {error}"
            )

    def verify_selected_chain(self):
        evidence_id = self.custody_evidence_combo.currentData()
        if evidence_id is None:
            QMessageBox.warning(self, "No Evidence", "Please select an evidence item.")
            return

        valid, message = verify_custody_chain(evidence_id)
        if valid:
            QMessageBox.information(
                self,
                "Integrity Verified",
                f"CHAIN OF CUSTODY VERIFIED\n\n{message}\n\n"
                f"All custody event hashes match their stored records."
            )
        else:
            QMessageBox.critical(
                self,
                "Integrity Verification Failed",
                f"CHAIN OF CUSTODY VERIFICATION FAILED\n\n{message}"
            )
        self.load_custody()

    # =====================================================
    # FILE ANALYSIS VIEW & PERSISTENCE FIX
    # =====================================================

    def show_analysis(self):
        self.active_tab = "analysis"
        self.clear_content()
        self.set_active_button(self.analysis_button)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("File Analysis")
        title.setObjectName("page_title")

        description = QLabel(
            "Analyze the preserved evidence copy without modifying the original evidence"
        )
        description.setObjectName("page_description")

        title_layout.addWidget(title)
        title_layout.addWidget(description)

        header.addLayout(title_layout)
        header.addStretch()

        self.content_layout.addLayout(header)

        selection_panel = QFrame()
        selection_panel.setObjectName("panel")

        selection_layout = QVBoxLayout(selection_panel)
        selection_layout.setContentsMargins(20, 20, 20, 20)

        selection_title = QLabel("Select Evidence for Examination")
        selection_title.setObjectName("section_title")

        selection_description = QLabel(
            "CyberTrace analyzes the preserved evidence copy stored in the evidence directory."
        )
        selection_description.setObjectName("section_description")
        selection_description.setWordWrap(True)

        self.analysis_evidence_combo = QComboBox()
        records = get_evidence()

        for evidence in records:
            self.analysis_evidence_combo.addItem(
                f"EV-{evidence['id']:04d} | {evidence['case_number']} | {evidence['evidence_name']}",
                evidence["id"]
            )

        analyze_button = QPushButton("Analyze Preserved Evidence")
        analyze_button.setObjectName("primary_button")
        analyze_button.clicked.connect(self.run_file_analysis)

        selection_layout.addWidget(selection_title)
        selection_layout.addWidget(selection_description)

        selection_row = QHBoxLayout()
        selection_row.addWidget(self.analysis_evidence_combo, 1)
        selection_row.addWidget(analyze_button)

        selection_layout.addLayout(selection_row)
        self.content_layout.addWidget(selection_panel)

        self.analysis_result_panel = QFrame()
        self.analysis_result_panel.setObjectName("panel")

        result_layout = QVBoxLayout(self.analysis_result_panel)
        result_layout.setContentsMargins(20, 20, 20, 20)

        result_title = QLabel("Forensic File Metadata")
        result_title.setObjectName("section_title")
        result_layout.addWidget(result_title)

        self.analysis_table = QTableWidget()
        self.analysis_table.setColumnCount(2)
        self.analysis_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.analysis_table.setRowCount(0)
        self.analysis_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.analysis_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.analysis_table.setAlternatingRowColors(True)
        self.analysis_table.verticalHeader().setVisible(False)

        analysis_header = self.analysis_table.horizontalHeader()
        analysis_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        analysis_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        result_layout.addWidget(self.analysis_table)

        self.analysis_status = QLabel("No evidence analyzed yet.")
        self.analysis_status.setObjectName("analysis_status")
        self.analysis_status.setWordWrap(True)

        result_layout.addWidget(self.analysis_status)
        self.content_layout.addWidget(self.analysis_result_panel)

        notice = QLabel(
            "🔎 Analysis is performed on the preserved evidence copy. "
            "The original source file is not opened for examination by this module."
        )
        notice.setObjectName("forensic_notice")
        notice.setWordWrap(True)
        self.content_layout.addWidget(notice)
        self.content_layout.addStretch()

        if self.analysis_evidence_combo.count() == 0:
            self.analysis_status.setText(
                "No digital evidence is available. Acquire evidence before starting file analysis."
            )

    def run_file_analysis(self):
        evidence_id = self.analysis_evidence_combo.currentData()
        if evidence_id is None:
            QMessageBox.warning(self, "No Evidence", "Please acquire digital evidence first.")
            return

        evidence = get_evidence_by_id(evidence_id)
        if not evidence:
            QMessageBox.warning(self, "Evidence Not Found", "The selected evidence could not be found.")
            return

        preserved_path = evidence["preserved_path"]
        if not preserved_path:
            QMessageBox.critical(self, "Preserved Copy Missing", "This evidence does not have a preserved copy.")
            return

        if not os.path.isfile(preserved_path):
            QMessageBox.critical(
                self,
                "Preserved Copy Missing",
                f"The preserved evidence file could not be found.\n\nExpected path:\n{preserved_path}"
            )
            return

        progress = QProgressDialog("Analyzing preserved evidence copy...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("File Analysis")
        progress.show()

        worker = AnalysisWorker(preserved_path, self)

        def on_finished(result):
            if getattr(self, "is_closing", False) or worker.isInterruptionRequested():
                return
            progress.close()

            properties = [
                ("Evidence ID", f"EV-{evidence_id:04d}"),
                ("Case", f"{evidence['case_number']} - {evidence['case_name']}"),
                ("File Name", result["file_name"]),
                ("Full Preserved Path", result["full_path"]),
                ("File Extension", result["extension"]),
                ("MIME Type", result["mime_type"]),
                (
                    "File Size",
                    f"{result['size_bytes']:,} bytes ({result['size_kb']:.2f} KB / {result['size_mb']:.2f} MB)"
                ),
                ("Created", result["created_time"]),
                ("Modified", result["modified_time"]),
                ("Accessed", result["accessed_time"]),
                ("SHA-256", result["sha256"]),
            ]

            self.analysis_table.setRowCount(len(properties))
            for row, (prop, val) in enumerate(properties):
                self.analysis_table.setItem(row, 0, QTableWidgetItem(prop))
                val_item = QTableWidgetItem(str(val))
                val_item.setToolTip(str(val))
                self.analysis_table.setItem(row, 1, val_item)

            stored_hash = evidence["sha256"] or ""
            integrity_status = "UNVERIFIED"

            if stored_hash:
                if result["sha256"].lower() == stored_hash.lower():
                    integrity_status = "MATCH"
                else:
                    integrity_status = "MISMATCH"

            # PERSIST ANALYSIS RECORD REGARDLESS OF HASH RESULT
            try:
                analysis_id = create_analysis(
                    evidence_id,
                    evidence["investigator"],
                    result["file_name"],
                    result["full_path"],
                    result["size_bytes"],
                    result["extension"],
                    result["mime_type"],
                    result["created_time"],
                    result["modified_time"],
                    result["accessed_time"],
                    result["sha256"],
                    integrity_status,
                    f"Preserved evidence examined ({integrity_status})."
                )

                if integrity_status == "MATCH":
                    self.analysis_status.setText(
                        f"● ANALYSIS COMPLETE — SHA-256 MATCHED THE STORED EVIDENCE HASH.\n"
                        f"Examination record #{analysis_id} saved to database."
                    )
                    self.analysis_status.setObjectName("integrity_success")
                elif integrity_status == "MISMATCH":
                    self.analysis_status.setText(
                        f"● SHA-256 INTEGRITY FAILURE — PRESERVED COPY SHA-256 DOES NOT MATCH STORED HASH!\n"
                        f"Examination failure record #{analysis_id} saved to database."
                    )
                    self.analysis_status.setObjectName("integrity_failed")
                else:
                    self.analysis_status.setText(
                        f"● ANALYSIS COMPLETE — No stored evidence SHA-256 available for comparison.\n"
                        f"Examination record #{analysis_id} saved to database."
                    )
                    self.analysis_status.setObjectName("analysis_status")

                self.analysis_status.style().unpolish(self.analysis_status)
                self.analysis_status.style().polish(self.analysis_status)
                self.statusBar().showMessage(f"File analysis completed and saved as record #{analysis_id}.")

            except Exception as db_err:
                QMessageBox.critical(
                    self,
                    "Analysis Persistence Failed",
                    f"Analysis completed but could not be saved to database.\n\nError: {db_err}"
                )

        def on_error(err_msg):
            if getattr(self, "is_closing", False) or worker.isInterruptionRequested():
                return
            progress.close()
            QMessageBox.critical(
                self,
                "File Analysis Failed",
                f"The evidence copy could not be analyzed.\n\nError: {err_msg}"
            )

        worker.finished_signal.connect(on_finished)
        worker.error_signal.connect(on_error)
        worker.finished_signal.connect(
            lambda result, active_worker=worker: self._untrack_worker(active_worker)
        )
        worker.error_signal.connect(
            lambda error, active_worker=worker: self._untrack_worker(active_worker)
        )
        self._track_worker(worker)
        worker.start()

    # =====================================================
    # NOTES & FINDINGS VIEW
    # =====================================================

    def show_notes(self):
        self.active_tab = "notes"
        self.clear_content()
        self.set_active_button(self.notes_button)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("Notes & Findings")
        title.setObjectName("page_title")

        description = QLabel(
            "Document observations, findings and investigation notes for each case"
        )
        description.setObjectName("page_description")
        description.setWordWrap(True)

        title_layout.addWidget(title)
        title_layout.addWidget(description)

        header.addLayout(title_layout)
        header.addStretch()

        add_button = QPushButton("+  Add Investigation Note")
        add_button.setObjectName("primary_button")
        add_button.clicked.connect(self.add_note)

        header.addWidget(add_button)
        self.content_layout.addLayout(header)

        selection_panel = QFrame()
        selection_panel.setObjectName("panel")

        selection_layout = QHBoxLayout(selection_panel)
        selection_layout.setContentsMargins(18, 18, 18, 18)

        selection_label = QLabel("Select Investigation Case:")
        selection_label.setObjectName("section_title")

        self.notes_case_combo = QComboBox()
        cases = get_cases()
        for case in cases:
            self.notes_case_combo.addItem(
                f"{case['case_id']} | {case['case_name']}",
                case["id"]
            )

        self.notes_case_combo.currentIndexChanged.connect(self.load_notes)

        refresh = QPushButton("Refresh")
        refresh.setObjectName("secondary_button")
        refresh.clicked.connect(self.refresh_notes_cases)

        selection_layout.addWidget(selection_label)
        selection_layout.addWidget(self.notes_case_combo, 1)
        selection_layout.addWidget(refresh)

        self.content_layout.addWidget(selection_panel)

        self.notes_table = QTableWidget()
        self.notes_table.setColumnCount(5)
        self.notes_table.setHorizontalHeaderLabels([
            "Note",
            "Case",
            "Created",
            "Type",
            "Action",
        ])
        self.notes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.notes_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.notes_table.setAlternatingRowColors(True)
        self.notes_table.verticalHeader().setVisible(False)
        self.notes_table.setWordWrap(True)

        header_view = self.notes_table.horizontalHeader()
        header_view.setMinimumSectionSize(60)
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.notes_table.setColumnWidth(1, 110)
        self.notes_table.setColumnWidth(2, 130)
        self.notes_table.setColumnWidth(3, 175)
        self.notes_table.setColumnWidth(4, 105)
        self.notes_table.verticalHeader().setDefaultSectionSize(46)

        self.content_layout.addWidget(self.notes_table)

        self.notes_status = QLabel("Select a case to view its investigation notes.")
        self.notes_status.setObjectName("notes_status")
        self.notes_status.setWordWrap(True)

        self.content_layout.addWidget(self.notes_status)

        notice = QLabel(
            "📝 Use Notes & Findings to document observations, suspicious indicators, hash results, and conclusions. "
            "These records can be referenced during final report preparation."
        )
        notice.setObjectName("forensic_notice")
        notice.setWordWrap(True)

        self.content_layout.addWidget(notice)
        self.content_layout.addStretch()
        self.load_notes()

    def refresh_notes_cases(self):
        current_case_id = (
            self.notes_case_combo.currentData()
            if hasattr(self, "notes_case_combo")
            else None
        )

        self.notes_case_combo.blockSignals(True)
        self.notes_case_combo.clear()

        for case in get_cases():
            self.notes_case_combo.addItem(
                f"{case['case_id']} | {case['case_name']}",
                case["id"]
            )

        if current_case_id is not None:
            index = self.notes_case_combo.findData(current_case_id)
            if index >= 0:
                self.notes_case_combo.setCurrentIndex(index)

        self.notes_case_combo.blockSignals(False)
        self.load_notes()

    def load_notes(self):
        if not hasattr(self, "notes_table"):
            return

        case_id = self.notes_case_combo.currentData()
        if case_id is None:
            self.notes_table.setRowCount(0)
            self.notes_status.setText("No investigation cases are available. Create a case first.")
            return

        records = get_notes(case_id)
        self.notes_table.setRowCount(len(records))

        for row, record in enumerate(records):
            note_text = record["note"] or ""
            note_item = QTableWidgetItem(note_text)
            note_item.setToolTip(note_text)

            self.notes_table.setItem(row, 0, note_item)
            self.notes_table.setItem(row, 1, QTableWidgetItem(record["case_number"]))
            self.notes_table.setItem(row, 2, QTableWidgetItem(record["created_at"]))
            self.notes_table.setItem(row, 3, QTableWidgetItem("Investigation Note / Finding"))

            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            delete_button = QPushButton("Delete")
            delete_button.setObjectName("danger_button")

            note_id = record["id"]
            delete_button.clicked.connect(
                lambda checked=False, item_id=note_id: self.delete_note(item_id)
            )

            action_layout.addWidget(delete_button)
            self.notes_table.setCellWidget(row, 4, action_widget)

        if records:
            self.notes_status.setText(f"{len(records)} investigation note(s) recorded for the selected case.")
        else:
            self.notes_status.setText("No notes or findings recorded for the selected case yet.")

        self.notes_status.style().unpolish(self.notes_status)
        self.notes_status.style().polish(self.notes_status)

    def add_note(self):
        case_id = self.notes_case_combo.currentData()
        if case_id is None:
            QMessageBox.warning(self, "No Case", "Please create and select an investigation case first.")
            return

        case = get_case(case_id)
        if not case:
            QMessageBox.warning(self, "Case Not Found", "The selected investigation case could not be found.")
            return

        dialog = NoteDialog(self, case)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        note_text = dialog.get_note()
        try:
            note_id = create_note(case_id, note_text)
            QMessageBox.information(
                self,
                "Note Saved",
                f"Investigation note #{note_id} was saved successfully.\n\n"
                f"The note is linked to the selected case and timestamped."
            )
            self.load_notes()

        except Exception as error:
            QMessageBox.critical(
                self,
                "Unable to Save Note",
                f"The investigation note could not be saved.\n\nError: {error}"
            )

    def delete_note(self, note_id):
        answer = QMessageBox.question(
            self,
            "Delete Investigation Note",
            "Are you sure you want to delete this investigation note?\n\n"
            "This removes the note from the case record.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            delete_note(note_id)
            self.load_notes()
            self.statusBar().showMessage("Investigation note deleted.")
        except Exception as error:
            QMessageBox.critical(
                self,
                "Unable to Delete Note",
                f"The investigation note could not be deleted.\n\nError: {error}"
            )

    # =====================================================
    # TIMELINE VIEW (WITH FILE ANALYSIS EVENTS)
    # =====================================================

    def show_timeline(self):
        self.active_tab = "timeline"
        self.clear_content()
        self.set_active_button(self.timeline_button)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("Investigation Timeline")
        title.setObjectName("page_title")

        description = QLabel(
            "View important events recorded during the lifecycle of a forensic investigation"
        )
        description.setObjectName("page_description")
        description.setWordWrap(True)

        title_layout.addWidget(title)
        title_layout.addWidget(description)

        header.addLayout(title_layout)
        header.addStretch()

        self.content_layout.addLayout(header)

        selection_panel = QFrame()
        selection_panel.setObjectName("panel")

        selection_layout = QHBoxLayout(selection_panel)
        selection_layout.setContentsMargins(18, 18, 18, 18)

        selection_label = QLabel("Select Investigation Case:")
        selection_label.setObjectName("section_title")

        self.timeline_case_combo = QComboBox()
        for case in get_cases():
            self.timeline_case_combo.addItem(
                f"{case['case_id']} | {case['case_name']}",
                case["id"]
            )

        self.timeline_case_combo.currentIndexChanged.connect(self.load_timeline)

        refresh = QPushButton("Refresh")
        refresh.setObjectName("secondary_button")
        refresh.clicked.connect(self.refresh_timeline_cases)
        replay_button = QPushButton("Replay Investigation")
        replay_button.setObjectName("primary_button")
        replay_button.clicked.connect(self.open_investigation_replay)

        selection_layout.addWidget(selection_label)
        selection_layout.addWidget(self.timeline_case_combo, 1)
        selection_layout.addWidget(refresh)
        selection_layout.addWidget(replay_button)

        self.content_layout.addWidget(selection_panel)

        self.timeline_table = QTableWidget()
        self.timeline_table.setColumnCount(5)
        self.timeline_table.setHorizontalHeaderLabels([
            "Date & Time",
            "Event",
            "Source",
            "Person",
            "Details",
        ])
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_table.verticalHeader().setVisible(False)
        self.timeline_table.setWordWrap(True)

        header_view = self.timeline_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.timeline_table.verticalHeader().setDefaultSectionSize(38)

        self.content_layout.addWidget(self.timeline_table)

        self.timeline_status = QLabel("Select a case to view its timeline.")
        self.timeline_status.setObjectName("timeline_status")
        self.timeline_status.setWordWrap(True)

        self.content_layout.addWidget(self.timeline_status)

        notice = QLabel(
            "Timeline combines case creation, evidence acquisition, custody events, "
            "file analysis examinations, and investigation notes into one chronological view."
        )
        notice.setObjectName("forensic_notice")
        notice.setWordWrap(True)

        self.content_layout.addWidget(notice)
        self.content_layout.addStretch()

        if self.timeline_case_combo.count() > 0:
            self.timeline_case_combo.setCurrentIndex(0)
        self.load_timeline()

    def refresh_timeline_cases(self):
        current_case_id = (
            self.timeline_case_combo.currentData()
            if hasattr(self, "timeline_case_combo")
            else None
        )

        self.timeline_case_combo.blockSignals(True)
        self.timeline_case_combo.clear()

        for case in get_cases():
            self.timeline_case_combo.addItem(
                f"{case['case_id']} | {case['case_name']}",
                case["id"]
            )

        if current_case_id is not None:
            index = self.timeline_case_combo.findData(current_case_id)
            if index >= 0:
                self.timeline_case_combo.setCurrentIndex(index)

        self.timeline_case_combo.blockSignals(False)
        self.load_timeline()

    def open_investigation_replay(self):
        """Open a read-only replay using the Timeline page's selected case."""
        case_db_id = self.timeline_case_combo.currentData()
        if case_db_id is None:
            QMessageBox.warning(
                self,
                "No Case Selected",
                "Select an investigation case before opening replay.",
            )
            return
        self.investigation_replay_dialog = InvestigationReplayDialog(
            case_db_id,
            theme=self.current_theme,
            parent=self,
        )
        self.investigation_replay_dialog.show()

    def load_timeline(self):
        if not hasattr(self, "timeline_table"):
            return

        case_db_id = self.timeline_case_combo.currentData()
        if case_db_id is None and self.timeline_case_combo.currentIndex() >= 0:
            case_db_id = self.timeline_case_combo.itemData(self.timeline_case_combo.currentIndex())

        if case_db_id is None:
            self.timeline_table.setRowCount(0)
            self.timeline_status.setText("No investigation cases are available. Create a case first.")
            return

        case = get_case(case_db_id)
        if not case:
            self.timeline_table.setRowCount(0)
            self.timeline_status.setText("The selected case could not be found.")
            return

        events = get_timeline_events(case_db_id)

        self.timeline_table.setRowCount(len(events))
        for row, event in enumerate(events):
            values = [
                event["timestamp"],
                event["event"],
                event["source"],
                event["person"],
                event["details"],
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.timeline_table.setItem(row, column, item)

        self.timeline_status.setText(
            f"{len(events)} timeline event(s) recorded for {case['case_id']}."
        )

    # =====================================================
    # REPORTS VIEW (WITH FILE ANALYSIS RESULTS)
    # =====================================================

    def show_reports(self):
        self.active_tab = "reports"
        self.clear_content()
        self.set_active_button(self.reports_button)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("Forensic Reports")
        title.setObjectName("page_title")

        description = QLabel(
            "Generate a structured investigation report from the recorded case, evidence, custody and findings data"
        )
        description.setObjectName("page_description")
        description.setWordWrap(True)

        title_layout.addWidget(title)
        title_layout.addWidget(description)

        header.addLayout(title_layout)
        header.addStretch()
        self.content_layout.addLayout(header)

        selection_panel = QFrame()
        selection_panel.setObjectName("panel")

        selection_layout = QHBoxLayout(selection_panel)
        selection_layout.setContentsMargins(18, 18, 18, 18)

        label = QLabel("Select Investigation Case:")
        label.setObjectName("section_title")

        self.report_case_combo = QComboBox()
        for case in get_cases():
            self.report_case_combo.addItem(
                f"{case['case_id']} | {case['case_name']}",
                case["id"]
            )

        refresh = QPushButton("Refresh")
        refresh.setObjectName("secondary_button")
        refresh.clicked.connect(self.refresh_report_cases)

        generate = QPushButton("Generate HTML Report")
        generate.setObjectName("primary_button")
        generate.clicked.connect(self.generate_report)

        summary_btn = QPushButton("View Executive Summary")
        summary_btn.setObjectName("secondary_button")
        summary_btn.clicked.connect(self.view_executive_summary_from_reports)

        selection_layout.addWidget(label)
        selection_layout.addWidget(self.report_case_combo, 1)
        selection_layout.addWidget(refresh)
        selection_layout.addWidget(summary_btn)
        selection_layout.addWidget(generate)

        self.content_layout.addWidget(selection_panel)


        summary_panel = QFrame()
        summary_panel.setObjectName("panel")

        summary_layout = QVBoxLayout(summary_panel)
        summary_layout.setContentsMargins(18, 18, 18, 18)

        summary_title = QLabel("Report Preview")
        summary_title.setObjectName("section_title")
        summary_layout.addWidget(summary_title)

        self.report_preview = QPlainTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setFont(QFont("Consolas", 10))
        self.report_preview.setPlaceholderText("Select a case to preview its investigation report...")

        summary_layout.addWidget(self.report_preview)
        self.content_layout.addWidget(summary_panel, 1)

        self.report_status = QLabel("Select a case to preview the report.")
        self.report_status.setObjectName("report_status")
        self.report_status.setWordWrap(True)

        self.content_layout.addWidget(self.report_status)

        notice = QLabel(
            "The generated report is saved as an HTML file that can be opened in a browser or submitted as part of the project demonstration."
        )
        notice.setObjectName("forensic_notice")
        notice.setWordWrap(True)

        self.content_layout.addWidget(notice)

        if self.report_case_combo.count() > 0:
            self.report_case_combo.setCurrentIndex(0)

        self.report_case_combo.currentIndexChanged.connect(self.preview_report)
        self.preview_report()

    def refresh_report_cases(self):
        current_case_id = (
            self.report_case_combo.currentData()
            if hasattr(self, "report_case_combo")
            else None
        )

        self.report_case_combo.blockSignals(True)
        self.report_case_combo.clear()

        for case in get_cases():
            self.report_case_combo.addItem(
                f"{case['case_id']} | {case['case_name']}",
                case["id"]
            )

        if current_case_id is not None:
            index = self.report_case_combo.findData(current_case_id)
            if index >= 0:
                self.report_case_combo.setCurrentIndex(index)

        self.report_case_combo.blockSignals(False)
        self.preview_report()

    def view_executive_summary_from_reports(self):
        case_id = self.report_case_combo.currentData()
        if case_id is None:
            QMessageBox.warning(self, "No Case Selected", "Please select an investigation case first.")
            return
        case = get_case(case_id)
        if not case:
            QMessageBox.warning(self, "Case Not Found", "The selected case record could not be found.")
            return
        self.show_executive_summary(case_id, case["case_id"])

    def build_report_text(self, case_db_id):

        case = get_case(case_db_id)
        if not case:
            return "", None

        evidence_records = get_evidence_for_case(case_db_id)
        analyses = get_analyses_for_case(case_db_id)
        notes = get_notes(case_db_id)
        correlation_findings = get_correlation_findings(case_db_id)
        timeline_events = get_timeline_events(case_db_id)

        health = get_case_health(case_db_id)
        stages = get_case_lifecycle_stage(case_db_id)

        lines = [
            "CYBERTRACE — DIGITAL FORENSICS INVESTIGATION REPORT",
            "=" * 62,
            "",
            f"Case ID: {case['case_id']}",
            f"Case Name: {case['case_name']}",
            f"Investigator: {case['investigator']}",
            f"Status: {case['status']}",
            f"Case Created: {case['created_at']}",
            "",
            "INVESTIGATION HEALTH & WORKFLOW INTEGRITY",
            "-" * 62,
            f"Health Score: {health['score']} / 100 ({health['label']})",
        ]

        for f in health.get("breakdown", []):
            lines.append(f"  • {f['factor']}: {f['pts']}/{f['max_pts']} pts ({f['status']}) - {f['details']}")

        if health.get("risk_flags"):
            lines.append("  [!] RISK WARNINGS:")
            for rf in health["risk_flags"]:
                lines.append(f"    ! {rf}")

        lines.extend([
            f"DISCLAIMER: {health['disclaimer']}",
            "",
            "8-STAGE INVESTIGATION LIFECYCLE",
            "-" * 62,
        ])

        for index, stage in enumerate(stages, 1):
            status_str = stage["status"].upper()
            state_str = "Completed" if stage["completed"] else "Pending"
            lines.append(f"  Stage {index}. {stage['stage']}: {status_str} ({state_str}) - {stage['details']}")

        lines.extend([
            "",
            "CASE DESCRIPTION",
            "-" * 62,
            case["description"] or "No case description recorded.",
            "",
            "EVIDENCE INVENTORY",
            "-" * 62,
        ])


        if evidence_records:
            for index, evidence in enumerate(evidence_records, 1):
                verification_status = get_current_evidence_status(evidence)
                lines.extend([
                    f"Evidence {index}: {evidence['evidence_name']}",
                    f"  Evidence ID: EV-{evidence['id']:04d}",
                    f"  Original Path: {evidence['original_path']}",
                    f"  Preserved Copy: {evidence['preserved_path']}",
                    f"  SHA-256 Hash: {evidence['sha256']}",
                    f"  Current Verification Status: {verification_status}",
                    f"  Acquisition Date: {evidence['acquired_at']}",
                    "",
                ])
        else:
            lines.append("No evidence records available.\n")

        lines.extend([
            "CHAIN OF CUSTODY",
            "-" * 62,
        ])

        if evidence_records:
            for evidence in evidence_records:
                lines.append(f"Evidence: {evidence['evidence_name']}")
                custody_events = get_custody_events(evidence["id"])
                if custody_events:
                    for event in custody_events:
                        lines.append(
                            f"  {event['timestamp']} | Action: {event['action']} | "
                            f"Person: {event['person']} | Remarks: {event['remarks'] or 'None'}"
                        )
                else:
                    lines.append("  No custody events recorded.")
                lines.append("")
        else:
            lines.append("No custody records available.\n")

        lines.extend([
            "FILE ANALYSIS & EXAMINATIONS",
            "-" * 62,
        ])

        if analyses:
            for index, analysis in enumerate(analyses, 1):
                lines.extend([
                    f"Examination {index}: {analysis['file_name']}",
                    f"  Analyzed At: {analysis['analyzed_at']}",
                    f"  Analyst: {analysis['analyst'] or 'Investigator'}",
                    f"  Preserved Path: {analysis['file_path']}",
                    f"  File Size: {analysis['file_size']:,} bytes",
                    f"  MIME Type: {analysis['mime_type']}",
                    f"  Examined SHA-256: {analysis['sha256']}",
                    f"  Integrity Status: {analysis['integrity_status']}",
                    "",
                ])
        else:
            lines.append("No file analysis records performed yet.\n")

        lines.extend([
            "CROSS-EVIDENCE CORRELATION ANALYSIS",
            "-" * 62,
            f"Evidence Items Analyzed: {len(evidence_records)}",
            f"Potential Relationships: {len(correlation_findings)}",
        ])
        if correlation_findings:
            for finding in correlation_findings:
                lines.extend([
                    f"  Evidence A: EV-{finding['evidence_a_id']:04d} | {finding['evidence_a_name']}",
                    f"  Evidence B: EV-{finding['evidence_b_id']:04d} | {finding['evidence_b_name']}",
                    f"  Relationship: {finding['relationship_type']}",
                    f"  Indicator: {finding['indicator_display'] or 'N/A'}",
                    f"  Strength: {finding['strength_label']}",
                    f"  Explanation: {finding['explanation']}",
                    f"  Detected: {finding['detected_at']}",
                    "",
                ])
        else:
            lines.append("No potential cross-evidence relationships recorded for this case.")
        if any(get_current_evidence_status(evidence) != "VERIFIED" for evidence in evidence_records):
            lines.append("WARNING: Correlation results may be incomplete because one or more current preserved evidence copies are missing, changed, or unverified.")
        lines.append(
            "DISCLAIMER: Correlation findings are deterministic indicators of potential relationships between evidence items in this case. They do not establish common origin, criminal activity, user identity, intent, or legal significance. Investigator review is required."
        )
        lines.append("")

        lines.extend([
            "INVESTIGATION TIMELINE",
            "-" * 62,
        ])
        if timeline_events:
            for event in timeline_events:
                lines.append(
                    f"  {event['timestamp']} | Event: {event['event']} | "
                    f"Source: {event['source']} | Person: {event['person']} | "
                    f"Details: {event['details']}"
                )
        else:
            lines.append("No investigation timeline events recorded for this case.")
        lines.extend([
            "",
            "INVESTIGATION NOTES & FINDINGS",
            "-" * 62,
        ])

        if notes:
            for index, note in enumerate(notes, 1):
                lines.append(f"{index}. {note['created_at']} | {note['note']}")
        else:
            lines.append("No investigation notes or findings recorded.")

        lines.extend([
            "",
            "SUMMARY & CONCLUSION",
            "-" * 62,
        ])

        if evidence_records:
            lines.append("RECORDED FACTS: Current preserved-evidence verification statuses are listed above.")
        else:
            lines.append("RECORDED FACTS: No evidence items were recorded; preservation and SHA-256 verification were not performed.")

        custody_count = sum(
            len(get_custody_events(evidence["id"]))
            for evidence in evidence_records
        )
        if custody_count:
            lines.append(f"RECORDED CUSTODY: {custody_count} custody event(s) are recorded.")
        else:
            lines.append("RECORDED CUSTODY: No custody events are recorded.")

        lines.extend([
            "INVESTIGATOR FINDINGS: Refer to the documented notes and examination records above.",
            "",
            "Generated by CyberTrace — Digital Forensics Investigation System",
            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ])

        return "\n".join(lines), case

    def preview_report(self):
        if not hasattr(self, "report_preview"):
            return

        case_db_id = self.report_case_combo.currentData()
        if case_db_id is None and self.report_case_combo.currentIndex() >= 0:
            case_db_id = self.report_case_combo.itemData(self.report_case_combo.currentIndex())

        if case_db_id is None:
            self.report_preview.clear()
            self.report_status.setText("No investigation cases are available. Create a case first.")
            return

        report_text, case = self.build_report_text(case_db_id)
        self.report_preview.setPlainText(report_text)

        if case:
            self.report_status.setText(f"Report preview ready for {case['case_id']}.")

    def generate_report(self):
        case_db_id = self.report_case_combo.currentData()
        if case_db_id is None:
            QMessageBox.warning(self, "No Case Selected", "Please select an investigation case first.")
            return

        html, case = build_html_report(case_db_id)
        if not case:
            QMessageBox.warning(self, "Case Not Found", "The selected investigation case could not be found.")
            return

        default_name = f"CyberTrace_{case['case_id']}_Forensic_Report.html"
        reports_dir = os.path.join(get_app_dir(), "reports")
        os.makedirs(reports_dir, exist_ok=True)

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Forensic Investigation Report",
            os.path.join(reports_dir, default_name),
            "HTML Files (*.html)"
        )

        if not file_path:
            return

        report_dir = os.path.dirname(file_path)
        if report_dir:
            os.makedirs(report_dir, exist_ok=True)

        try:
            with open(file_path, "w", encoding="utf-8") as report_file:
                report_file.write(html)

            self.report_status.setText(f"Forensic report generated successfully: {file_path}")
            self.statusBar().showMessage("Forensic report generated.")

            QMessageBox.information(
                self,
                "Report Generated",
                f"The forensic investigation report was saved successfully.\n\n{file_path}"
            )

        except Exception as error:
            QMessageBox.critical(
                self,
                "Report Generation Failed",
                f"The report could not be generated.\n\nError: {error}"
            )

    # =====================================================
    # CASE OPERATIONS
    # =====================================================

    def new_case(self):
        dialog = CaseDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()

            try:
                create_case(
                    data["case_id"],
                    data["case_name"],
                    data["investigator"],
                    data["description"],
                    data["status"],
                )

                QMessageBox.information(
                    self,
                    "Case Created",
                    f"Investigation case {data['case_id']} created successfully."
                )
                self.show_cases()

            except sqlite3.IntegrityError as error:
                err_text = str(error)
                if "UNIQUE constraint failed" in err_text or "cases.case_id" in err_text:
                    QMessageBox.warning(
                        self,
                        "Duplicate Case ID",
                        f"Case ID {data['case_id']} already exists.\n\nPlease use a different Case ID."
                    )
                else:
                    QMessageBox.critical(
                        self,
                        "Unable to Create Case",
                        f"Database Integrity Error: {error}"
                    )
            except Exception as error:
                QMessageBox.critical(
                    self,
                    "Unable to Create Case",
                    f"The case could not be created.\n\nError: {error}"
                )

    def edit_case(self, database_id):
        case = get_case(database_id)
        if not case:
            QMessageBox.warning(self, "Case Not Found", "The selected case could not be found.")
            return

        dialog = CaseDialog(self, case)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_data()

            try:
                update_case(
                    database_id,
                    data["case_name"],
                    data["investigator"],
                    data["description"],
                    data["status"],
                )

                QMessageBox.information(
                    self,
                    "Case Updated",
                    "Investigation case updated successfully."
                )
                self.show_cases()

            except Exception as error:
                QMessageBox.critical(
                    self,
                    "Unable to Update Case",
                    f"The case could not be updated.\n\nError: {error}"
                )

    def delete_case(self, database_id):
        case = get_case(database_id)
        if not case:
            return

        if get_evidence_for_case(database_id):
            QMessageBox.warning(
                self,
                "Case Deletion Blocked",
                "This case contains preserved digital evidence and cannot be deleted "
                "through the normal workflow.\n\n"
                "The case and its evidence records were left unchanged to protect "
                "evidence provenance and prevent orphaned preserved copies."
            )
            return

        answer = QMessageBox.question(
            self,
            "Delete Investigation Case",
            f"Are you sure you want to delete\n\n"
            f"{case['case_id']} - {case['case_name']}?\n\n"
            f"Related database records will also be removed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            delete_case(database_id)
            QMessageBox.information(self, "Case Deleted", "Investigation case deleted successfully.")
            self.show_cases()
        except sqlite3.IntegrityError:
            QMessageBox.warning(
                self,
                "Case Deletion Blocked",
                "The case contains preserved digital evidence and was not deleted.\n\n"
                "The case and its evidence records remain unchanged."
            )
        except Exception as error:
            QMessageBox.critical(
                self,
                "Unable to Delete Case",
                f"The case could not be deleted.\n\nError: {error}"
            )



# =========================================================
# APPLICATION STYLES (DARK + LIGHT THEME SUPPORT)
# =========================================================

def get_theme_stylesheet(theme="dark"):
    if theme == "light":
        return """
        QMainWindow {
            background-color: #f8fafc;
        }

        QWidget {
            font-family: "Segoe UI", "Inter", -apple-system, sans-serif;
            color: #0f172a;
        }

        #sidebar {
            background-color: #ffffff;
            border-right: 1px solid #e2e8f0;
        }

        #logo {
            font-size: 22px;
            font-weight: 800;
            color: #0284c7;
            letter-spacing: 1.5px;
        }

        #subtitle {
            color: #64748b;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 2px;
        }

        #version {
            color: #94a3b8;
            font-size: 11px;
        }

        #content {
            background-color: #f8fafc;
        }

        #page_title {
            font-size: 24px;
            font-weight: 700;
            color: #0f172a;
        }

        #page_description {
            color: #64748b;
            font-size: 13px;
        }

        #status {
            color: #0284c7;
            font-size: 12px;
            font-weight: 700;
            padding: 6px 14px;
            background-color: #e0f2fe;
            border: 1px solid #0284c7;
            border-radius: 6px;
        }

        #nav_button,
        #nav_button_active {
            text-align: left;
            padding-left: 18px;
            border-radius: 6px;
            border: none;
            font-size: 13px;
            font-weight: 500;
        }

        #nav_button {
            background-color: transparent;
            color: #64748b;
        }

        #nav_button:hover {
            background-color: #f1f5f9;
            color: #0284c7;
        }

        #nav_button_active {
            background-color: #e0f2fe;
            color: #0284c7;
            font-weight: 700;
            border-left: 3px solid #0284c7;
        }

        #theme_toggle_button {
            background-color: #f1f5f9;
            color: #0f172a;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 12px;
        }

        #theme_toggle_button:hover {
            background-color: #e2e8f0;
            border-color: #0284c7;
            color: #0284c7;
        }

        #stat_card {
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-top: 3px solid #0284c7;
            border-radius: 8px;
            min-height: 120px;
        }

        #card_title {
            color: #64748b;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        #card_value {
            color: #0284c7;
            font-size: 32px;
            font-weight: 700;
        }

        #card_description {
            color: #94a3b8;
            font-size: 11px;
        }

        #panel {
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
        }

        #section_title {
            color: #0f172a;
            font-size: 16px;
            font-weight: 700;
        }

        #section_description {
            color: #64748b;
            font-size: 12px;
        }

        #workflow {
            color: #0284c7;
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 18px;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        #primary_button,
        #secondary_button,
        #small_button,
        #danger_button {
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
        }

        #primary_button {
            min-height: 38px;
            padding: 0 18px;
            background-color: #0284c7;
            color: white;
            border: 1px solid #0369a1;
        }

        #primary_button:hover {
            background-color: #0369a1;
        }

        #secondary_button {
            min-height: 38px;
            padding: 0 18px;
            background-color: #f1f5f9;
            color: #0f172a;
            border: 1px solid #cbd5e1;
        }

        #secondary_button:hover {
            background-color: #e2e8f0;
            border-color: #0284c7;
            color: #0284c7;
        }

        #small_button {
            min-width: 50px;
            min-height: 28px;
            padding: 3px 10px;
            background-color: #f1f5f9;
            color: #0f172a;
            border: 1px solid #cbd5e1;
        }

        #small_button:hover {
            border-color: #0284c7;
            color: #0284c7;
            background-color: #e0f2fe;
        }

        #danger_button {
            min-width: 55px;
            min-height: 28px;
            padding: 3px 10px;
            background-color: #fef2f2;
            color: #ef4444;
            border: 1px solid #fca5a5;
        }

        #danger_button:hover {
            background-color: #fee2e2;
            color: #b91c1c;
        }

        QLineEdit,
        QPlainTextEdit,
        QComboBox {
            background-color: #ffffff;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 8px 12px;
            color: #0f172a;
            selection-background-color: #e0f2fe;
            selection-color: #0284c7;
        }

        QLineEdit:focus,
        QPlainTextEdit:focus,
        QComboBox:focus {
            border-color: #0284c7;
        }

        QComboBox QAbstractItemView {
            background-color: #ffffff;
            color: #0f172a;
            selection-background-color: #e0f2fe;
            selection-color: #0284c7;
            border: 1px solid #cbd5e1;
        }

        QTableWidget {
            background-color: #ffffff;
            alternate-background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            gridline-color: #e2e8f0;
            color: #0f172a;
            selection-background-color: #e0f2fe;
            selection-color: #0f172a;
        }

        QHeaderView::section {
            background-color: #f1f5f9;
            color: #475569;
            border: none;
            border-bottom: 1px solid #cbd5e1;
            padding: 10px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }

        QTableWidget::item {
            padding: 8px;
        }

        QTableWidget::item:hover {
            background-color: #f1f5f9;
        }

        #analysis_status,
        #timeline_status,
        #report_status,
        #custody_status,
        #notes_status {
            padding: 12px 16px;
            border-radius: 6px;
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            color: #64748b;
            font-size: 12px;
        }

        #integrity_success {
            color: #047857;
            background-color: #ecfdf5;
            border: 1px solid #a7f3d0;
            font-weight: 600;
        }

        #integrity_failed {
            color: #b91c1c;
            background-color: #fef2f2;
            border: 1px solid #fca5a5;
            font-weight: 600;
        }

        QDialog {
            background-color: #ffffff;
        }

        #dialog_title {
            font-size: 20px;
            font-weight: 700;
            color: #0f172a;
        }

        #dialog_description {
            color: #64748b;
            font-size: 12px;
        }

        #evidence_info {
            color: #475569;
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 12px;
        }

        #forensic_notice {
            color: #0284c7;
            background-color: #e0f2fe;
            border: 1px solid #7dd3fc;
            border-radius: 6px;
            padding: 12px 16px;
            font-size: 11px;
            line-height: 1.4;
        }

        QDialog QLabel {
            color: #0f172a;
        }

        QDialogButtonBox QPushButton {
            min-width: 90px;
            min-height: 35px;
            border-radius: 6px;
            background-color: #f1f5f9;
            color: #0f172a;
            border: 1px solid #cbd5e1;
        }

        QDialogButtonBox QPushButton:hover {
            border-color: #0284c7;
            color: #0284c7;
        }

        QStatusBar {
            background-color: #ffffff;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
        }

        QScrollBar:vertical {
            background-color: #f8fafc;
            width: 12px;
            margin: 0px;
        }

        QScrollBar::handle:vertical {
            background-color: #cbd5e1;
            min-height: 20px;
            border-radius: 6px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #94a3b8;
        }

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }

        QScrollBar:horizontal {
            background-color: #f8fafc;
            height: 12px;
            margin: 0px;
        }

        QScrollBar::handle:horizontal {
            background-color: #cbd5e1;
            min-width: 20px;
            border-radius: 6px;
        }

        QScrollBar::handle:horizontal:hover {
            background-color: #94a3b8;
        }

        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        """
    else:
        return """
        QMainWindow {
            background-color: #080c14;
        }

        QWidget {
            font-family: "Segoe UI", "Inter", -apple-system, sans-serif;
            color: #e2e8f0;
        }

        #sidebar {
            background-color: #0e1420;
            border-right: 1px solid #1e293b;
        }

        #logo {
            font-size: 22px;
            font-weight: 800;
            color: #38bdf8;
            letter-spacing: 1.5px;
        }

        #subtitle {
            color: #94a3b8;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 2px;
        }

        #version {
            color: #64748b;
            font-size: 11px;
        }

        #content {
            background-color: #080c14;
        }

        #page_title {
            font-size: 24px;
            font-weight: 700;
            color: #f8fafc;
        }

        #page_description {
            color: #94a3b8;
            font-size: 13px;
        }

        #status {
            color: #38bdf8;
            font-size: 12px;
            font-weight: 700;
            padding: 6px 14px;
            background-color: #0f2b48;
            border: 1px solid #0ea5e9;
            border-radius: 6px;
        }

        #nav_button,
        #nav_button_active {
            text-align: left;
            padding-left: 18px;
            border-radius: 6px;
            border: none;
            font-size: 13px;
            font-weight: 500;
        }

        #nav_button {
            background-color: transparent;
            color: #94a3b8;
        }

        #nav_button:hover {
            background-color: #162032;
            color: #f8fafc;
        }

        #nav_button_active {
            background-color: #0f2b48;
            color: #38bdf8;
            font-weight: 700;
            border-left: 3px solid #0ea5e9;
        }

        #theme_toggle_button {
            background-color: #162032;
            color: #e2e8f0;
            border: 1px solid #1e293b;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 12px;
        }

        #theme_toggle_button:hover {
            background-color: #1e293b;
            border-color: #0ea5e9;
            color: #38bdf8;
        }

        #stat_card {
            background-color: #111827;
            border: 1px solid #1e293b;
            border-top: 3px solid #0ea5e9;
            border-radius: 8px;
            min-height: 120px;
        }

        #card_title {
            color: #94a3b8;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        #card_value {
            color: #38bdf8;
            font-size: 32px;
            font-weight: 700;
        }

        #card_description {
            color: #64748b;
            font-size: 11px;
        }

        #panel {
            background-color: #111827;
            border: 1px solid #1e293b;
            border-radius: 8px;
        }

        #section_title {
            color: #f8fafc;
            font-size: 16px;
            font-weight: 700;
        }

        #section_description {
            color: #94a3b8;
            font-size: 12px;
        }

        #workflow {
            color: #38bdf8;
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 18px;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        #primary_button,
        #secondary_button,
        #small_button,
        #danger_button {
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
        }

        #primary_button {
            min-height: 38px;
            padding: 0 18px;
            background-color: #0ea5e9;
            color: white;
            border: 1px solid #0284c7;
        }

        #primary_button:hover {
            background-color: #0284c7;
        }

        #secondary_button {
            min-height: 38px;
            padding: 0 18px;
            background-color: #1e293b;
            color: #cbd5e1;
            border: 1px solid #334155;
        }

        #secondary_button:hover {
            background-color: #334155;
            border-color: #38bdf8;
            color: #ffffff;
        }

        #small_button {
            min-width: 50px;
            min-height: 28px;
            padding: 3px 10px;
            background-color: #1e293b;
            color: #cbd5e1;
            border: 1px solid #334155;
        }

        #small_button:hover {
            border-color: #38bdf8;
            color: #38bdf8;
            background-color: #0f2b48;
        }

        #danger_button {
            min-width: 55px;
            min-height: 28px;
            padding: 3px 10px;
            background-color: #451a1a;
            color: #f87171;
            border: 1px solid #7f1d1d;
        }

        #danger_button:hover {
            background-color: #7f1d1d;
            color: #ffffff;
        }

        QLineEdit,
        QPlainTextEdit,
        QComboBox {
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 8px 12px;
            color: #f8fafc;
            selection-background-color: #0ea5e9;
        }

        QLineEdit:focus,
        QPlainTextEdit:focus,
        QComboBox:focus {
            border-color: #38bdf8;
        }

        QComboBox QAbstractItemView {
            background-color: #111827;
            color: #f8fafc;
            selection-background-color: #0ea5e9;
            border: 1px solid #1e293b;
        }

        QTableWidget {
            background-color: #111827;
            alternate-background-color: #0b0f19;
            border: 1px solid #1e293b;
            border-radius: 8px;
            gridline-color: #1e293b;
            color: #e2e8f0;
            selection-background-color: #1e293b;
            selection-color: #f8fafc;
        }

        QHeaderView::section {
            background-color: #1e293b;
            color: #cbd5e1;
            border: none;
            border-bottom: 1px solid #334155;
            padding: 10px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }

        QTableWidget::item {
            padding: 8px;
        }

        QTableWidget::item:hover {
            background-color: #162032;
        }

        #analysis_status,
        #timeline_status,
        #report_status,
        #custody_status,
        #notes_status {
            padding: 12px 16px;
            border-radius: 6px;
            background-color: #111827;
            border: 1px solid #1e293b;
            color: #94a3b8;
            font-size: 12px;
        }

        #integrity_success {
            color: #34d399;
            background-color: #064e3b;
            border: 1px solid #059669;
            font-weight: 600;
        }

        #integrity_failed {
            color: #f87171;
            background-color: #451a1a;
            border: 1px solid #7f1d1d;
            font-weight: 600;
        }

        QDialog {
            background-color: #111827;
        }

        #dialog_title {
            font-size: 20px;
            font-weight: 700;
            color: #f8fafc;
        }

        #dialog_description {
            color: #94a3b8;
            font-size: 12px;
        }

        #evidence_info {
            color: #94a3b8;
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 12px;
        }

        #forensic_notice {
            color: #38bdf8;
            background-color: #0f2b48;
            border: 1px solid #0ea5e9;
            border-radius: 6px;
            padding: 12px 16px;
            font-size: 11px;
            line-height: 1.4;
        }

        QDialog QLabel {
            color: #cbd5e1;
        }

        QDialogButtonBox QPushButton {
            min-width: 90px;
            min-height: 35px;
            border-radius: 6px;
            background-color: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
        }

        QDialogButtonBox QPushButton:hover {
            border-color: #38bdf8;
            color: #38bdf8;
        }

        QStatusBar {
            background-color: #0e1420;
            color: #94a3b8;
            border-top: 1px solid #1e293b;
        }

        QScrollBar:vertical {
            background-color: #080c14;
            width: 12px;
            margin: 0px;
        }

        QScrollBar::handle:vertical {
            background-color: #1e293b;
            min-height: 20px;
            border-radius: 6px;
        }

        QScrollBar::handle:vertical:hover {
            background-color: #334155;
        }

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }

        QScrollBar:horizontal {
            background-color: #080c14;
            height: 12px;
            margin: 0px;
        }

        QScrollBar::handle:horizontal {
            background-color: #1e293b;
            min-width: 20px;
            border-radius: 6px;
        }

        QScrollBar::handle:horizontal:hover {
            background-color: #334155;
        }

        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        """


# =========================================================
# APPLICATION ENTRY POINT
# =========================================================

def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("CyberTrace.DigitalForensics.App")
        except Exception:
            pass

    initialize_database()
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    settings = QSettings("CyberTrace", "CyberTraceApp")
    initial_theme = settings.value("theme", "dark")
    app.setStyleSheet(get_theme_stylesheet(initial_theme))

    window = CyberTraceWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()