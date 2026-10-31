import os
import sys
import tempfile
import unittest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from database.db import create_case, create_evidence, get_cases, initialize_database
from main import CyberTraceWindow, build_html_report


class TestGuiStartup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="cybertrace_gui_test_")
        cls.db_path = os.path.join(cls.temp_dir, "data", "cybertrace.db")
        os.makedirs(os.path.dirname(cls.db_path), exist_ok=True)

        import database.db
        database.db.DATABASE_PATH = cls.db_path
        initialize_database()

        if not QApplication.instance():
            cls.app = QApplication(sys.argv)
        else:
            cls.app = QApplication.instance()

    def test_cybertrace_window_instantiation_and_methods(self):
        window = CyberTraceWindow()
        self.assertIsNotNone(window)

        # Verify that critical navigation/case methods exist and are callable on CyberTraceWindow
        expected_methods = [
            "new_case",
            "edit_case",
            "delete_case",
            "build_report_text",
            "preview_report",
            "generate_report",
            "show_dashboard",
            "show_cases",
            "show_evidence",
            "show_timeline",
            "open_investigation_replay",
            "show_reports",
        ]

        for method_name in expected_methods:
            self.assertTrue(
                hasattr(window, method_name),
                f"CyberTraceWindow is missing method '{method_name}'"
            )
            self.assertTrue(
                callable(getattr(window, method_name)),
                f"Attribute '{method_name}' on CyberTraceWindow is not callable"
            )

        window.close()

    def test_standalone_build_html_report_callable(self):
        self.assertTrue(callable(build_html_report))

    def test_evidence_selection_resolves_correlation_case(self):
        create_case(
            "CT-2026-002",
            "Correlation Selection Test",
            "Synthetic Investigator",
            "Synthetic regression fixture",
            "Open",
        )
        case = get_cases()[0]
        create_evidence(
            case["id"],
            "incident_alpha.txt",
            "synthetic-original",
            "missing-preserved-copy",
            "synthetic-hash",
            "2026-09-09 20:00:00",
        )

        window = CyberTraceWindow()
        window.show_evidence()
        window.show()
        window.evidence_table.selectRow(0)
        self.app.processEvents()

        self.assertEqual(window.current_correlation_case_id, case["id"])
        self.assertEqual(
            window.correlation_case_context.text(),
            "Case: CT-2026-002 | Correlation Selection Test",
        )
        self.assertTrue(window.open_graph_button.isVisible())
        self.assertTrue(window.open_graph_button.isEnabled())

        window.open_relationship_graph()
        self.app.processEvents()
        self.assertEqual(
            window.relationship_graph_dialog.case_id,
            window.current_correlation_case_id,
        )
        self.assertEqual(
            window.relationship_graph_dialog.findings,
            [],
        )
        window.relationship_graph_dialog.close()
        window.close()


if __name__ == "__main__":
    unittest.main()
