import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime


def get_app_dir():
    """Return the root application directory for writable data."""
    if getattr(sys, "frozen", False):
        local_appdata = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        return os.path.join(local_appdata, "CyberTrace")
    return os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )


DATA_DIR = os.path.join(
    get_app_dir(),
    "data"
)

DATABASE_PATH = os.path.join(
    DATA_DIR,
    "cybertrace.db"
)


def ensure_persistent_db_migration():
    """Safely migrate development database to persistent APPDATA directory on first EXE launch."""
    if not getattr(sys, "frozen", False):
        return

    persistent_db_path = DATABASE_PATH

    # STRICT GUARD: If the persistent DB file already exists, NEVER overwrite or re-migrate.
    if os.path.exists(persistent_db_path):
        return

    dev_db_path = os.path.join("D:\\CyberTrace", "data", "cybertrace.db")
    if not os.path.exists(dev_db_path):
        return

    temporary_db_path = None
    connection = None
    staging_evidence_dir = None
    persistent_evidence_dir = os.path.join(get_app_dir(), "evidence")
    promoted_evidence_files = []
    created_evidence_dirs = []
    renamed_evidence_dir = False
    persistent_db_promoted = False
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        temporary_fd, temporary_db_path = tempfile.mkstemp(
            prefix="cybertrace_migration_",
            suffix=".db",
            dir=DATA_DIR,
        )
        os.close(temporary_fd)
        shutil.copy2(dev_db_path, temporary_db_path)

        dev_evidence_dir = os.path.join("D:\\CyberTrace", "evidence")
        if os.path.exists(dev_evidence_dir):
            os.makedirs(get_app_dir(), exist_ok=True)
            staging_evidence_dir = tempfile.mkdtemp(
                prefix=".cybertrace_evidence_migration_",
                dir=get_app_dir(),
            )
            for root_dir, dirs, files in os.walk(dev_evidence_dir):
                rel_path = os.path.relpath(root_dir, dev_evidence_dir)
                target_dir = os.path.join(staging_evidence_dir, rel_path) if rel_path != "." else staging_evidence_dir
                os.makedirs(target_dir, exist_ok=True)
                for file_name in files:
                    src_file = os.path.join(root_dir, file_name)
                    dst_file = os.path.join(target_dir, file_name)
                    shutil.copy2(src_file, dst_file)

        # Update evidence and analysis paths to point to persistent APPDATA directory
        connection = sqlite3.connect(temporary_db_path)
        cursor = connection.cursor()

        cursor.execute("SELECT id, preserved_path FROM evidence WHERE preserved_path IS NOT NULL")
        for ev_id, path in cursor.fetchall():
            if path and "D:\\CyberTrace\\evidence" in path:
                rel = os.path.relpath(path, "D:\\CyberTrace\\evidence")
                new_path = os.path.join(persistent_evidence_dir, rel)
                cursor.execute("UPDATE evidence SET preserved_path = ? WHERE id = ?", (new_path, ev_id))

        cursor.execute("SELECT id, file_path FROM analyses WHERE file_path IS NOT NULL")
        for an_id, path in cursor.fetchall():
            if path and "D:\\CyberTrace\\evidence" in path:
                rel = os.path.relpath(path, "D:\\CyberTrace\\evidence")
                new_path = os.path.join(persistent_evidence_dir, rel)
                cursor.execute("UPDATE analyses SET file_path = ? WHERE id = ?", (new_path, an_id))

        connection.commit()

        cursor.execute("PRAGMA integrity_check")
        row = cursor.fetchone()
        if not row or row[0] != "ok":
            raise sqlite3.DatabaseError("Migrated database failed integrity check.")

        connection.close()
        connection = None

        if staging_evidence_dir:
            if not os.path.exists(persistent_evidence_dir):
                os.rename(staging_evidence_dir, persistent_evidence_dir)
                staging_evidence_dir = None
                renamed_evidence_dir = True
            else:
                for root_dir, dirs, files in os.walk(staging_evidence_dir):
                    rel_path = os.path.relpath(root_dir, staging_evidence_dir)
                    target_dir = os.path.join(persistent_evidence_dir, rel_path) if rel_path != "." else persistent_evidence_dir
                    if not os.path.exists(target_dir):
                        os.makedirs(target_dir, exist_ok=True)
                        created_evidence_dirs.append(target_dir)
                    for file_name in files:
                        target_file = os.path.join(target_dir, file_name)
                        if os.path.exists(target_file):
                            raise FileExistsError(
                                f"Persistent evidence file already exists: {target_file}"
                            )
                        shutil.copy2(os.path.join(root_dir, file_name), target_file)
                        promoted_evidence_files.append(target_file)

        # os.rename does not replace an existing destination on Windows.
        # Preserve a database created concurrently instead of overwriting it.
        if os.path.exists(persistent_db_path):
            return
        os.rename(temporary_db_path, persistent_db_path)
        temporary_db_path = None
        persistent_db_promoted = True
    except Exception as err:
        raise RuntimeError(f"Persistent database migration failed: {err}") from err
    finally:
        if connection is not None:
            connection.close()
        if temporary_db_path and os.path.exists(temporary_db_path):
            os.remove(temporary_db_path)
        if staging_evidence_dir and os.path.exists(staging_evidence_dir):
            shutil.rmtree(staging_evidence_dir)
        if not persistent_db_promoted:
            if renamed_evidence_dir and os.path.exists(persistent_evidence_dir):
                shutil.rmtree(persistent_evidence_dir)
            else:
                for file_path in reversed(promoted_evidence_files):
                    if os.path.exists(file_path):
                        os.remove(file_path)
                for directory in reversed(created_evidence_dirs):
                    try:
                        os.rmdir(directory)
                    except OSError:
                        pass


def get_connection():
    """Create and return a SQLite database connection with FK enabled."""
    os.makedirs(
        DATA_DIR,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def initialize_database():
    """Create CyberTrace database tables and run safe migrations."""
    ensure_persistent_db_migration()
    connection = get_connection()
    cursor = connection.cursor()

    try:
        # =====================================================
        # CASES
        # =====================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                case_name TEXT NOT NULL,
                investigator TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL
            )
            """
        )

        # =====================================================
        # EVIDENCE
        # =====================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                evidence_name TEXT NOT NULL,
                original_path TEXT,
                preserved_path TEXT,
                sha256 TEXT,
                acquired_at TEXT,
                FOREIGN KEY (case_id)
                    REFERENCES cases(id)
                    ON DELETE CASCADE
            )
            """
        )

        # =====================================================
        # CHAIN OF CUSTODY
        # =====================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                person TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                remarks TEXT,
                previous_hash TEXT,
                event_hash TEXT,
                FOREIGN KEY (evidence_id)
                    REFERENCES evidence(id)
                    ON DELETE CASCADE
            )
            """
        )

        # =====================================================
        # NOTES
        # =====================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id)
                    REFERENCES cases(id)
                    ON DELETE CASCADE
            )
            """
        )

        # =====================================================
        # FILE EXAMINATIONS / ANALYSES
        # =====================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                analyzed_at TEXT NOT NULL,
                analyst TEXT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                extension TEXT,
                mime_type TEXT,
                created_time TEXT,
                modified_time TEXT,
                accessed_time TEXT,
                sha256 TEXT NOT NULL,
                integrity_status TEXT NOT NULL,
                notes TEXT,
                FOREIGN KEY (evidence_id)
                    REFERENCES evidence(id)
                    ON DELETE CASCADE
            )
            """
        )

        # =====================================================
        # CROSS-EVIDENCE CORRELATION FINDINGS
        # =====================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS correlation_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                evidence_a_id INTEGER NOT NULL,
                evidence_b_id INTEGER NOT NULL,
                relationship_type TEXT NOT NULL,
                indicator_type TEXT,
                indicator_fingerprint TEXT,
                indicator_display TEXT,
                strength_score INTEGER NOT NULL,
                strength_label TEXT NOT NULL,
                explanation TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
                FOREIGN KEY (evidence_a_id) REFERENCES evidence(id) ON DELETE CASCADE,
                FOREIGN KEY (evidence_b_id) REFERENCES evidence(id) ON DELETE CASCADE,
                CHECK (evidence_a_id < evidence_b_id),
                CHECK (evidence_a_id != evidence_b_id),
                UNIQUE (
                    case_id,
                    evidence_a_id,
                    evidence_b_id,
                    relationship_type,
                    indicator_fingerprint
                )
            )
            """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_correlation_findings_case_active "
            "ON correlation_findings(case_id, active)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_correlation_findings_evidence_a "
            "ON correlation_findings(evidence_a_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_correlation_findings_evidence_b "
            "ON correlation_findings(evidence_b_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_correlation_findings_detected_at "
            "ON correlation_findings(detected_at)"
        )

        # =====================================================
        # DATABASE MIGRATIONS FOR EXISTING DATABASES
        # =====================================================
        cursor.execute("PRAGMA table_info(custody)")
        custody_columns = [row["name"] for row in cursor.fetchall()]

        if "previous_hash" not in custody_columns:
            cursor.execute(
                "ALTER TABLE custody ADD COLUMN previous_hash TEXT"
            )

        if "event_hash" not in custody_columns:
            cursor.execute(
                "ALTER TABLE custody ADD COLUMN event_hash TEXT"
            )

        custody_foreign_keys = cursor.execute(
            "PRAGMA foreign_key_list(custody)"
        ).fetchall()

        if not custody_foreign_keys:
            cursor.execute(
                """
                SELECT custody.id
                FROM custody
                LEFT JOIN evidence
                    ON custody.evidence_id = evidence.id
                WHERE evidence.id IS NULL
                LIMIT 1
                """
            )

            if cursor.fetchone():
                connection.rollback()
                raise sqlite3.IntegrityError(
                    "Cannot migrate custody records with missing evidence."
                )

            cursor.execute("ALTER TABLE custody RENAME TO custody_legacy")
            cursor.execute(
                """
                CREATE TABLE custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    person TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    remarks TEXT,
                    previous_hash TEXT,
                    event_hash TEXT,
                    FOREIGN KEY (evidence_id)
                        REFERENCES evidence(id)
                        ON DELETE CASCADE
                )
                """
            )
            cursor.execute(
                """
                INSERT INTO custody
                (id, evidence_id, action, person, timestamp, remarks,
                 previous_hash, event_hash)
                SELECT id, evidence_id, action, person, timestamp, remarks,
                       previous_hash, event_hash
                FROM custody_legacy
                """
            )
            cursor.execute("DROP TABLE custody_legacy")

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS custody_prevent_update
            BEFORE UPDATE ON custody
            BEGIN
                SELECT RAISE(ABORT, 'Custody events are append-only');
            END
            """
        )

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS custody_prevent_delete
            BEFORE DELETE ON custody
            WHEN EXISTS (
                SELECT 1
                FROM evidence
                WHERE evidence.id = OLD.evidence_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'Custody events are append-only');
            END
            """
        )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


# =========================================================
# CASE ID GENERATION
# =========================================================

def get_next_case_id():
    """Generate the next available Case ID in CT-YYYY-NNN format."""
    current_year = datetime.now().year
    prefix = f"CT-{current_year}-"

    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT case_id
            FROM cases
            WHERE case_id LIKE ?
            ORDER BY case_id
            """,
            (f"{prefix}%",),
        )
        existing_ids = {row["case_id"] for row in cursor.fetchall()}
    finally:
        connection.close()

    number = 1
    while f"{prefix}{number:03d}" in existing_ids:
        number += 1

    return f"{prefix}{number:03d}"


# =========================================================
# CASE FUNCTIONS
# =========================================================

def create_case(
    case_id,
    case_name,
    investigator,
    description,
    status
):
    """Create a new investigation case."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            INSERT INTO cases
            (
                case_id,
                case_name,
                investigator,
                description,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                case_name,
                investigator,
                description,
                status,
                created_at,
            ),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_cases(search_text=""):
    """Return all cases or matching cases."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if search_text.strip():
            search = f"%{search_text.strip()}%"
            cursor.execute(
                """
                SELECT *
                FROM cases
                WHERE case_id LIKE ?
                   OR case_name LIKE ?
                   OR investigator LIKE ?
                   OR status LIKE ?
                ORDER BY id DESC
                """,
                (search, search, search, search),
            )
        else:
            cursor.execute(
                """
                SELECT *
                FROM cases
                ORDER BY id DESC
                """
            )
        return cursor.fetchall()
    finally:
        connection.close()


def get_case(database_id):
    """Return one case by database ID."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT *
            FROM cases
            WHERE id = ?
            """,
            (database_id,),
        )
        return cursor.fetchone()
    finally:
        connection.close()


def update_case(
    database_id,
    case_name,
    investigator,
    description,
    status
):
    """Update an existing case."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE cases
            SET case_name = ?,
                investigator = ?,
                description = ?,
                status = ?
            WHERE id = ?
            """,
            (
                case_name,
                investigator,
                description,
                status,
                database_id,
            ),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def delete_case(database_id):
    """Delete an evidence-free case and related database records."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT 1
            FROM evidence
            WHERE case_id = ?
            LIMIT 1
            """,
            (database_id,),
        )
        if cursor.fetchone():
            raise sqlite3.IntegrityError(
                "Cases containing evidence cannot be deleted."
            )

        cursor.execute(
            """
            DELETE FROM cases
            WHERE id = ?
            """,
            (database_id,),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def create_note(case_id, note):
    """Create a new investigation note for a case."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            INSERT INTO notes
            (
                case_id,
                note,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (case_id, note, created_at),
        )
        connection.commit()
        return cursor.lastrowid
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_notes(case_id=None):
    """Return investigation notes, optionally filtered by case."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if case_id is not None:
            cursor.execute(
                """
                SELECT
                    notes.id,
                    notes.case_id,
                    notes.note,
                    notes.created_at,
                    cases.case_id AS case_number,
                    cases.case_name
                FROM notes
                INNER JOIN cases
                    ON notes.case_id = cases.id
                WHERE notes.case_id = ?
                ORDER BY notes.id DESC
                """,
                (case_id,),
            )
        else:
            cursor.execute(
                """
                SELECT
                    notes.id,
                    notes.case_id,
                    notes.note,
                    notes.created_at,
                    cases.case_id AS case_number,
                    cases.case_name
                FROM notes
                INNER JOIN cases
                    ON notes.case_id = cases.id
                ORDER BY notes.id DESC
                """
            )
        return cursor.fetchall()
    finally:
        connection.close()


def delete_note(note_id):
    """Delete an investigation note by ID."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            DELETE FROM notes
            WHERE id = ?
            """,
            (note_id,),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_active_case_count():
    """Return number of active cases."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM cases
            WHERE status != 'Closed'
            """
        )
        result = cursor.fetchone()
        return result["total"] if result else 0
    finally:
        connection.close()


# =========================================================
# EVIDENCE FUNCTIONS
# =========================================================

def create_evidence(
    case_id,
    evidence_name,
    original_path,
    preserved_path,
    sha256,
    acquired_at
):
    """Register preserved evidence."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO evidence
            (
                case_id,
                evidence_name,
                original_path,
                preserved_path,
                sha256,
                acquired_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                evidence_name,
                original_path,
                preserved_path,
                sha256,
                acquired_at,
            ),
        )
        connection.commit()
        return cursor.lastrowid
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def create_evidence_with_custody(
    case_id,
    evidence_name,
    original_path,
    preserved_path,
    sha256,
    acquired_at,
    person,
    remarks
):
    """Register evidence and its acquisition event atomically."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO evidence
            (
                case_id,
                evidence_name,
                original_path,
                preserved_path,
                sha256,
                acquired_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                evidence_name,
                original_path,
                preserved_path,
                sha256,
                acquired_at,
            ),
        )

        evidence_id = cursor.lastrowid
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_hash = calculate_custody_event_hash(
            evidence_id,
            "Acquired",
            person,
            timestamp,
            remarks,
            "",
        )

        cursor.execute(
            """
            INSERT INTO custody
            (
                evidence_id,
                action,
                person,
                timestamp,
                remarks,
                previous_hash,
                event_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                "Acquired",
                person,
                timestamp,
                remarks,
                "",
                event_hash,
            ),
        )

        connection.commit()
        return evidence_id
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_evidence(search_text=""):
    """Return evidence records."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if search_text.strip():
            search = f"%{search_text.strip()}%"
            cursor.execute(
                """
                SELECT
                    evidence.id,
                    evidence.case_id,
                    evidence.evidence_name,
                    evidence.original_path,
                    evidence.preserved_path,
                    evidence.sha256,
                    evidence.acquired_at,
                    cases.case_id AS case_number,
                    cases.case_name
                FROM evidence
                INNER JOIN cases
                    ON evidence.case_id = cases.id
                WHERE evidence.evidence_name LIKE ?
                   OR evidence.sha256 LIKE ?
                   OR cases.case_id LIKE ?
                   OR cases.case_name LIKE ?
                ORDER BY evidence.id DESC
                """,
                (search, search, search, search),
            )
        else:
            cursor.execute(
                """
                SELECT
                    evidence.id,
                    evidence.case_id,
                    evidence.evidence_name,
                    evidence.original_path,
                    evidence.preserved_path,
                    evidence.sha256,
                    evidence.acquired_at,
                    cases.case_id AS case_number,
                    cases.case_name
                FROM evidence
                INNER JOIN cases
                    ON evidence.case_id = cases.id
                ORDER BY evidence.id DESC
                """
            )
        return cursor.fetchall()
    finally:
        connection.close()


def get_evidence_for_case(case_id):
    """Return evidence belonging to one case."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT *
            FROM evidence
            WHERE case_id = ?
            ORDER BY id DESC
            """,
            (case_id,),
        )
        return cursor.fetchall()
    finally:
        connection.close()


def get_evidence_by_id(evidence_id):
    """Return one evidence record."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT
                evidence.*,
                cases.case_id AS case_number,
                cases.case_name,
                cases.investigator
            FROM evidence
            INNER JOIN cases
                ON evidence.case_id = cases.id
            WHERE evidence.id = ?
            """,
            (evidence_id,),
        )
        return cursor.fetchone()
    finally:
        connection.close()


def replace_correlation_findings(case_id, findings, engine_version="1"):
    """Replace active correlation findings for one case atomically."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id FROM cases WHERE id = ?", (case_id,))
        if not cursor.fetchone():
            raise ValueError("The selected investigation case does not exist.")

        evidence_ids = {
            row["id"]
            for row in cursor.execute(
                "SELECT id FROM evidence WHERE case_id = ?", (case_id,)
            ).fetchall()
        }

        cursor.execute(
            "UPDATE correlation_findings SET active = 0 WHERE case_id = ? AND active = 1",
            (case_id,),
        )

        for finding in findings:
            evidence_a_id = int(finding["evidence_a_id"])
            evidence_b_id = int(finding["evidence_b_id"])
            if evidence_a_id >= evidence_b_id:
                raise ValueError("Correlation evidence pairs must be ordered.")
            if evidence_a_id == evidence_b_id:
                raise ValueError("Correlation evidence pairs must contain two records.")
            if evidence_a_id not in evidence_ids or evidence_b_id not in evidence_ids:
                raise ValueError("Correlation findings cannot cross investigation cases.")

            cursor.execute(
                """
                INSERT INTO correlation_findings (
                    case_id,
                    evidence_a_id,
                    evidence_b_id,
                    relationship_type,
                    indicator_type,
                    indicator_fingerprint,
                    indicator_display,
                    strength_score,
                    strength_label,
                    explanation,
                    detected_at,
                    engine_version,
                    active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT (
                    case_id,
                    evidence_a_id,
                    evidence_b_id,
                    relationship_type,
                    indicator_fingerprint
                ) DO UPDATE SET
                    indicator_display = excluded.indicator_display,
                    strength_score = excluded.strength_score,
                    strength_label = excluded.strength_label,
                    explanation = excluded.explanation,
                    detected_at = excluded.detected_at,
                    engine_version = excluded.engine_version,
                    active = 1
                """,
                (
                    case_id,
                    evidence_a_id,
                    evidence_b_id,
                    finding["relationship_type"],
                    finding.get("indicator_type"),
                    finding.get("indicator_fingerprint"),
                    finding.get("indicator_value"),
                    finding["strength_score"],
                    finding["strength_label"],
                    finding["explanation"],
                    finding["detected_at"],
                    engine_version,
                ),
            )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_correlation_findings(case_id, include_inactive=False):
    """Return persisted correlation findings for one case."""
    connection = get_connection()
    try:
        active_clause = "" if include_inactive else "AND correlation_findings.active = 1"
        return connection.execute(
            f"""
            SELECT correlation_findings.*,
                   evidence_a.evidence_name AS evidence_a_name,
                   evidence_b.evidence_name AS evidence_b_name
            FROM correlation_findings
            INNER JOIN evidence AS evidence_a
                ON correlation_findings.evidence_a_id = evidence_a.id
            INNER JOIN evidence AS evidence_b
                ON correlation_findings.evidence_b_id = evidence_b.id
            WHERE correlation_findings.case_id = ? {active_clause}
            ORDER BY correlation_findings.evidence_a_id,
                     correlation_findings.evidence_b_id,
                     correlation_findings.relationship_type,
                     correlation_findings.id
            """,
            (case_id,),
        ).fetchall()
    finally:
        connection.close()


def get_evidence_count():
    """Return total evidence count."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM evidence
            """
        )
        result = cursor.fetchone()
        return result["total"] if result else 0
    finally:
        connection.close()


def get_verified_evidence_count():
    """Return evidence records having SHA-256."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM evidence")
        evidence_items = cursor.fetchall()
        return sum(
            1
            for evidence in evidence_items
            if get_current_evidence_status(evidence) == "VERIFIED"
        )
    finally:
        connection.close()


# =====================================================
# FILE EXAMINATION FUNCTIONS
# =====================================================

def create_analysis(
    evidence_id,
    analyst,
    file_name,
    file_path,
    file_size,
    extension,
    mime_type,
    created_time,
    modified_time,
    accessed_time,
    sha256,
    integrity_status,
    notes=""
):
    """Persist one examination of a preserved evidence copy."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO analyses
            (
                evidence_id,
                analyzed_at,
                analyst,
                file_name,
                file_path,
                file_size,
                extension,
                mime_type,
                created_time,
                modified_time,
                accessed_time,
                sha256,
                integrity_status,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                analyst,
                file_name,
                file_path,
                file_size,
                extension,
                mime_type,
                created_time,
                modified_time,
                accessed_time,
                sha256,
                integrity_status,
                notes,
            ),
        )
        connection.commit()
        return cursor.lastrowid
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_analyses_for_evidence(evidence_id):
    """Return examinations for one evidence record, newest first."""
    connection = get_connection()
    try:
        return connection.execute(
            """
            SELECT analyses.*, evidence.evidence_name,
                   cases.case_id AS case_number
            FROM analyses
            INNER JOIN evidence
                ON analyses.evidence_id = evidence.id
            INNER JOIN cases
                ON evidence.case_id = cases.id
            WHERE analyses.evidence_id = ?
            ORDER BY analyses.id DESC
            """,
            (evidence_id,),
        ).fetchall()
    finally:
        connection.close()


def get_analyses_for_case(case_id):
    """Return examinations for every evidence item in a case."""
    connection = get_connection()
    try:
        return connection.execute(
            """
            SELECT analyses.*, evidence.evidence_name,
                   cases.case_id AS case_number
            FROM analyses
            INNER JOIN evidence
                ON analyses.evidence_id = evidence.id
            INNER JOIN cases
                ON evidence.case_id = cases.id
            WHERE evidence.case_id = ?
            ORDER BY analyses.analyzed_at ASC, analyses.id ASC
            """,
            (case_id,),
        ).fetchall()
    finally:
        connection.close()


# =========================================================
# CHAIN OF CUSTODY FUNCTIONS
# =========================================================

def get_last_custody_hash(evidence_id):
    """Return the latest custody event hash."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT event_hash
            FROM custody
            WHERE evidence_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (evidence_id,),
        )
        result = cursor.fetchone()
        if result and result["event_hash"]:
            return result["event_hash"]
        return ""
    finally:
        connection.close()


def calculate_custody_event_hash(
    evidence_id,
    action,
    person,
    timestamp,
    remarks,
    previous_hash
):
    """Create SHA-256 hash for a custody event."""
    event_data = (
        f"{evidence_id}|"
        f"{action}|"
        f"{person}|"
        f"{timestamp}|"
        f"{remarks}|"
        f"{previous_hash}"
    )
    return hashlib.sha256(event_data.encode("utf-8")).hexdigest()


def add_custody_event(
    evidence_id,
    action,
    person,
    remarks
):
    """Add a new append-only custody event referencing previous event hash."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            SELECT event_hash
            FROM custody
            WHERE evidence_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (evidence_id,),
        )
        previous_record = cursor.fetchone()
        previous_hash = (
            previous_record["event_hash"]
            if previous_record and previous_record["event_hash"]
            else ""
        )

        event_hash = calculate_custody_event_hash(
            evidence_id,
            action,
            person,
            timestamp,
            remarks,
            previous_hash,
        )

        cursor.execute(
            """
            INSERT INTO custody
            (
                evidence_id,
                action,
                person,
                timestamp,
                remarks,
                previous_hash,
                event_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                action,
                person,
                timestamp,
                remarks,
                previous_hash,
                event_hash,
            ),
        )
        connection.commit()
        return cursor.lastrowid
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_custody_events(evidence_id=None):
    """Return custody events."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if evidence_id is not None:
            cursor.execute(
                """
                SELECT
                    custody.*,
                    evidence.evidence_name,
                    cases.case_id AS case_number
                FROM custody
                INNER JOIN evidence
                    ON custody.evidence_id = evidence.id
                INNER JOIN cases
                    ON evidence.case_id = cases.id
                WHERE custody.evidence_id = ?
                ORDER BY custody.id ASC
                """,
                (evidence_id,),
            )
        else:
            cursor.execute(
                """
                SELECT
                    custody.*,
                    evidence.evidence_name,
                    cases.case_id AS case_number
                FROM custody
                INNER JOIN evidence
                    ON custody.evidence_id = evidence.id
                INNER JOIN cases
                    ON evidence.case_id = cases.id
                ORDER BY custody.id DESC
                """
            )
        return cursor.fetchall()
    finally:
        connection.close()


def verify_custody_chain(evidence_id):
    """
    Verify the complete custody hash chain.

    Returns:
        (True, message) or (False, message)
    """
    events = get_custody_events(evidence_id)

    if not events:
        return (False, "No custody events found.")

    previous_hash = ""

    for event in events:
        expected_hash = calculate_custody_event_hash(
            event["evidence_id"],
            event["action"],
            event["person"],
            event["timestamp"],
            event["remarks"] or "",
            previous_hash,
        )

        stored_previous = event["previous_hash"] or ""
        stored_event = event["event_hash"] or ""

        if stored_previous != previous_hash:
            return (
                False,
                f"Chain broken at event #{event['id']}."
            )

        if stored_event != expected_hash:
            return (
                False,
                f"Integrity mismatch at event #{event['id']}."
            )

        previous_hash = stored_event

    return (True, "Custody chain integrity verified.")


# =====================================================
# IMPACT LAYER - INVESTIGATION HEALTH, LIFECYCLE & ANALYTICS
# =====================================================

def calculate_file_sha256(file_path):
    """Safely calculate SHA-256 hash of a file on disk in chunks."""
    if not file_path or not os.path.isfile(file_path):
        return None
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def get_current_evidence_status(evidence):
    """Return the current verification state of a preserved evidence copy."""
    preserved_path = evidence["preserved_path"]
    stored_hash = (evidence["sha256"] or "").strip()

    if not preserved_path or not os.path.isfile(preserved_path):
        return "MISSING"

    if not stored_hash:
        return "UNVERIFIED"

    current_hash = calculate_file_sha256(preserved_path)
    if not current_hash:
        return "UNVERIFIED"

    return "VERIFIED" if current_hash.lower() == stored_hash.lower() else "MISMATCH"


def get_case_report_file(case_id_or_db_id):
    """Return path to generated forensic report file if it exists on disk."""
    case = None
    if hasattr(case_id_or_db_id, "keys") or isinstance(case_id_or_db_id, dict):
        case = case_id_or_db_id
    elif isinstance(case_id_or_db_id, (int, str)):
        connection = get_connection()
        try:
            cursor = connection.cursor()
            if isinstance(case_id_or_db_id, int) or (isinstance(case_id_or_db_id, str) and case_id_or_db_id.isdigit()):
                cursor.execute("SELECT * FROM cases WHERE id = ?", (int(case_id_or_db_id),))
            else:
                cursor.execute("SELECT * FROM cases WHERE case_id = ?", (str(case_id_or_db_id),))
            case = cursor.fetchone()
        finally:
            connection.close()

    if not case:
        return None

    case_id = case["case_id"]
    reports_dir = os.path.join(get_app_dir(), "reports")
    if not os.path.exists(reports_dir):
        return None

    default_path = os.path.join(reports_dir, f"CyberTrace_{case_id}_Forensic_Report.html")
    if os.path.isfile(default_path):
        return default_path

    try:
        for fname in os.listdir(reports_dir):
            if case_id in fname and fname.endswith(".html"):
                full_path = os.path.join(reports_dir, fname)
                if os.path.isfile(full_path):
                    return full_path
    except Exception:
        pass

    return None


def is_case_report_ready(evidence_items, analyses, notes):
    """Return whether all current evidence, custody, analysis, and notes are ready."""
    if not evidence_items or not notes:
        return False

    current_verified_ids = {
        evidence["id"]
        for evidence in evidence_items
        if get_current_evidence_status(evidence) == "VERIFIED"
    }
    matched_analysis_ids = {
        analysis["evidence_id"]
        for analysis in analyses
        if "evidence_id" in analysis.keys()
        and analysis["evidence_id"]
        and (analysis["integrity_status"] or "").upper() == "MATCH"
    }

    if len(current_verified_ids) != len(evidence_items):
        return False
    if not all(evidence_id in matched_analysis_ids for evidence_id in current_verified_ids):
        return False

    for evidence in evidence_items:
        events = get_custody_events(evidence["id"])
        if not events or not verify_custody_chain(evidence["id"])[0]:
            return False

    return True


def get_case_health(case_id_or_db_id):
    """
    Calculate transparent, deterministic Investigation Health score (0-100) for a case.
    Accepts database ID (int) or case_id (str like 'CT-2026-001').
    """
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if isinstance(case_id_or_db_id, int) or (isinstance(case_id_or_db_id, str) and case_id_or_db_id.isdigit()):
            cursor.execute("SELECT * FROM cases WHERE id = ?", (int(case_id_or_db_id),))
        else:
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (str(case_id_or_db_id),))
        case = cursor.fetchone()
    finally:
        connection.close()

    if not case:
        return {
            "score": 0,
            "label": "INCOMPLETE",
            "color": "#e74c3c",
            "breakdown": [],
            "risk_flags": ["Case record not found."],
            "disclaimer": "CyberTrace Investigation Health Score is an internal completeness and workflow integrity indicator. It is NOT a legal, court, or forensic certification."
        }

    case_db_id = case["id"]
    evidence_items = get_evidence_for_case(case_db_id)
    notes = get_notes(case_db_id)
    analyses = get_analyses_for_case(case_db_id)

    factors = []
    risk_flags = []
    total_score = 0
    has_critical_failure = False

    # 1. Base Case Details (10 pts)
    if case["case_name"] and case["investigator"] and case["created_at"]:
        factors.append({"factor": "Base Case Details", "pts": 10, "max_pts": 10, "status": "COMPLETE", "details": "Case metadata, investigator, and creation timestamp recorded."})
        total_score += 10
    else:
        factors.append({"factor": "Base Case Details", "pts": 5, "max_pts": 10, "status": "PARTIAL", "details": "Case created with missing optional details."})
        total_score += 5

    # 2. Digital Evidence Acquired (15 pts)
    ev_count = len(evidence_items)
    if ev_count > 0:
        factors.append({"factor": "Evidence Acquisition", "pts": 15, "max_pts": 15, "status": "COMPLETE", "details": f"{ev_count} evidence record(s) acquired."})
        total_score += 15
    else:
        factors.append({"factor": "Evidence Acquisition", "pts": 0, "max_pts": 15, "status": "PENDING", "details": "No evidence items acquired for this case yet."})

    if ev_count > 0:
        # 3. Preserved Evidence Available (15 pts)
        preserved_present = 0
        for ev in evidence_items:
            path = ev["preserved_path"]
            if path and os.path.exists(path):
                preserved_present += 1
            else:
                risk_flags.append(f"HIGH ATTENTION: Preserved copy for evidence '{ev['evidence_name']}' is missing from disk.")

        preserved_ratio = preserved_present / ev_count
        pres_pts = round(15 * preserved_ratio)
        total_score += pres_pts
        factors.append({
            "factor": "Preserved Evidence Copies",
            "pts": pres_pts,
            "max_pts": 15,
            "status": "COMPLETE" if preserved_ratio == 1.0 else "PARTIAL",
            "details": f"{preserved_present}/{ev_count} preserved evidence copy file(s) available on disk."
        })

        # 4. SHA-256 Verification Result (20 pts)
        match_count = 0
        mismatch_count = 0
        unverified_count = 0

        for ev in evidence_items:
            path = ev["preserved_path"]
            stored_hash = ev["sha256"] or ""
            if path and os.path.exists(path) and stored_hash:
                actual_hash = calculate_file_sha256(path)
                if actual_hash and actual_hash.lower() == stored_hash.lower():
                    match_count += 1
                else:
                    mismatch_count += 1
                    has_critical_failure = True
                    risk_flags.append(f"CRITICAL RISK: SHA-256 mismatch detected for evidence '{ev['evidence_name']}'.")
            else:
                unverified_count += 1

        if mismatch_count > 0:
            hash_pts = 0
            hash_status = "MISMATCH DETECTED"
        elif match_count == ev_count:
            hash_pts = 20
            hash_status = "VERIFIED MATCH"
        else:
            hash_pts = round(20 * (match_count / ev_count))
            hash_status = "PARTIALLY VERIFIED"

        total_score += hash_pts
        factors.append({
            "factor": "SHA-256 Hash Verification",
            "pts": hash_pts,
            "max_pts": 20,
            "status": hash_status,
            "details": f"{match_count}/{ev_count} match, {mismatch_count} mismatch, {unverified_count} unverified."
        })

        # 5. Chain of Custody Integrity (15 pts)
        verified_custody_count = 0
        broken_custody_count = 0
        no_custody_count = 0

        for ev in evidence_items:
            events = get_custody_events(ev["id"])
            if not events:
                no_custody_count += 1
            else:
                valid, msg = verify_custody_chain(ev["id"])
                if valid:
                    verified_custody_count += 1
                else:
                    broken_custody_count += 1
                    has_critical_failure = True
                    risk_flags.append(f"CRITICAL RISK: Chain of Custody integrity failure for '{ev['evidence_name']}': {msg}")

        if broken_custody_count > 0:
            cust_pts = 0
            cust_status = "CHAIN BROKEN"
        elif verified_custody_count == ev_count:
            cust_pts = 15
            cust_status = "VERIFIED INTACT"
        else:
            cust_pts = round(15 * (verified_custody_count / ev_count))
            cust_status = "PARTIAL CUSTODY"

        total_score += cust_pts
        factors.append({
            "factor": "Chain of Custody Integrity",
            "pts": cust_pts,
            "max_pts": 15,
            "status": cust_status,
            "details": f"{verified_custody_count}/{ev_count} intact custody chains, {broken_custody_count} broken, {no_custody_count} pending."
        })

        # 6. File Examination Persisted (10 pts)
        current_verified_ev_ids = {
            ev["id"]
            for ev in evidence_items
            if get_current_evidence_status(ev) == "VERIFIED"
        }
        examined_ev_ids = {
            a["evidence_id"]
            for a in analyses
            if "evidence_id" in a.keys()
            and a["evidence_id"]
            and a["evidence_id"] in current_verified_ev_ids
            and (a["integrity_status"] or "").upper() == "MATCH"
        }
        examined_count = len(examined_ev_ids)
        exam_ratio = examined_count / ev_count if ev_count > 0 else 0
        exam_pts = round(10 * exam_ratio)
        total_score += exam_pts
        factors.append({
            "factor": "File Examination Persisted",
            "pts": exam_pts,
            "max_pts": 10,
            "status": "COMPLETE" if examined_count == ev_count else "PARTIAL",
            "details": f"{len(analyses)} total analysis record(s) saved across {examined_count}/{ev_count} evidence item(s)."
        })
    else:
        factors.append({"factor": "Preserved Evidence Copies", "pts": 0, "max_pts": 15, "status": "PENDING", "details": "No evidence acquired."})
        factors.append({"factor": "SHA-256 Hash Verification", "pts": 0, "max_pts": 20, "status": "PENDING", "details": "No evidence acquired."})
        factors.append({"factor": "Chain of Custody Integrity", "pts": 0, "max_pts": 15, "status": "PENDING", "details": "No evidence acquired."})
        factors.append({"factor": "File Examination Persisted", "pts": 0, "max_pts": 10, "status": "PENDING", "details": "No evidence acquired."})

    # 7. Findings/Notes Recorded (10 pts)
    note_count = len(notes)
    note_pts = 10 if note_count >= 1 else 0
    total_score += note_pts
    factors.append({
        "factor": "Findings & Notes Recorded",
        "pts": note_pts,
        "max_pts": 10,
        "status": "COMPLETE" if note_count >= 1 else "PENDING",
        "details": f"{note_count} investigation note(s) / finding(s) recorded."
    })

    # 8. Report Availability (5 pts)
    report_ready = is_case_report_ready(evidence_items, analyses, notes)
    report_file = get_case_report_file(case)
    report_pts = 5 if report_ready else (3 if ev_count > 0 else 0)
    total_score += report_pts
    if report_file and os.path.isfile(report_file):
        rep_status = "GENERATED"
        rep_details = f"Forensic report generated ({os.path.basename(report_file)})."
    elif report_ready:
        rep_status = "READY"
        rep_details = "Case data is complete for final forensic report generation."
    else:
        rep_status = "PARTIAL"
        rep_details = "Case requires additional evidence/analysis or current integrity verification before final report."

    factors.append({
        "factor": "Report Generation Readiness",
        "pts": report_pts,
        "max_pts": 5,
        "status": rep_status,
        "details": rep_details
    })

    # Fail-safe capping rule: If any evidence item has a mismatch or broken custody, cap score at 49
    if has_critical_failure and total_score > 49:
        total_score = 49

    total_score = max(0, min(100, total_score))

    if total_score >= 85:
        label = "EXCELLENT"
        color = "#2ecc71"
    elif total_score >= 70:
        label = "GOOD"
        color = "#3498db"
    elif total_score >= 40:
        label = "ATTENTION REQUIRED"
        color = "#f39c12"
    else:
        label = "INCOMPLETE"
        color = "#e74c3c"

    return {
        "case_id": case["case_id"],
        "case_name": case["case_name"],
        "score": total_score,
        "label": label,
        "color": color,
        "breakdown": factors,
        "risk_flags": risk_flags,
        "disclaimer": "CyberTrace Investigation Health Score is an internal completeness and workflow integrity indicator. It is NOT a legal, court, or forensic certification."
    }


def get_case_lifecycle_stage(case_id_or_db_id):
    """
    Returns an 8-stage visual lifecycle overview for a case based on actual state.
    """
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if isinstance(case_id_or_db_id, int) or (isinstance(case_id_or_db_id, str) and case_id_or_db_id.isdigit()):
            cursor.execute("SELECT * FROM cases WHERE id = ?", (int(case_id_or_db_id),))
        else:
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (str(case_id_or_db_id),))
        case = cursor.fetchone()
    finally:
        connection.close()

    if not case:
        return [
            {"stage": "Case Creation", "completed": False, "status": "pending", "details": "Awaiting case creation"},
            {"stage": "Evidence Acquired", "completed": False, "status": "pending", "details": "No evidence acquired"},
            {"stage": "SHA-256 Verified", "completed": False, "status": "pending", "details": "Awaiting evidence"},
            {"stage": "Chain of Custody", "completed": False, "status": "pending", "details": "Awaiting custody events"},
            {"stage": "File Analysis", "completed": False, "status": "pending", "details": "Awaiting file analysis"},
            {"stage": "Findings & Notes", "completed": False, "status": "pending", "details": "Awaiting investigation notes"},
            {"stage": "Timeline Analysis", "completed": False, "status": "pending", "details": "Awaiting timeline events"},
            {"stage": "Forensic Report", "completed": False, "status": "pending", "details": "Awaiting report generation"},
        ]

    case_db_id = case["id"]
    evidence_items = get_evidence_for_case(case_db_id)
    analyses = get_analyses_for_case(case_db_id)
    notes = get_notes(case_db_id)

    ev_count = len(evidence_items)

    stage1 = {"stage": "Case Created", "completed": True, "status": "completed", "details": f"Created on {case['created_at']} by {case['investigator']}"}

    stage2 = {
        "stage": "Evidence Acquired",
        "completed": ev_count > 0,
        "status": "completed" if ev_count > 0 else "pending",
        "details": f"{ev_count} item(s) acquired" if ev_count > 0 else "No evidence acquired"
    }

    if ev_count > 0:
        verified_count = 0
        mismatch_count = 0
        missing_count = 0
        for ev in evidence_items:
            path = ev["preserved_path"]
            stored = ev["sha256"] or ""
            if not path or not os.path.exists(path):
                missing_count += 1
            elif stored:
                h = calculate_file_sha256(path)
                if h and h.lower() == stored.lower():
                    verified_count += 1
                else:
                    mismatch_count += 1
            else:
                missing_count += 1
        if mismatch_count > 0:
            stage3 = {"stage": "SHA-256 Verified", "completed": False, "status": "attention", "details": f"{mismatch_count} hash mismatch detected!"}
        elif missing_count > 0:
            stage3 = {"stage": "SHA-256 Verified", "completed": False, "status": "attention", "details": f"{missing_count} evidence copy file(s) missing from disk"}
        elif verified_count == ev_count:
            stage3 = {"stage": "SHA-256 Verified", "completed": True, "status": "completed", "details": f"All {ev_count} item(s) verified matching SHA-256"}
        else:
            stage3 = {"stage": "SHA-256 Verified", "completed": False, "status": "pending", "details": f"{verified_count}/{ev_count} item(s) verified"}
    else:
        stage3 = {"stage": "SHA-256 Verified", "completed": False, "status": "pending", "details": "Awaiting evidence acquisition"}

    if ev_count > 0:
        custody_ok = True
        total_custody_events = 0
        for ev in evidence_items:
            events = get_custody_events(ev["id"])
            total_custody_events += len(events)
            if not events or not verify_custody_chain(ev["id"])[0]:
                custody_ok = False
        if total_custody_events > 0 and custody_ok:
            stage4 = {"stage": "Custody Recorded", "completed": True, "status": "completed", "details": f"{total_custody_events} custody event(s) verified"}
        elif total_custody_events > 0 and not custody_ok:
            stage4 = {"stage": "Custody Recorded", "completed": False, "status": "attention", "details": "Custody chain integrity issue detected"}
        else:
            stage4 = {"stage": "Custody Recorded", "completed": False, "status": "pending", "details": "No custody events recorded"}
    else:
        stage4 = {"stage": "Custody Recorded", "completed": False, "status": "pending", "details": "Awaiting evidence"}

    current_verified_ev_ids = {
        ev["id"]
        for ev in evidence_items
        if get_current_evidence_status(ev) == "VERIFIED"
    }
    examined_ev_ids = {
        a["evidence_id"]
        for a in analyses
        if "evidence_id" in a.keys()
        and a["evidence_id"]
        and a["evidence_id"] in current_verified_ev_ids
        and (a["integrity_status"] or "").upper() == "MATCH"
    }
    if ev_count > 0 and len(examined_ev_ids) == ev_count:
        stage5 = {"stage": "Evidence Examined", "completed": True, "status": "completed", "details": f"All {ev_count} evidence item(s) have a matching persisted analysis"}
    else:
        stage5 = {"stage": "Evidence Examined", "completed": False, "status": "pending", "details": f"{len(examined_ev_ids)}/{ev_count} evidence item(s) have a matching persisted analysis"}

    if len(notes) > 0:
        stage6 = {"stage": "Finding Recorded", "completed": True, "status": "completed", "details": f"{len(notes)} note(s)/finding(s) recorded"}
    else:
        stage6 = {"stage": "Finding Recorded", "completed": False, "status": "pending", "details": "No findings recorded"}

    has_timeline = ev_count > 0 or len(analyses) > 0 or len(notes) > 0
    stage7 = {
        "stage": "Timeline Updated",
        "completed": has_timeline,
        "status": "completed" if has_timeline else "pending",
        "details": "Investigation timeline populated" if has_timeline else "No timeline events yet"
    }

    is_report_ready = is_case_report_ready(evidence_items, analyses, notes)
    report_file = get_case_report_file(case)

    if report_file and os.path.isfile(report_file):
        stage8 = {
            "stage": "Report Generated",
            "completed": True,
            "status": "completed",
            "details": f"Report generated: {os.path.basename(report_file)}"
        }
    elif is_report_ready:
        stage8 = {
            "stage": "Report Ready for Generation",
            "completed": True,
            "status": "completed",
            "details": "Ready for export/generation"
        }
    else:
        stage8 = {
            "stage": "Forensic Report",
            "completed": False,
            "status": "pending",
            "details": "Pending investigation completion"
        }

    return [stage1, stage2, stage3, stage4, stage5, stage6, stage7, stage8]


def get_evidence_attention_flags(case_id_or_db_id=None):
    """
    Returns deterministic rule-based attention/risk items across cases/evidence.
    Categories: CRITICAL RISK, HIGH ATTENTION, MEDIUM ATTENTION, PENDING ACTION, INFORMATION
    """
    if case_id_or_db_id is not None:
        connection = get_connection()
        try:
            cursor = connection.cursor()
            if isinstance(case_id_or_db_id, int) or (isinstance(case_id_or_db_id, str) and case_id_or_db_id.isdigit()):
                cursor.execute("SELECT * FROM cases WHERE id = ?", (int(case_id_or_db_id),))
            else:
                cursor.execute("SELECT * FROM cases WHERE case_id = ?", (str(case_id_or_db_id),))
            cases = cursor.fetchall()
        finally:
            connection.close()
    else:
        cases = get_cases()

    flags = []

    for case in cases:
        case_id = case["case_id"]
        case_db_id = case["id"]
        evidence_items = get_evidence_for_case(case_db_id)
        analyses = get_analyses_for_case(case_db_id)

        if not evidence_items:
            flags.append({
                "level": "PENDING ACTION",
                "color": "#e67e22",
                "case_id": case_id,
                "evidence_name": "N/A",
                "title": "No Evidence Acquired",
                "description": f"Case '{case['case_name']}' ({case_id}) has no digital evidence assigned."
            })
            continue

        current_verified_ev_ids = {
            ev["id"]
            for ev in evidence_items
            if get_current_evidence_status(ev) == "VERIFIED"
        }
        examined_ev_ids = {
            a["evidence_id"]
            for a in analyses
            if "evidence_id" in a.keys()
            and a["evidence_id"]
            and a["evidence_id"] in current_verified_ev_ids
            and (a["integrity_status"] or "").upper() == "MATCH"
        }

        for ev in evidence_items:
            ev_name = ev["evidence_name"]
            path = ev["preserved_path"]
            stored_hash = ev["sha256"] or ""

            if not path or not os.path.exists(path):
                flags.append({
                    "level": "HIGH ATTENTION",
                    "color": "#e74c3c",
                    "case_id": case_id,
                    "evidence_name": ev_name,
                    "title": "Preserved File Missing",
                    "description": f"Preserved evidence file for '{ev_name}' is missing at '{path}'."
                })
            else:
                if stored_hash:
                    actual_hash = calculate_file_sha256(path)
                    if actual_hash and actual_hash.lower() != stored_hash.lower():
                        flags.append({
                            "level": "CRITICAL RISK",
                            "color": "#c0392b",
                            "case_id": case_id,
                            "evidence_name": ev_name,
                            "title": "SHA-256 Mismatch Detected",
                            "description": f"Disk file SHA-256 ({actual_hash[:12]}...) does not match database ({stored_hash[:12]}...)."
                        })

            events = get_custody_events(ev["id"])
            if not events:
                flags.append({
                    "level": "MEDIUM ATTENTION",
                    "color": "#f39c12",
                    "case_id": case_id,
                    "evidence_name": ev_name,
                    "title": "Custody Record Pending",
                    "description": f"No chain of custody log entries exist for evidence '{ev_name}'."
                })
            else:
                valid, msg = verify_custody_chain(ev["id"])
                if not valid:
                    flags.append({
                        "level": "CRITICAL RISK",
                        "color": "#c0392b",
                        "case_id": case_id,
                        "evidence_name": ev_name,
                        "title": "Custody Chain Broken",
                        "description": f"Chain of custody integrity check failed for '{ev_name}': {msg}"
                    })

            current_status = get_current_evidence_status(ev)
            if ev["id"] not in examined_ev_ids or current_status != "VERIFIED":
                flags.append({
                    "level": "MEDIUM ATTENTION",
                    "color": "#f39c12",
                    "case_id": case_id,
                    "evidence_name": ev_name,
                    "title": "Analysis Pending",
                    "description": f"No file examination record persisted for evidence '{ev_name}'."
                })

    return flags


def get_forensic_analytics_summary():
    """
    Aggregate system-wide forensic analytics metrics from database facts.
    """
    cases = get_cases()
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM evidence")
        all_evidence = cursor.fetchall()
        cursor.execute("SELECT * FROM analyses")
        all_analyses = cursor.fetchall()
        cursor.execute("SELECT * FROM custody")
        all_custody = cursor.fetchall()
        cursor.execute("SELECT * FROM notes")
        all_notes = cursor.fetchall()
    finally:
        connection.close()

    status_counts = {"Open": 0, "Under Investigation": 0, "Closed": 0, "Other": 0}
    for c in cases:
        st = c["status"] or "Open"
        if st in status_counts:
            status_counts[st] += 1
        else:
            status_counts["Other"] += 1

    match_count = 0
    mismatch_count = 0
    missing_count = 0
    unverified_count = 0

    for ev in all_evidence:
        st = get_current_evidence_status(ev)
        if st == "VERIFIED":
            match_count += 1
        elif st == "MISMATCH":
            mismatch_count += 1
        elif st == "MISSING":
            missing_count += 1
        else:
            unverified_count += 1

    verification_counts = {
        "MATCH": match_count,
        "MISMATCH": mismatch_count,
        "FILE MISSING": missing_count,
        "UNVERIFIED": unverified_count
    }

    extension_counts = {}
    mime_category_counts = {
        "Text / Documents": 0,
        "Images": 0,
        "Executables / Binaries": 0,
        "Archives": 0,
        "Other / System": 0
    }

    for ev in all_evidence:
        name = ev["evidence_name"] or ""
        ext = os.path.splitext(name)[1].lower() or ".unknown"
        extension_counts[ext] = extension_counts.get(ext, 0) + 1

        if ext in [".txt", ".log", ".pdf", ".doc", ".docx", ".csv", ".json", ".md", ".xml", ".html"]:
            mime_category_counts["Text / Documents"] += 1
        elif ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".tiff"]:
            mime_category_counts["Images"] += 1
        elif ext in [".exe", ".dll", ".sys", ".elf", ".bin", ".dat"]:
            mime_category_counts["Executables / Binaries"] += 1
        elif ext in [".zip", ".tar", ".gz", ".rar", ".7z", ".iso", ".img"]:
            mime_category_counts["Archives"] += 1
        else:
            mime_category_counts["Other / System"] += 1

    return {
        "total_cases": len(cases),
        "total_evidence": len(all_evidence),
        "total_custody_events": len(all_custody),
        "total_analyses": len(all_analyses),
        "total_notes": len(all_notes),
        "case_status_distribution": status_counts,
        "verification_distribution": verification_counts,
        "extension_distribution": extension_counts,
        "mime_distribution": mime_category_counts
    }


def get_automated_case_summary(case_id_or_db_id):
    """
    Generate a deterministic factual forensic investigation summary text based strictly on database facts.
    """
    health = get_case_health(case_id_or_db_id)
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if isinstance(case_id_or_db_id, int) or (isinstance(case_id_or_db_id, str) and case_id_or_db_id.isdigit()):
            cursor.execute("SELECT * FROM cases WHERE id = ?", (int(case_id_or_db_id),))
        else:
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (str(case_id_or_db_id),))
        case = cursor.fetchone()
    finally:
        connection.close()

    if not case:
        return "No case record found."

    case_db_id = case["id"]
    evidence_items = get_evidence_for_case(case_db_id)
    notes = get_notes(case_db_id)
    analyses = get_analyses_for_case(case_db_id)

    lines = []
    lines.append(f"INVESTIGATION SUMMARY REPORT: {case['case_id']}")
    lines.append(f"Case Title: {case['case_name']}")
    lines.append(f"Investigator: {case['investigator']}")
    lines.append(f"Creation Date: {case['created_at']}")
    lines.append(f"Case Status: {case['status']}")
    lines.append("-" * 60)
    lines.append(f"Investigation Health Score: {health['score']}/100 ({health['label']})")
    lines.append("-" * 60)
    lines.append(f"Digital Evidence Items: {len(evidence_items)} record(s) acquired.")

    for idx, ev in enumerate(evidence_items, 1):
        path = ev["preserved_path"]
        stored_hash = ev["sha256"] or "N/A"
        path_status = "Available on disk" if (path and os.path.exists(path)) else "MISSING on disk"

        hash_status = "UNVERIFIED"
        if path and os.path.exists(path) and stored_hash != "N/A":
            h = calculate_file_sha256(path)
            if h and h.lower() == stored_hash.lower():
                hash_status = "VERIFIED MATCH"
            else:
                hash_status = "MISMATCH DETECTED"

        events = get_custody_events(ev["id"])
        cust_status = "No events"
        if events:
            valid, msg = verify_custody_chain(ev["id"])
            cust_status = f"Verified ({len(events)} events)" if valid else f"BROKEN ({msg})"

        lines.append(f"  Item #{idx}: {ev['evidence_name']}")
        lines.append(f"    - SHA-256 Stored: {stored_hash}")
        lines.append(f"    - SHA-256 Integrity: {hash_status}")
        lines.append(f"    - Preserved Copy: {path_status}")
        lines.append(f"    - Chain of Custody: {cust_status}")

    lines.append("-" * 60)
    lines.append(f"Persisted Examinations / File Analyses: {len(analyses)} record(s)")
    for a in analyses:
        lines.append(f"  - Analysis #{a['id']}: {a['file_name']} | Result: {a['integrity_status']} | Analyst: {a['analyst'] or 'N/A'}")

    lines.append("-" * 60)
    lines.append(f"Investigation Notes / Findings: {len(notes)} entry(ies)")
    for n in notes:
        lines.append(f"  - [{n['created_at']}] {n['note']}")

    if health["risk_flags"]:
        lines.append("-" * 60)
        lines.append("ATTENTION / RISK WARNINGS:")
        for rf in health["risk_flags"]:
            lines.append(f"  ! {rf}")

    lines.append("-" * 60)
    lines.append("DISCLAIMER: " + health["disclaimer"])

    return "\n".join(lines)


def get_evidence_relationship_data(case_id_or_db_id):
    """
    Returns visual linkage flow node data for a case.
    Structure: Case -> Evidence -> Preserved Copy -> SHA-256 -> Custody -> Analysis -> Findings -> Report
    """
    connection = get_connection()
    try:
        cursor = connection.cursor()
        if isinstance(case_id_or_db_id, int) or (isinstance(case_id_or_db_id, str) and case_id_or_db_id.isdigit()):
            cursor.execute("SELECT * FROM cases WHERE id = ?", (int(case_id_or_db_id),))
        else:
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (str(case_id_or_db_id),))
        case = cursor.fetchone()
    finally:
        connection.close()

    if not case:
        return {}

    case_db_id = case["id"]
    evidence_items = get_evidence_for_case(case_db_id)
    analyses = get_analyses_for_case(case_db_id)
    notes = get_notes(case_db_id)

    nodes = []

    nodes.append({
        "type": "Case",
        "title": case["case_id"],
        "subtitle": case["case_name"],
        "status": case["status"],
        "color": "#34495e"
    })

    for ev in evidence_items:
        path = ev["preserved_path"]
        stored_hash = ev["sha256"] or ""
        path_exists = path and os.path.exists(path)

        hash_valid = False
        if path_exists and stored_hash:
            h = calculate_file_sha256(path)
            hash_valid = (h and h.lower() == stored_hash.lower())

        events = get_custody_events(ev["id"])
        custody_valid = False
        if events:
            custody_valid, _ = verify_custody_chain(ev["id"])

        ev_analyses = [a for a in analyses if "evidence_id" in a.keys() and a["evidence_id"] == ev["id"]]

        nodes.append({
            "type": "Evidence Item",
            "title": ev["evidence_name"],
            "subtitle": f"Acquired: {ev['acquired_at']}",
            "status": "Acquired",
            "color": "#2980b9",
            "children": [
                {
                    "type": "Preserved Copy",
                    "title": os.path.basename(path) if path else "No Path",
                    "status": "Available" if path_exists else "Missing",
                    "color": "#2ecc71" if path_exists else "#e74c3c"
                },
                {
                    "type": "SHA-256 Hash",
                    "title": (stored_hash[:16] + "...") if stored_hash else "None",
                    "status": "Match Verified" if hash_valid else "Mismatch / Unverified",
                    "color": "#2ecc71" if hash_valid else "#e74c3c"
                },
                {
                    "type": "Chain of Custody",
                    "title": f"{len(events)} custody log(s)",
                    "status": "Intact" if custody_valid else "Pending / Issue",
                    "color": "#2ecc71" if custody_valid else "#f39c12"
                },
                {
                    "type": "File Analysis",
                    "title": f"{len(ev_analyses)} analysis record(s)",
                    "status": "Persisted" if ev_analyses else "Pending",
                    "color": "#9b59b6" if ev_analyses else "#95a5a6"
                }
            ]
        })

    nodes.append({
        "type": "Findings & Report",
        "title": f"{len(notes)} note(s)",
        "subtitle": "Report Ready" if len(evidence_items) > 0 and len(notes) > 0 else "Draft Mode",
        "status": "Ready" if len(evidence_items) > 0 and len(notes) > 0 else "In Progress",
        "color": "#16a085"
    })

    return {
        "case_id": case["case_id"],
        "nodes": nodes
    }

