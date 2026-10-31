import hashlib
import os
import shutil
import tempfile
import unittest

from database.db import (
    add_custody_event,
    create_analysis,
    create_case,
    create_evidence_with_custody,
    create_note,
    get_case_health,
    get_case_lifecycle_stage,
    get_cases,
    initialize_database,
)
from main import CyberTraceWindow, build_html_report


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cybertrace_test_")
        self.db_path = os.path.join(self.temp_dir, "data", "cybertrace.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        import database.db
        database.db.DATABASE_PATH = self.db_path
        initialize_database()

        self.evidence_dir = os.path.join(self.temp_dir, "evidence")
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.dummy_file = os.path.join(self.temp_dir, "test_file.txt")
        with open(self.dummy_file, "w", encoding="utf-8") as f:
            f.write("CyberTrace Forensic Test Evidence Content")

        with open(self.dummy_file, "rb") as f:
            self.file_sha256 = hashlib.sha256(f.read()).hexdigest()

        self.preserved_file = os.path.join(self.evidence_dir, "preserved_test_file.txt")
        shutil.copy2(self.dummy_file, self.preserved_file)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_html_report_generation_contains_health_and_lifecycle(self):
        create_case("CT-TEST-001", "Test Investigation Case", "Lead Investigator", "Test Description", "OPEN")
        case = [c for c in get_cases() if c["case_id"] == "CT-TEST-001"][0]
        case_db_id = case["id"]

        ev_id = create_evidence_with_custody(
            case_db_id,
            "Test Evidence Item",
            self.dummy_file,
            self.preserved_file,
            self.file_sha256,
            "2026-09-06 12:00:00",
            "Lead Investigator",
            "Initial Acquisition",
        )
        add_custody_event(ev_id, "Evidence Analysis", "Lead Investigator", "Extracted evidence for analysis")
        create_analysis(
            ev_id,
            "Lead Investigator",
            "preserved_test_file.txt",
            self.preserved_file,
            100,
            ".txt",
            "text/plain",
            "2026-09-06 12:00:00",
            "2026-09-06 12:00:00",
            "2026-09-06 12:00:00",
            self.file_sha256,
            "MATCH",
            "No anomalies detected",
        )
        create_note(case_db_id, "Test investigation note")

        health = get_case_health(case_db_id)
        stages = get_case_lifecycle_stage(case_db_id)

        html_content, case_res = build_html_report(case_db_id)

        self.assertIsNotNone(case_res)
        self.assertIn("INVESTIGATION HEALTH", html_content.upper())
        self.assertIn(f"Health Score:</strong> {health['score']} / 100", html_content)
        self.assertIn(health['label'], html_content)
        self.assertIn("8-STAGE INVESTIGATION LIFECYCLE", html_content.upper())

        for stage in stages:
            self.assertIn(stage["stage"].upper(), html_content.upper())

        self.assertIn("Digital Evidence Inventory", html_content)
        self.assertIn("Chain of Custody History", html_content)
        self.assertIn("File Analysis &amp; Examination Results", html_content)
        self.assertIn("Investigation Notes &amp; Findings", html_content)
        self.assertIn("Summary &amp; Conclusion", html_content)
        self.assertIn("Disclaimer", html_content)

    def test_mismatched_missing_evidence_health_and_lifecycle_semantics(self):
        create_case("CT-TEST-002", "Mismatched Test Case", "Lead Investigator", "Test Description", "OPEN")
        case = [c for c in get_cases() if c["case_id"] == "CT-TEST-002"][0]
        case_db_id = case["id"]

        missing_preserved = os.path.join(self.evidence_dir, "non_existent_file.txt")
        ev_id = create_evidence_with_custody(
            case_db_id,
            "Missing Evidence Item",
            self.dummy_file,
            missing_preserved,
            self.file_sha256,
            "2026-09-06 12:00:00",
            "Lead Investigator",
            "Initial Acquisition",
        )

        health = get_case_health(case_db_id)
        stages = get_case_lifecycle_stage(case_db_id)

        self.assertNotEqual(health["label"], "EXCELLENT")
        self.assertLessEqual(health["score"], 80)

        sha_stage = [s for s in stages if s["stage"] == "SHA-256 Verified"][0]
        self.assertFalse(sha_stage["completed"])

        html_content, _ = build_html_report(case_db_id)
        self.assertIn("INVESTIGATION HEALTH", html_content.upper())
        self.assertIn("8-STAGE INVESTIGATION LIFECYCLE", html_content.upper())

    def test_timeline_is_included_in_html_and_text_reports(self):
        create_case("CT-TEST-003", "Timeline Test Case", "Lead Investigator", "Test Description", "OPEN")
        case = [c for c in get_cases() if c["case_id"] == "CT-TEST-003"][0]
        case_db_id = case["id"]
        create_note(case_db_id, "Timeline note <must be escaped>")

        html_content, _ = build_html_report(case_db_id)
        text_report, _ = CyberTraceWindow.__new__(CyberTraceWindow).build_report_text(case_db_id)

        self.assertIn("<h2>Investigation Timeline</h2>", html_content)
        self.assertIn("Case Created", html_content)
        self.assertIn("Investigation Note / Finding", html_content)
        self.assertIn("Timeline note &lt;must be escaped&gt;", html_content)
        self.assertIn("INVESTIGATION TIMELINE", text_report)
        self.assertIn("Case Created", text_report)
        self.assertIn("Investigation Note / Finding", text_report)
        self.assertIn("Timeline note <must be escaped>", text_report)
        timeline_text = text_report.split(
            "INVESTIGATION TIMELINE", 1
        )[1].split("INVESTIGATION NOTES & FINDINGS", 1)[0]
        self.assertNotIn("Evidence Acquired", timeline_text)
        self.assertNotIn("File Analysis / Examination", timeline_text)

    def test_timeline_without_persisted_activity_has_no_fabricated_events(self):
        create_case("CT-TEST-004", "Empty Timeline Case", "Lead Investigator", "Test Description", "OPEN")
        case = [c for c in get_cases() if c["case_id"] == "CT-TEST-004"][0]

        html_content, _ = build_html_report(case["id"])
        text_report, _ = CyberTraceWindow.__new__(CyberTraceWindow).build_report_text(case["id"])

        timeline_html = html_content.split(
            "<h2>Investigation Timeline</h2>", 1
        )[1].split("<h2>Investigation Notes &amp; Findings</h2>", 1)[0]
        timeline_text = text_report.split(
            "INVESTIGATION TIMELINE", 1
        )[1].split("INVESTIGATION NOTES & FINDINGS", 1)[0]
        self.assertIn("Case Created", timeline_html)
        self.assertIn("Case Created", timeline_text)
        self.assertNotIn("Evidence Acquired", timeline_html)
        self.assertNotIn("Evidence Acquired", timeline_text)
        self.assertNotIn("File Analysis / Examination", timeline_html)
        self.assertNotIn("File Analysis / Examination", timeline_text)
        self.assertNotIn("Investigation Note / Finding", timeline_html)
        self.assertNotIn("Investigation Note / Finding", timeline_text)


if __name__ == "__main__":
    unittest.main()
