import hashlib
import os
import shutil
import tempfile
import unittest

from database import db
from evidence.correlation import CorrelationConfig, analyze_evidence


class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cybertrace_correlation_")
        self.paths = []

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def make_evidence(self, evidence_id, name, content, acquired_at="2026-09-09 10:00:00", sha256=None):
        path = os.path.join(self.temp_dir, f"{evidence_id}_{name}")
        with open(path, "wb") as evidence_file:
            evidence_file.write(content.encode("utf-8"))
        actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.paths.append(path)
        return {
            "id": evidence_id,
            "case_id": 1,
            "evidence_name": name,
            "preserved_path": path,
            "sha256": sha256 if sha256 is not None else actual_hash,
            "acquired_at": acquired_at,
        }

    def test_zero_and_one_evidence(self):
        self.assertEqual(analyze_evidence({})["findings"], [])
        self.assertEqual(analyze_evidence([self.make_evidence(1, "one.txt", "203.0.113.25")])["findings"], [])

    def test_identical_verified_hash_is_strongest(self):
        first = self.make_evidence(1, "a.bin", "same")
        second = self.make_evidence(2, "b.bin", "same")
        findings = analyze_evidence([first, second])["findings"]
        hash_findings = [finding for finding in findings if finding["relationship_type"] == "Identical SHA-256"]
        self.assertEqual(len(hash_findings), 1)
        self.assertEqual(hash_findings[0]["strength_score"], 100)
        self.assertEqual(hash_findings[0]["evidence_a_id"], 1)
        self.assertEqual(hash_findings[0]["evidence_b_id"], 2)

    def test_shared_indicators_are_classified_and_suppressed(self):
        first = self.make_evidence(1, "incident-a.txt", "IP 203.0.113.25 URL https://example.test/path email analyst@example.test C:\\Case\\incident.log")
        second = self.make_evidence(2, "incident-b.md", "IP 203.0.113.25 URL https://example.test/path email analyst@example.test C:\\Case\\incident.log")
        findings = analyze_evidence([first, second])["findings"]
        types = {finding["indicator_type"] for finding in findings}
        self.assertTrue({"ip", "url", "email", "path"}.issubset(types))
        self.assertTrue(all(finding["strength_score"] < 100 for finding in findings if finding["indicator_type"] != "sha256"))

        suppressed = self.make_evidence(3, "other.log", "127.0.0.1 192.168.1.1 localhost")
        self.assertFalse(any(finding["indicator_type"] == "ip" for finding in analyze_evidence([first, suppressed])["findings"]))

    def test_filename_extension_and_temporal_rules(self):
        first = self.make_evidence(1, "distinctive.log", "one", "2026-09-09 10:00:00")
        second = self.make_evidence(2, "distinctive.log", "two", "2026-09-09 10:04:00")
        findings = analyze_evidence([first, second], CorrelationConfig(include_contextual=True))["findings"]
        relationships = {finding["relationship_type"] for finding in findings}
        self.assertIn("Same Distinctive Filename", relationships)
        self.assertIn("Temporal Proximity", relationships)
        self.assertIn("Same File Extension", relationships)

        late = self.make_evidence(3, "later.log", "three", "2026-09-09 11:00:00")
        late_findings = analyze_evidence([first, late])["findings"]
        self.assertFalse(any(finding["relationship_type"] == "Temporal Proximity" for finding in late_findings))

        common_a = self.make_evidence(4, "notes.txt", "four")
        common_b = self.make_evidence(5, "notes.txt", "five")
        self.assertFalse(any(finding["relationship_type"] == "Same Distinctive Filename" for finding in analyze_evidence([common_a, common_b])["findings"]))

    def test_mismatch_missing_and_unsupported_are_incomplete(self):
        mismatch = self.make_evidence(1, "a.txt", "203.0.113.25", sha256="0" * 64)
        missing = self.make_evidence(2, "b.txt", "203.0.113.25")
        os.remove(missing["preserved_path"])
        result = analyze_evidence([mismatch, missing])
        self.assertTrue(all(finding["strength_score"] < 100 for finding in result["findings"]))
        self.assertTrue(result["incomplete"])
        self.assertEqual(result["skipped_count"], 2)

        binary = self.make_evidence(3, "sample.exe", "203.0.113.25")
        binary_result = analyze_evidence([binary])
        self.assertFalse(binary_result["incomplete"])
        self.assertEqual(binary_result["findings"], [])

    def test_unverified_pairs_produce_no_relationships(self):
        verified = self.make_evidence(1, "verified.bin", "verified", "2026-09-09 10:00:00")
        verified_two = self.make_evidence(2, "other.exe", "different", "2026-09-09 11:00:00")
        mismatch = self.make_evidence(3, "mismatch.txt", "mismatch", "2026-09-09 10:00:00", sha256="0" * 64)
        missing = self.make_evidence(4, "missing.txt", "missing", "2026-09-09 10:00:00")
        os.remove(missing["preserved_path"])

        verified_result = analyze_evidence(
            [verified, verified_two],
            CorrelationConfig(include_contextual=True),
        )
        self.assertEqual(verified_result["findings"], [])

        for invalid_pair in ([verified, mismatch], [verified, missing], [mismatch, missing]):
            result = analyze_evidence(
                invalid_pair,
                CorrelationConfig(include_contextual=True),
            )
            self.assertEqual(result["findings"], [])

        multiple_result = analyze_evidence(
            [verified, verified_two, mismatch, missing],
            CorrelationConfig(include_contextual=True),
        )
        self.assertTrue(
            all(
                finding["evidence_a_id"] not in {3, 4}
                and finding["evidence_b_id"] not in {3, 4}
                for finding in multiple_result["findings"]
            )
        )

    def test_large_text_is_bounded(self):
        first = self.make_evidence(1, "large.txt", "x" * 200)
        second = self.make_evidence(2, "other.txt", "203.0.113.25")
        result = analyze_evidence([first, second], CorrelationConfig(max_text_file_size=100))
        self.assertTrue(result["incomplete"])
        self.assertTrue(all(finding["relationship_type"] == "Temporal Proximity" for finding in result["findings"]))

    def test_malformed_text_is_read_safely(self):
        path = os.path.join(self.temp_dir, "malformed.txt")
        with open(path, "wb") as evidence_file:
            evidence_file.write(b"\xff\xfe\x00\x81")
        evidence = {
            "id": 1,
            "case_id": 1,
            "evidence_name": "malformed.txt",
            "preserved_path": path,
            "sha256": hashlib.sha256(b"\xff\xfe\x00\x81").hexdigest(),
            "acquired_at": "2026-09-09 10:00:00",
        }
        result = analyze_evidence([evidence])
        self.assertEqual(result["findings"], [])


class TestCorrelationPersistence(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cybertrace_db_correlation_")
        self.db_path = os.path.join(self.temp_dir, "data", "cybertrace.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.original_db_path = db.DATABASE_PATH
        db.DATABASE_PATH = self.db_path
        db.initialize_database()
        db.create_case("CT-TEST-001", "Correlation Case", "Investigator", "", "OPEN")
        db.create_case("CT-TEST-002", "Other Case", "Investigator", "", "OPEN")
        self.case_one = db.get_cases()[1]["id"]
        self.case_two = db.get_cases()[0]["id"]

    def tearDown(self):
        db.DATABASE_PATH = self.original_db_path
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def finding(self, first, second, relationship="Shared IP Indicator"):
        return {
            "evidence_a_id": min(first, second),
            "evidence_b_id": max(first, second),
            "relationship_type": relationship,
            "indicator_type": "ip",
            "indicator_fingerprint": f"fingerprint-{relationship}",
            "indicator_value": "203.0.113.25",
            "strength_score": 45,
            "strength_label": "Contextual",
            "explanation": "Synthetic test relationship.",
            "detected_at": "2026-09-09 10:00:00",
        }

    def test_repeated_runs_replace_active_findings(self):
        first = db.create_evidence(self.case_one, "a.txt", "", "", "a", "2026-09-09 10:00:00")
        second = db.create_evidence(self.case_one, "b.txt", "", "", "b", "2026-09-09 10:00:00")
        finding = self.finding(first, second)
        db.replace_correlation_findings(self.case_one, [finding])
        db.replace_correlation_findings(self.case_one, [finding])
        active = db.get_correlation_findings(self.case_one)
        self.assertEqual(len(active), 1)
        self.assertEqual(len(db.get_correlation_findings(self.case_one, include_inactive=True)), 1)

    def test_cross_case_and_unordered_pairs_are_rejected(self):
        first = db.create_evidence(self.case_one, "a.txt", "", "", "a", "2026-09-09 10:00:00")
        second = db.create_evidence(self.case_two, "b.txt", "", "", "b", "2026-09-09 10:00:00")
        with self.assertRaises(ValueError):
            db.replace_correlation_findings(self.case_one, [self.finding(first, second)])

        third = db.create_evidence(self.case_one, "c.txt", "", "", "c", "2026-09-09 10:00:00")
        unordered = self.finding(third, first)
        unordered["evidence_a_id"], unordered["evidence_b_id"] = third, first
        with self.assertRaises(ValueError):
            db.replace_correlation_findings(self.case_one, [unordered])

    def test_database_foreign_keys_reject_unknown_evidence(self):
        connection = db.get_connection()
        try:
            with self.assertRaises(Exception):
                connection.execute(
                    """
                    INSERT INTO correlation_findings (
                        case_id, evidence_a_id, evidence_b_id,
                        relationship_type, strength_score, strength_label,
                        explanation, detected_at, engine_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self.case_one, 1001, 1002, "Test", 1, "Weak", "Test", "2026-09-09 10:00:00", "test"),
                )
        finally:
            connection.rollback()
            connection.close()

    def test_report_contains_correlation_section_and_disclaimer(self):
        first = db.create_evidence(self.case_one, "a.txt", "", "", "a", "2026-09-09 10:00:00")
        second = db.create_evidence(self.case_one, "b.txt", "", "", "b", "2026-09-09 10:00:00")
        db.replace_correlation_findings(self.case_one, [self.finding(first, second)])

        from main import build_html_report

        html, case = build_html_report(self.case_one)
        self.assertIsNotNone(case)
        self.assertIn("Cross-Evidence Correlation Analysis", html)
        self.assertIn("EV-", html)
        self.assertIn("They do not establish common origin", html)


if __name__ == "__main__":
    unittest.main()
