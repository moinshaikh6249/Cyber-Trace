import os
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from database import db
import main
from main import AcquisitionWorker, cleanup_acquisition_copy


class TestAcquisitionHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cybertrace_acquisition_")
        self.original_db_path = db.DATABASE_PATH
        self.db_path = os.path.join(self.temp_dir, "data", "cybertrace.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        db.DATABASE_PATH = self.db_path
        db.initialize_database()
        self.original_path = os.path.join(self.temp_dir, "original.txt")
        with open(self.original_path, "wb") as evidence_file:
            evidence_file.write(b"controlled acquisition test")

    def tearDown(self):
        db.DATABASE_PATH = self.original_db_path
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def worker_for(self, preserved_path):
        worker = AcquisitionWorker(self.original_path, preserved_path)
        finished = []
        errors = []
        worker.finished_signal.connect(finished.append)
        worker.error_signal.connect(errors.append)
        worker.run()
        return worker, finished, errors

    def test_copy_protection_and_database_registration_succeed(self):
        preserved_path = os.path.join(self.temp_dir, "preserved.txt")
        worker, finished, errors = self.worker_for(preserved_path)

        self.assertTrue(worker.copy_created)
        self.assertEqual(len(finished), 1)
        self.assertEqual(errors, [])
        self.assertTrue(os.path.isfile(preserved_path))
        self.assertFalse(os.stat(preserved_path).st_mode & stat.S_IWRITE)

        db.create_case(
            "CT-TEST-ACQ-001",
            "Acquisition Test",
            "Test Investigator",
            "",
            "Open",
        )
        case = db.get_cases()[0]
        evidence_id = db.create_evidence_with_custody(
            case["id"],
            "preserved.txt",
            self.original_path,
            preserved_path,
            finished[0]["preserved_hash"],
            "2026-09-10 12:00:00",
            "Test Investigator",
            "Test acquisition",
        )
        self.assertIsNotNone(evidence_id)
        self.assertTrue(os.path.exists(preserved_path))

    def test_registration_failure_cleans_only_current_copy(self):
        preserved_path = os.path.join(self.temp_dir, "failed-registration.txt")
        worker, finished, errors = self.worker_for(preserved_path)
        self.assertEqual(errors, [])
        self.assertTrue(os.path.exists(preserved_path))

        with self.assertRaises(Exception):
            db.create_evidence_with_custody(
                999999,
                "failed-registration.txt",
                self.original_path,
                preserved_path,
                finished[0]["preserved_hash"],
                "2026-09-10 12:00:00",
                "Test Investigator",
                "Should fail",
            )

        self.assertIsNone(cleanup_acquisition_copy(preserved_path, worker.copy_created))
        self.assertFalse(os.path.exists(preserved_path))

    def test_cancellation_after_copy_cleans_current_copy(self):
        preserved_path = os.path.join(self.temp_dir, "cancelled.txt")
        real_copy = shutil.copy2
        worker = AcquisitionWorker(self.original_path, preserved_path)

        with patch.object(
            main.shutil,
            "copy2",
            side_effect=lambda source, destination: real_copy(source, destination),
        ), patch.object(
            worker,
            "isInterruptionRequested",
            side_effect=[False, False, True],
        ):
            worker.run()

        self.assertTrue(worker.copy_created)
        self.assertFalse(os.path.exists(preserved_path))

    def test_protection_failure_emits_error_and_cleans_copy(self):
        preserved_path = os.path.join(self.temp_dir, "protection-failure.txt")
        worker = AcquisitionWorker(self.original_path, preserved_path)
        errors = []
        worker.error_signal.connect(errors.append)

        with patch.object(main, "protect_evidence_file", side_effect=PermissionError("protection failed")):
            worker.run()

        self.assertEqual(len(errors), 1)
        self.assertFalse(os.path.exists(preserved_path))

    def test_cleanup_does_not_remove_unowned_existing_file(self):
        preserved_path = os.path.join(self.temp_dir, "existing.txt")
        with open(preserved_path, "wb") as evidence_file:
            evidence_file.write(b"existing registered content")

        self.assertIsNone(cleanup_acquisition_copy(preserved_path, False))
        self.assertTrue(os.path.exists(preserved_path))


if __name__ == "__main__":
    unittest.main()
