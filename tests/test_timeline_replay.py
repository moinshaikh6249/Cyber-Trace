import os
import shutil
import tempfile
import unittest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

from database import db
from main import InvestigationReplayDialog, get_timeline_events


class TestTimelineReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cybertrace_replay_")
        self.db_path = os.path.join(self.temp_dir, "data", "cybertrace.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.original_db_path = db.DATABASE_PATH
        db.DATABASE_PATH = self.db_path
        db.initialize_database()
        db.create_case("CT-REPLAY-001", "Replay Case", "Replay Tester", "", "OPEN")
        db.create_case("CT-REPLAY-002", "Other Case", "Replay Tester", "", "OPEN")
        cases = {case["case_id"]: case["id"] for case in db.get_cases()}
        self.case_id = cases["CT-REPLAY-001"]
        self.other_case_id = cases["CT-REPLAY-002"]

    def tearDown(self):
        db.DATABASE_PATH = self.original_db_path
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def add_evidence(self, case_id, name):
        return db.create_evidence(
            case_id,
            name,
            "synthetic",
            "",
            "",
            "2026-09-09 10:00:00",
        )

    def test_zero_events_for_unknown_case(self):
        replay = InvestigationReplayDialog(999999)
        self.assertEqual(replay.replay_events, [])
        self.assertEqual(replay.progress_label.text(), "Event 0 of 0")
        self.assertFalse(replay.play_button.isEnabled())
        replay.close()

    def test_one_event_starts_at_first_and_disables_navigation(self):
        replay = InvestigationReplayDialog(self.case_id)
        self.assertEqual(len(replay.replay_events), 1)
        self.assertEqual(replay.current_index, 0)
        self.assertIn("Case Created", replay.active_event_label.text())
        self.assertFalse(replay.previous_button.isEnabled())
        self.assertFalse(replay.next_button.isEnabled())
        self.assertIn("Case Management", replay.replay_details.toPlainText())
        replay.close()

    def test_multiple_events_match_shared_timeline_and_playback_controls(self):
        self.add_evidence(self.case_id, "alpha.txt")
        events = get_timeline_events(self.case_id)
        replay = InvestigationReplayDialog(self.case_id)

        self.assertEqual(len(replay.replay_events), len(events))
        self.assertEqual(
            [event["timestamp"] for event in replay.replay_events],
            sorted(event["timestamp"] for event in replay.replay_events),
        )
        self.assertEqual(replay.replay_events, events)
        self.assertEqual(replay.current_index, 0)

        replay.next_event()
        self.assertEqual(replay.current_index, 1)
        replay.previous_event()
        self.assertEqual(replay.current_index, 0)
        replay.reset_replay()
        self.assertEqual(replay.current_index, 0)

        replay.play_replay()
        self.assertTrue(replay.replay_timer.isActive())
        replay.pause_replay()
        self.assertFalse(replay.replay_timer.isActive())
        replay.next_event()
        self.assertIn(replay.replay_events[1]["event"], replay.active_event_label.text())
        self.assertIn(replay.replay_events[1]["details"], replay.replay_details.toPlainText())
        replay.close()

    def test_final_event_stops_and_replay_is_read_only_and_case_scoped(self):
        self.add_evidence(self.case_id, "alpha.txt")
        self.add_evidence(self.other_case_id, "other.txt")
        events_before = get_timeline_events(self.case_id)
        connection = db.get_connection()
        before = connection.total_changes
        replay = InvestigationReplayDialog(self.case_id)
        for _ in range(len(replay.replay_events) + 2):
            replay.next_event()
        self.assertEqual(replay.current_index, len(replay.replay_events) - 1)
        self.assertFalse(replay.replay_timer.isActive())
        self.assertEqual(connection.total_changes, before)
        self.assertEqual(get_timeline_events(self.case_id), events_before)
        self.assertNotIn("other.txt", "\n".join(event["details"] for event in replay.replay_events))
        replay.close()
        connection.close()

    def test_close_stops_timer_and_reopen_starts_clean(self):
        self.add_evidence(self.case_id, "timer.txt")
        replay = InvestigationReplayDialog(self.case_id)
        replay.play_replay()
        self.assertTrue(replay.replay_timer.isActive())
        replay.pause_replay()
        self.assertFalse(replay.replay_timer.isActive())
        replay.play_replay()
        self.assertTrue(replay.replay_timer.isActive())
        replay.close()
        self.assertFalse(replay.replay_timer.isActive())

        reopened = InvestigationReplayDialog(self.case_id)
        self.assertFalse(reopened.replay_timer.isActive())
        reopened.close()


if __name__ == "__main__":
    unittest.main()
