import os
import shutil
import tempfile
import unittest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

from database import db
from main import RelationshipGraphDialog


class TestRelationshipGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="cybertrace_graph_")
        self.db_path = os.path.join(self.temp_dir, "data", "cybertrace.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.original_db_path = db.DATABASE_PATH
        db.DATABASE_PATH = self.db_path
        db.initialize_database()
        db.create_case("CT-GRAPH-001", "Graph Case", "Tester", "", "OPEN")
        db.create_case("CT-GRAPH-002", "Other Case", "Tester", "", "OPEN")
        cases = {case["case_id"]: case["id"] for case in db.get_cases()}
        self.case_id = cases["CT-GRAPH-001"]
        self.other_case_id = cases["CT-GRAPH-002"]

    def tearDown(self):
        db.DATABASE_PATH = self.original_db_path
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def evidence(self, case_id, name):
        return db.create_evidence(
            case_id,
            name,
            "synthetic",
            "",
            "",
            "2026-09-09 10:00:00",
        )

    def finding(self, first, second, index, label):
        return {
            "evidence_a_id": min(first, second),
            "evidence_b_id": max(first, second),
            "relationship_type": f"Relationship {index}",
            "indicator_type": "synthetic",
            "indicator_fingerprint": f"fingerprint-{index}",
            "indicator_value": f"indicator-{index}",
            "strength_score": {"Strongest Deterministic": 100, "Moderate": 70, "Contextual": 45, "Weak": 20}[label],
            "strength_label": label,
            "explanation": f"Explanation {index}",
            "detected_at": "2026-09-09 11:00:00",
        }

    def test_zero_evidence_empty_state(self):
        graph = RelationshipGraphDialog(self.case_id)
        self.assertEqual(graph.node_items, {})
        self.assertIn("No evidence items are available", graph.status_label.text())
        graph.close()

    def test_one_node_and_no_relationships(self):
        evidence_id = self.evidence(self.case_id, "single.txt")
        graph = RelationshipGraphDialog(self.case_id)
        self.assertEqual(set(graph.node_items), {evidence_id})
        self.assertEqual(graph.edge_items, {})
        self.assertEqual(graph.relationship_stat_value.text(), "0")
        self.assertIn("No cross-evidence relationships recorded", graph.status_label.text())
        graph.close()

    def test_four_nodes_use_stable_layout_and_render_metadata(self):
        evidence_ids = [
            self.evidence(self.case_id, f"evidence-{index}.txt")
            for index in range(4)
        ]
        graph = RelationshipGraphDialog(self.case_id)
        self.assertEqual(set(graph.node_items), set(evidence_ids))
        positions = [node.pos() for node in graph.node_items.values()]
        self.assertEqual(len(set((point.x(), point.y()) for point in positions)), 4)
        for evidence_id, node in graph.node_items.items():
            self.assertEqual(node.evidence["id"], evidence_id)
            self.assertIn("evidence-", node.evidence["evidence_name"])
            self.assertGreater(node.boundingRect().width(), 240)
            self.assertGreater(node.boundingRect().height(), 120)
        graph.close()

    def test_relationship_stat_counts_grouped_edges(self):
        first = self.evidence(self.case_id, "first.txt")
        second = self.evidence(self.case_id, "second.txt")
        third = self.evidence(self.case_id, "third.txt")
        db.replace_correlation_findings(
            self.case_id,
            [
                self.finding(first, second, 1, "Contextual"),
                self.finding(first, third, 2, "Contextual"),
                self.finding(second, third, 3, "Contextual"),
            ],
        )
        graph = RelationshipGraphDialog(self.case_id)
        self.assertEqual(len(graph.node_items), 3)
        self.assertEqual(len(graph.edge_items), 3)
        self.assertEqual(graph.relationship_stat_value.text(), "3")
        self.assertIn("3 grouped relationship(s) shown.", graph.status_label.text())
        graph.close()

    def test_nodes_edges_grouping_case_isolation_and_details(self):
        first = self.evidence(self.case_id, "first.txt")
        second = self.evidence(self.case_id, "second.txt")
        isolated = self.evidence(self.case_id, "isolated.txt")
        other_first = self.evidence(self.other_case_id, "other-a.txt")
        other_second = self.evidence(self.other_case_id, "other-b.txt")

        findings = [
            self.finding(first, second, 1, "Strongest Deterministic"),
            self.finding(first, second, 2, "Moderate"),
            self.finding(first, second, 3, "Contextual"),
            self.finding(first, second, 4, "Weak"),
            self.finding(other_first, other_second, 5, "Moderate"),
        ]
        db.replace_correlation_findings(self.case_id, findings[:4])
        db.replace_correlation_findings(self.other_case_id, [findings[4]])

        before = db.get_connection().total_changes
        graph = RelationshipGraphDialog(self.case_id)
        after = db.get_connection().total_changes
        self.assertEqual(before, after)
        self.assertEqual(set(graph.node_items), {first, second, isolated})
        for node in graph.node_items.values():
            self.assertEqual(node.boundingRect().size(), node.graph_dialog.node_rect(node).size())
            self.assertGreater(node.boundingRect().width(), 240)
            self.assertGreater(node.boundingRect().height(), 120)
        self.assertEqual(set(graph.edge_items), {(min(first, second), max(first, second))})
        self.assertEqual(graph.relationship_stat_value.text(), "1")
        edge = next(iter(graph.edge_items.values()))
        self.assertEqual(len(edge.findings), 4)
        label = graph.edge_labels[(min(first, second), max(first, second))]
        midpoint = edge.line().pointAt(0.5)
        self.assertNotEqual(label.pos(), midpoint)
        self.assertNotEqual(
            label.pos(),
            graph.node_items[first].boundingRect().center() + graph.node_items[first].pos(),
        )
        self.assertEqual(
            {finding["strength_label"] for finding in edge.findings},
            {"Strongest Deterministic", "Moderate", "Contextual", "Weak"},
        )
        graph.show_edge_details(edge)
        details = graph.details.toPlainText()
        for expected in ("Relationship 1", "indicator-2", "Moderate", "Explanation 3", "2026-09-09 11:00:00"):
            self.assertIn(expected, details)

        graph.node_items[first].setSelected(True)
        self.app.processEvents()
        self.assertIn("first.txt", graph.details.toPlainText())
        self.assertIn("Verification status:", graph.details.toPlainText())
        graph.close()

    def test_graph_does_not_run_correlation_or_write_database(self):
        first = self.evidence(self.case_id, "first.txt")
        second = self.evidence(self.case_id, "second.txt")
        db.replace_correlation_findings(
            self.case_id,
            [self.finding(first, second, 1, "Contextual")],
        )
        connection = db.get_connection()
        before = connection.total_changes
        graph = RelationshipGraphDialog(self.case_id)
        self.assertEqual(connection.total_changes, before)
        self.assertEqual(len(graph.findings), 1)
        graph.close()
        connection.close()


if __name__ == "__main__":
    unittest.main()
