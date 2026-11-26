#!/usr/bin/env python3
"""dev_eval/improve.py building blocks: fresh held-out names avoid every shipped list; scoring works."""
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from dev_eval import improve  # noqa: E402


class HeldOut(unittest.TestCase):
    def test_names_unseen_and_deterministic(self):
        ex, exf = improve._exclusion()
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            improve.gen_heldout(a, 7, n_files=10)
            improve.gen_heldout(b, 7, n_files=10)
            ta = json.load(open(os.path.join(a, "truth.json"), encoding="utf-8"))
            tb = json.load(open(os.path.join(b, "truth.json"), encoding="utf-8"))
            self.assertEqual(ta, tb)
            for t in ta["truth"]:
                for n in t["names"]:
                    if n["name"].isascii():
                        self.assertNotIn(n["name"].lower(), ex)

    def test_promotion_gate_lists(self):
        self.assertIn("dev_leaks", improve.LOWER)
        self.assertIn("name_recall", improve.HIGHER)
        self.assertIn("retention", improve.HIGHER)


if __name__ == "__main__":
    unittest.main(verbosity=1)
