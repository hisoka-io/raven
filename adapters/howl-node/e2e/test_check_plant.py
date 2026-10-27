#!/usr/bin/env python3
"""check-plant.py must pass a red caused by the planted row and refuse every other red."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

# the checker is loaded from a file path; keep the tree free of a bytecode cache
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check-plant.py")
spec = importlib.util.spec_from_file_location("check_plant", SCRIPT)
check_plant = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_plant)

ASSET = "0x0B306BF915C4d645ff596e518fAf3F9669b97016"


def missing(step, leaf):
    return {"step": step, "label": "a deposit", "agent": "alice",
            "missing": [f"{leaf}:0x29ef:1341:{ASSET}:U:self"], "extra": []}


def solvency(step):
    return {"step": step, "label": "a deposit", "asset": ASSET, "notes": "0", "memos": "0", "held": "1"}


class CheckPlant(unittest.TestCase):
    def run_script(self, rows, planted):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "mismatches.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(json.dumps(r) + "\n" for r in rows)
            return subprocess.run([sys.executable, SCRIPT, path, str(planted)],
                                  capture_output=True, text=True).returncode

    def test_plant_only_passes(self):
        self.assertEqual(self.run_script([missing(1, 1), solvency(1), missing(2, 1), solvency(2)], 1), 0)

    def test_another_leaf_fails(self):
        self.assertEqual(self.run_script([missing(1, 1), missing(2, 3)], 1), 1)

    def test_extra_note_fails(self):
        row = missing(1, 1)
        row["extra"] = [f"4:0xab:1:{ASSET}:U:self"]
        self.assertEqual(self.run_script([row], 1), 1)

    def test_other_mismatch_kind_fails(self):
        reorg = {"step": 9, "label": "reorg: shorter chain not followed", "agent": "bob", "want": 3, "got": "5"}
        self.assertEqual(self.run_script([missing(1, 1), reorg], 1), 1)

    def test_solvency_alone_fails(self):
        self.assertEqual(self.run_script([solvency(1)], 1), 1)

    def test_empty_fails(self):
        self.assertEqual(self.run_script([], 1), 1)

    def test_no_file_fails(self):
        r = subprocess.run([sys.executable, SCRIPT, os.path.join(HERE, "absent.jsonl"), "1"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)

    def test_leaf_parse(self):
        self.assertEqual(check_plant.leaf_of("70001:0x1:2:0x3:U:self"), 70001)


if __name__ == "__main__":
    unittest.main()
