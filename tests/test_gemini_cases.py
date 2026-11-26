"""The --gemini-cases path: validation, graceful skipping, deterministic split, name-model tokens,
and an end-to-end run on the small example file. All cases are invented."""
import json, os, subprocess, sys, tempfile, unittest
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from dev_eval import gemini_cases as G  # noqa: E402

EXAMPLE = os.path.join(ROOT, "dev_eval", "gemini_cases_example.jsonl")
GOOD = {"id": "t1", "format": "txt", "filename": "note.txt",
        "text": "Patient Name: Orvenna Klyst. Mobile 9812044671. Tab Dolo 650 1-0-1",
        "pii": [{"text": "Orvenna Klyst", "type": "PATIENT_NAME"}, {"text": "9812044671", "type": "PHONE"}],
        "must_keep": ["Tab Dolo 650 1-0-1"]}


def line(**kw):
    c = dict(GOOD)
    c.update(kw)
    return json.dumps(c)


class Validate(unittest.TestCase):
    def test_good(self):
        c, why = G.validate_line(1, line())
        self.assertIsNone(why)
        self.assertEqual(c["ext"], ".txt")

    def test_bad_lines_have_reasons(self):
        bad = ["not json", "[1, 2]", line(text=""), line(format="pdf"),
               line(pii=[{"text": "Zzz", "type": "PATIENT_NAME"}]),
               line(pii=[{"text": "Orvenna Klyst", "type": "FAVOURITE_COLOUR"}]),
               line(must_keep=["Tab Dolo 650 1-0-1", "not in text"]),
               line(must_keep=["Orvenna Klyst. Mobile"]),
               line(format="json", text="{broken"), line(pii="Orvenna")]
        for i, b in enumerate(bad):
            c, why = G.validate_line(i + 1, b)
            self.assertIsNone(c, b)
            self.assertTrue(why and why.startswith("line %d" % (i + 1)), why)

    def test_blank_comment_fence_ignored(self):
        for b in ("", "   ", "# note", "```json", "```"):
            self.assertEqual(G.validate_line(1, b), (None, None))

    def test_filename_sanitised(self):
        c, _ = G.validate_line(1, line(filename="../../etc/pass wd.txt"))
        self.assertNotIn("/", c["stem"])
        self.assertNotIn("..", c["stem"])


class LoadSplitTrain(unittest.TestCase):
    def test_example_file(self):
        cases, problems = G.load_cases(EXAMPLE)
        self.assertEqual(len(cases), 8)
        self.assertEqual(len(problems), 2)  # the two deliberately broken lines at the end

    def test_dedupe_and_split_deterministic(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "c.jsonl")
        with open(p, "w") as fh:
            fh.write(line() + "\n" + line() + "\n" + line(id="t2", text=GOOD["text"] + " BP 120/80") + "\n")
        cases, problems = G.load_cases(p)
        self.assertEqual((len(cases), problems), (2, []))
        a, b = G.split(cases)
        self.assertEqual((len(a), len(b)), (1, 1))
        self.assertEqual(G.split(cases), (a, b))

    def test_training_tokens(self):
        c, _ = G.validate_line(1, line())
        toks = dict(G.name_training_tokens([c]))
        self.assertEqual(toks.get("Orvenna"), 1)
        self.assertEqual(toks.get("Klyst"), 1)
        self.assertEqual(toks.get("Dolo"), 0)


class EndToEnd(unittest.TestCase):
    def test_cli_run_on_example(self):
        env = dict(os.environ, PYTHONPATH=ROOT)
        r = subprocess.run([sys.executable, "-m", "dev_eval.gemini_cases", EXAMPLE, "--run"], cwd=ROOT, env=env,
                           capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("valid cases: 8", r.stdout)
        self.assertIn("PII still visible: 0 of", r.stdout)

    def test_improve_rejects_empty_file(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "bad.jsonl")
        with open(p, "w") as fh:
            fh.write("oops\n")
        r = subprocess.run([sys.executable, "-m", "dev_eval.improve", "--rounds", "1", "--gemini-cases", p, "--no-log"],
                           cwd=ROOT, capture_output=True, text=True, timeout=600)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no valid case", r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main()
