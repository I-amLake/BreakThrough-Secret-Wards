#!/usr/bin/env python3
"""The pipeline (main.py + raksha/) never touches evaluation material.

1. Static: no runtime module imports dev_eval/ or names an answer-key / attacker file.
2. Dynamic: run main.py under a sys.addaudithook that records every file opened; none may be an
   answer key, attacker registry or dev_eval script, and nothing outside the repo, the input, the
   output and the Python installation is opened.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORBIDDEN = re.compile(r"truth\.json|registry\.csv|known_facts|/attacker/|dev_eval")

HOOK = r'''
import os, sys
log = open(sys.argv[1], "w")
def hook(ev, args):
    if ev == "open" and args and isinstance(args[0], (str, bytes)):
        p = args[0].decode() if isinstance(args[0], bytes) else args[0]
        log.write(os.path.abspath(p) + "\n"); log.flush()
sys.addaudithook(hook)
repo = sys.argv[2]
sys.path.insert(0, repo)
sys.argv = [os.path.join(repo, "main.py"), "--input", sys.argv[3], "--output", sys.argv[4], "--quiet"]
import main as m
sys.exit(m.main())
'''


class Isolation(unittest.TestCase):
    def test_static_no_eval_material(self):
        files = [os.path.join(REPO, "main.py")]
        for dp, _, fns in os.walk(os.path.join(REPO, "raksha")):
            files += [os.path.join(dp, f) for f in fns if f.endswith(".py")]
        for f in files:
            with open(f, encoding="utf-8") as fh:
                src = fh.read()
            self.assertIsNone(FORBIDDEN.search(src), f)
            self.assertNotRegex(src, r"(?m)^\s*(from|import)\s+(dev_eval|scripts)\b", f)

    def test_runtime_opens_no_eval_material(self):
        with tempfile.TemporaryDirectory(prefix="iso_") as w:
            inp, out = os.path.join(w, "in"), os.path.join(w, "out")
            os.makedirs(os.path.join(inp, "notes"))
            with open(os.path.join(inp, "notes", "n1.txt"), "w", encoding="utf-8") as fh:
                fh.write("Patient: Tevan Orlikar, 52 years, M\nPh 9876501234. Dengue, Dolo 650.\n")
            with open(os.path.join(inp, "reg.csv"), "w", encoding="utf-8") as fh:
                fh.write("patient_name,age,phone,diagnosis\nTevan Orlikar,52,9876501234,dengue\n")
            log = os.path.join(w, "opened.txt")
            hook = os.path.join(w, "hook.py")
            with open(hook, "w", encoding="utf-8") as fh:
                fh.write(HOOK)
            env = dict(os.environ, RAKSHA_SECRET="iso-test", PYTHONHASHSEED="0")
            r = subprocess.run([sys.executable, hook, log, REPO, inp, out], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            with open(log, encoding="utf-8") as fh:
                opened = [l.strip() for l in fh if l.strip()]
            self.assertTrue(any(p.startswith(inp) for p in opened))
            stdlib_dir = os.path.realpath(os.path.dirname(os.__file__))
            allowed = [os.path.realpath(REPO), os.path.realpath(w), w, REPO, sys.prefix, sys.base_prefix,
                       os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix), stdlib_dir,
                       "/usr", "/lib", "/etc", "/proc", "/dev"]
            for p in opened:
                self.assertIsNone(FORBIDDEN.search(p), p)
                self.assertTrue(any(p.startswith(a) for a in allowed), "unexpected open: " + p)


if __name__ == "__main__":
    unittest.main()
