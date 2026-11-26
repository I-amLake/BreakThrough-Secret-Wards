#!/usr/bin/env python3
"""Probe tests for leak paths and release hygiene found in external reviews (invented data only).

Each probe writes a tiny input folder, runs main.py and checks the output files one by one.
"""
import base64
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
b64 = lambda s: base64.b64encode(s.encode()).decode()


def run(inp, out, secret="probe", extra_env=None, script=None):
    env = dict(os.environ, RAKSHA_SECRET=secret, **(extra_env or {}))
    return subprocess.run([sys.executable, script or os.path.join(REPO, "main.py"), "--input", inp, "--output", out, "--quiet"],
                          env=env, capture_output=True, text=True, timeout=300)


def outputs(out):
    rep = json.load(open(os.path.join(out, "report.json"), encoding="utf-8"))
    res = {}
    for f in rep["files"]:
        if f["output"]:
            res[f["input_sha256"]] = open(os.path.join(out, f["output"]), encoding="utf-8").read()
    return rep, res


def decoded(text):
    import re
    extra = []
    for m in re.finditer(r"[A-Za-z0-9+/]{8,}={0,2}", text):
        t = m.group(0)
        try:
            extra.append(base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "ignore"))
        except Exception:
            pass
    return text + "\n" + "\n".join(extra)


class Probes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = tempfile.mkdtemp(prefix="probes_")
        cls.inp = os.path.join(cls.w, "in")
        cls.cases = {}  # rel -> (must_not_contain, must_contain)
        def put(rel, content, bad, good=()):
            p = os.path.join(cls.inp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
            cls.cases[rel] = (bad, good)
        put("notes/addr_pin.txt", "Patient: Tevan Orlikar, 52 years, M\nAddress: 14 MG Road, Qorvapur, PIN: 226010\n"
            "Diagnosis: dengue fever. Dolo 650 given.\n", ["Qorvapur", "226010", "Tevan", "Orlikar"], ["dengue", "Dolo 650"])
        put("notes/addr_stay.txt", "Pt. Zevrina ji, W/o Kelvansh. Age: 47 years. Village: Syntalpur. PIN: 226010. "
            "Stay 2024-03-01 to 2024-03-10. Typhoid.\n", ["Syntalpur", "226010", "Zevrina", "Kelvansh"], ["Typhoid"])
        put("notes/short_b64.txt", "Name: Tevan Qosh\nref token OTg3NjUwMTIzNA== and nm VGV2YW4gUW9zaA==\nfever\n",
            ["Tevan", "Qosh", "9876501234"], ["fever"])
        pid = "tevan-orlikar-9876501234"
        bundle = {"resourceType": "Bundle", "type": "collection", "entry": [
            {"fullUrl": "https://hosp.example/Patient/Tevan_Orlikar", "resource": {"resourceType": "Patient", "id": pid,
             "name": [{"given": ["Tevan"], "family": "Orlikar"}], "gender": "male", "birthDate": "1971-04-02",
             "telecom": [{"system": "phone", "value": "9876501234"}]}},
            {"fullUrl": "urn:uuid:4f1c2b9e-1a2b-4c3d-8e9f-0a1b2c3d4e5f", "resource": {"resourceType": "Observation",
             "id": "4f1c2b9e-1a2b-4c3d-8e9f-0a1b2c3d4e5f", "status": "final", "code": {"text": "Haemoglobin"},
             "subject": {"reference": "Patient/" + pid}, "valueQuantity": {"value": 11.2, "unit": "g/dL"}}},
            {"fullUrl": "urn:uuid:bin-1", "resource": {"resourceType": "Binary", "id": "bin-1", "contentType": "text/plain",
             "data": b64("SYNTHa1b2c3d4e5f6")}},
            {"fullUrl": "urn:uuid:bin-2", "resource": {"resourceType": "Binary", "id": "bin-2", "contentType": "image/svg+xml",
             "data": b64("<svg><text>Tevan Orlikar 9876501234</text></svg>")}},
        ]}
        put("fhir/b1.json", json.dumps(bundle, indent=1),
            ["Tevan", "Orlikar", "9876501234", "SYNTHa1b2c3d4e5f6", "1971-04-02"], ["Haemoglobin", "4f1c2b9e-1a2b-4c3d-8e9f-0a1b2c3d4e5f"])
        s = io.StringIO()
        csv.writer(s).writerows([["patient_name", "age", "phone", "referred_by", "village", "diagnosis"],
                                 ["Tevan Orlikar", "52", "9876501234", "Kelvansh (brother), 9812345670", "Syntalpur", "dengue"],
                                 ["Zevrina Dovral", "47", "9876501299", "Dr. Hulvaro Rathvan", "Brindapur", "typhoid"]])
        put("reg/r1.csv", s.getvalue(), ["Tevan", "Orlikar", "9876501234", "9812345670", "Kelvansh", "Syntalpur", "Zevrina"],
            ["dengue", "typhoid"])
        put("reg/r2.csv", "name,age,village_Syntalpur,diagnosis\nPimmo Qarvesh,33,yes,malaria\n", ["Pimmo", "Qarvesh", "Syntalpur"], ["malaria"])
        put("reg/r3.tsv", 'patient_name\tage\theight\tnote\nTevan Orlikar\t52\t5"8\tasthma\n', ["Tevan", "Orlikar"], ["asthma"])
        j = {"records": [{"patient_name": "Tevan Orlikar", "age": 52, "diagnosis": "dengue"}],
             "patient_Zevrina_Dovral": {"diagnosis": "typhoid"}, "patient_SYNTHa1b2c3d4": {"diagnosis": "asthma"},
             "tok": "OTg3NjUwMTIzNA==", "nm": b64("Tevan Orlikar")}
        put("json/j1.json", json.dumps(j, indent=1), ["Tevan", "Orlikar", "Zevrina", "Dovral", "SYNTHa1b2c3d4", "9876501234"],
            ["dengue", "typhoid", "asthma"])
        cls.out = os.path.join(cls.w, "out")
        cls.r = run(cls.inp, cls.out)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.w, ignore_errors=True)

    def test_each_probe(self):
        import hashlib
        self.assertEqual(self.r.returncode, 0, self.r.stderr[-400:])
        rep, outs = outputs(self.out)
        for rel, (bad, good) in self.cases.items():
            sha = hashlib.sha256(open(os.path.join(self.inp, rel), "rb").read()).hexdigest()
            with self.subTest(rel=rel):
                self.assertIn(sha, outs, rel + " was not exported")
                hay = decoded(outs[sha])
                for b in bad:
                    self.assertNotIn(b, hay, rel)
                for g in good:
                    self.assertIn(g, outs[sha], rel)
        for name in os.listdir(os.path.join(self.out, "sanitized", "json")) + os.listdir(os.path.join(self.out, "sanitized", "reg")):
            self.assertNotRegex(name, "Tevan|Orlikar|9876501234")

    def test_report_counts_consistent(self):
        rep = json.load(open(os.path.join(self.out, "report.json")))
        c = rep["counts"]
        self.assertEqual(c["identifiers_detected"], sum(rep["entities"].values()))
        self.assertEqual(c["files_total"], len(rep["files"]))
        self.assertEqual(c["files_sanitized"] + c["files_quarantined"], c["files_total"])
        n = sum(1 for l in open(os.path.join(self.out, "records.jsonl")) if l.strip())
        self.assertEqual(c["records_processed"], n)
        self.assertEqual(c["records_suppressed"], 0)
        st = {json.loads(l).get("status") for l in open(os.path.join(self.out, "records.jsonl")) if l.strip()}
        self.assertNotIn("suppressed", st)


class Probes2(unittest.TestCase):
    """v1.6 probes: date side channels, ages, zero-width joiners, clinical shorthand, address frames, homonyms."""

    @classmethod
    def setUpClass(cls):
        cls.w = tempfile.mkdtemp(prefix="probes2_")
        cls.inp = os.path.join(cls.w, "in")
        os.makedirs(cls.inp)
        def put(rel, txt):
            open(os.path.join(cls.inp, rel), "w", encoding="utf-8").write(txt)
        put("opd_2024-03-05_visit.txt", "Patient: Tevan Orlikar, 47/F, admitted 05/03/2024, discharged 14/03/2024 (Thursday).\n"
            "Patient seen in OPD. (47F) aayu 47 varsh. Temp 101F. K/C/O DM, HTN. H/O CAD. TLC 11,200 /cumm.\n"
            "LOINC 718-7, SNOMED 38341003. Tab Amlodipine 5 mg 1-0-1 x 5 days. Syp 10 ml TDS. १-०-१ खाने के बाद।\n")
        put("zw.txt", "\u0928\u093e\u092e: \u091f\u0947\u200d\u0935\u0928 \u0913\u0930\u200c\u0932\u093f\u0915\u0930\n"
            "\u092e\u0930\u0940\u091c\u093c \u091f\u0947\u200d\u0935\u0928 \u0915\u094b \u092c\u0941\u0916\u093e\u0930\u0964\n")
        put("addr.txt", "Name: Zevrina Dovral\nMareez ka ghar no 56, Tola Pashchim, Brindapur.\n"
            "\u092e\u0915\u093e\u0928 \u0928\u0902. 12, \u091f\u094b\u0932\u093e \u0915\u0932\u0935\u094b, fever.\n"
            "Ghar 3 din se band tha. Referred from Basti district.\n")
        put("homonym.csv", "patient_name,age,sex,father_name,village,diagnosis\n"
            "Qelvo Dramik,52,M,Kelvansh Dramik,Brindapur,dengue\nQelvo Dramik,52,M,Pimmo Dramik,Brindapur,typhoid\n"
            "Qelvo Dramik,53,M,,Brindapur,malaria\n")
        cls.out = os.path.join(cls.w, "out")
        cls.r = run(cls.inp, cls.out)
        cls.rep, cls.outs = outputs(cls.out)
        import hashlib
        cls.by = {rel: cls.outs.get(hashlib.sha256(open(os.path.join(cls.inp, rel), "rb").read()).hexdigest(), "")
                  for rel in os.listdir(cls.inp)}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.w, ignore_errors=True)

    def test_dates_and_ages(self):
        t = self.by["opd_2024-03-05_visit.txt"]
        self.assertNotIn("Thursday", t)
        self.assertNotIn("05/03/2024", t)
        names = [f["output"] for f in self.rep["files"] if f["output"]]
        self.assertFalse(any("2024-03-05" in n for n in names), names)
        # the file-name date moves with the admission date inside the file
        adm = re.search(r"admitted (\d\d)/(\d\d)/(\d{4})", t)
        self.assertTrue(any("%s-%s-%s" % (adm.group(3), adm.group(2), adm.group(1)) in n for n in names), names)
        for bad in ("(47F)", "47 varsh", "47/F"):
            self.assertNotIn(bad, t)

    def test_clinical_shorthand_kept(self):
        t = self.by["opd_2024-03-05_visit.txt"]
        for good in ("Patient seen in OPD", "Temp 101F", "K/C/O DM, HTN", "H/O CAD", "TLC 11,200 /cumm", "LOINC 718-7",
                     "SNOMED 38341003", "5 mg 1-0-1 x 5 days", "10 ml TDS", "\u0967-\u0966-\u0967"):
            self.assertIn(good, t)

    def test_zero_width_joiner_name(self):
        t = self.by["zw.txt"]
        self.assertNotIn("\u0935\u0928 \u0915\u094b", t)   # second half of the split name
        self.assertNotIn("\u091f\u0947", t)

    def test_triggerless_address_frames(self):
        t = self.by["addr.txt"]
        for bad in ("56", "Pashchim", "Brindapur", "\u0915\u0932\u0935\u094b", "Zevrina"):
            self.assertNotIn(bad, t)
        self.assertIn("Ghar 3 din se band tha", t)
        self.assertIn("Basti", t)

    def test_homonym_abstention(self):
        recs = [json.loads(l) for l in open(os.path.join(self.out, "records.jsonl")) if '"homonym' in l or "homonym" in l]
        rows = {r["loc"]: r["patient"] for r in recs}
        self.assertNotEqual(rows["row:0"], rows["row:1"])          # different fathers: different people
        self.assertNotIn(rows["row:2"], (rows["row:0"], rows["row:1"]))  # fits both: abstain


class Release(unittest.TestCase):
    def setUp(self):
        self.w = tempfile.mkdtemp(prefix="rel_")
        self.inp = os.path.join(self.w, "in")
        os.makedirs(self.inp)
        open(os.path.join(self.inp, "a.txt"), "w").write("Patient: Tevan Orlikar\nfever\n")

    def tearDown(self):
        shutil.rmtree(self.w, ignore_errors=True)

    def test_refusals(self):
        nonempty = os.path.join(self.w, "nonempty"); os.makedirs(nonempty); open(os.path.join(nonempty, "x"), "w").close()
        real = os.path.join(self.w, "real"); os.makedirs(real)
        link = os.path.join(self.w, "link"); os.symlink(real, link)
        afile = os.path.join(self.w, "afile"); open(afile, "w").close()
        for out in (nonempty, link, afile, os.path.join(self.inp, "out"), self.w, self.inp):
            r = run(self.inp, out)
            self.assertEqual(r.returncode, 2, out)
        self.assertEqual(os.listdir(real), [])
        self.assertEqual(os.listdir(nonempty), ["x"])

    def test_atomic_release_and_cleanup(self):
        out = os.path.join(self.w, "out")
        self.assertEqual(run(self.inp, out).returncode, 0)
        self.assertEqual(sorted(os.listdir(out)), ["records.jsonl", "report.json", "sanitized"])
        # a failing run leaves no partial output behind
        out2 = os.path.join(self.w, "out2")
        hook = os.path.join(self.w, "fail.py")
        open(hook, "w").write(
            "import sys; sys.path.insert(0, %r)\nimport raksha.pipeline as P\n"
            "def boom(i, o, *a):\n    open(o + '/report.json', 'w').write('partial'); raise RuntimeError()\n"
            "P.run = boom\nimport main\nsys.argv = ['main.py'] + sys.argv[1:]\nsys.exit(main.main())\n" % REPO)
        r = run(self.inp, out2, extra_env={"PYTHONHASHSEED": "0"}, script=hook)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(os.listdir(out2), [])

    def test_symlinks_and_fifos_quarantined_not_followed(self):
        outside = os.path.join(self.w, "outside.txt")
        open(outside, "w").write("Patient: Qelvorin Bhatrak\nsecret outside\n")
        os.symlink(outside, os.path.join(self.inp, "link.txt"))
        if hasattr(os, "mkfifo"):
            os.mkfifo(os.path.join(self.inp, "pipe.txt"))
        out = os.path.join(self.w, "out")
        r = run(self.inp, out)
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.load(open(os.path.join(out, "report.json")))
        q = [f for f in rep["files"] if f["status"] == "quarantined"]
        self.assertEqual(len(q), 2 if hasattr(os, "mkfifo") else 1)
        self.assertTrue(all(f["reason"] == "unsafe_filesystem_entry" for f in q))
        for dp, _, fns in os.walk(out):
            for f in fns:
                self.assertNotIn("Qelvorin", open(os.path.join(dp, f), encoding="utf-8", errors="replace").read())


class HashSeed(unittest.TestCase):
    def test_output_independent_of_hash_seed_without_reexec(self):
        """Determinism comes from the code (sorted tie-breaks), not from main.py's PYTHONHASHSEED re-exec."""
        w = tempfile.mkdtemp(prefix="seed_")
        try:
            inp = os.path.join(w, "in"); os.makedirs(inp)
            open(os.path.join(inp, "n1.txt"), "w").write("Patient: Tevan Orlikar 52/M, adm 03/04/2024, dis 07/04/2024. Dengue.\n"
                                                         "Seen 2024-04-03, follow-up 2025-01-02.\n")
            open(os.path.join(inp, "r.csv"), "w").write("patient_name,age,phone,visit\nTevan Orlikar,52,9876501234,03/04/2024\n"
                                                        "Zevrina Dovral,47,9876501299,12/05/2024\n")
            drv = os.path.join(w, "drv.py")
            open(drv, "w").write("import sys; sys.path.insert(0, %r)\nimport main\nsys.argv = ['main.py'] + sys.argv[1:]\n"
                                 "sys.exit(main.main())\n" % REPO)
            res = []
            for seed in ("1", "2", "12345"):
                out = os.path.join(w, "o" + seed)
                r = run(inp, out, extra_env={"PYTHONHASHSEED": seed}, script=drv)
                self.assertEqual(r.returncode, 0, r.stderr)
                files = {}
                for dp, _, fns in os.walk(os.path.join(out, "sanitized")):
                    for f in fns:
                        files[os.path.relpath(os.path.join(dp, f), out)] = open(os.path.join(dp, f), "rb").read()
                files["records.jsonl"] = open(os.path.join(out, "records.jsonl"), "rb").read()
                res.append(files)
            self.assertEqual(res[0], res[1])
            self.assertEqual(res[0], res[2])
        finally:
            shutil.rmtree(w, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
