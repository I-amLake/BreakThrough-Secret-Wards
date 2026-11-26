#!/usr/bin/env python3
"""Stigma Shield tests (invented data only): detector, honey generator, planner escalation, facility
removal, the honey-PII self-check counters and determinism."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from raksha import stigma  # noqa: E402
from raksha.config import load_policy  # noqa: E402
from raksha.privacy import Planner  # noqa: E402

DEMO = os.path.join(REPO, "dev_eval", "demo_stigma")


def run(inp, out, secret="stigma-test"):
    env = dict(os.environ, RAKSHA_SECRET=secret)
    return subprocess.run([sys.executable, os.path.join(REPO, "main.py"), "--input", inp, "--output", out, "--quiet"],
                          env=env, capture_output=True, text=True, timeout=300)


class Detector(unittest.TestCase):
    def test_categories_three_scripts(self):
        cases = {
            "K/C/O HIV, on ART since 2 yrs": "HIV", "PLHIV registered at ICTC": "HIV", "HIV+ male": "HIV",
            "एचआईवी पॉजिटिव": "HIV", "Pulmonary TB on ATT": "TB", "तपेदिक का इलाज": "TB",
            "H/O suicide attempt": "MENTAL", "manasik rog ka ilaj": "MENTAL", "मानसिक रोग": "MENTAL",
            "MTP done": "MTP", "garbhpaat hua tha": "MTP", "गर्भपात": "MTP",
            "POCSO case": "ASSAULT", "balatkar ki report": "ASSAULT", "बलात्कार": "ASSAULT",
            "Hansen's disease, MB-MDT": "LEPROSY", "कुष्ठ रोग": "LEPROSY",
            "nasha mukti kendra": "SUBSTANCE", "alcohol dependence syndrome": "SUBSTANCE", "नशा मुक्ति": "SUBSTANCE",
            "ling parikshan karaya": "SEXDET", "PCPNDT form": "SEXDET", "लिंग परीक्षण": "SEXDET",
        }
        for text, cat in cases.items():
            self.assertIn(cat, stigma.categories(text), text)

    def test_negation_and_ordinary_text(self):
        for text in ("HIV negative", "HIV 1&2 non-reactive", "no h/o TB", "Patient not HIV reactive",
                     "Dengue fever, NS1 positive", "art of breathing", "Tab Dolo 650", "attention", "rapeseed oil",
                     "spontaneous miscarriage"):
            self.assertEqual(stigma.categories(text), (), text)

    def test_facility_names(self):
        t, n = stigma.strip_facilities("Referred to ART Centre, Govt Medical College Rampur for CD4 count.")
        self.assertEqual(n, 1)
        self.assertIn("ART Centre, [FACILITY] for CD4 count", t)
        t, n = stigma.strip_facilities("Admitted under Medicine, Govt Medical College Rampur.")
        self.assertEqual(n, 0)


class HoneyValues(unittest.TestCase):
    def test_shapes_and_determinism(self):
        h1, h2 = stigma.Honey(b"k", "file"), stigma.Honey(b"k", "file")
        a = h1.digits_like("2345 6789 0123", "AADHAAR")
        self.assertEqual(a, h2.digits_like("2345 6789 0123", "AADHAAR"))
        d = a.replace(" ", "")
        self.assertEqual(len(d), 12)
        self.assertEqual(stigma.verhoeff_digit(d[:11]), d[11])
        self.assertIn(d[0], "23456789")
        p = h1.digits_like("98765 01234", "PHONE").replace(" ", "")
        self.assertEqual(len(p), 10)
        self.assertIn(p[0], "6789")
        n = h1.name_like("Tevan Orlikar")
        self.assertEqual(len(n.split()), 2)
        self.assertTrue(all(w[0].isupper() for w in n.split()))
        self.assertTrue(any("\u0900" <= c <= "\u097f" for c in h1.name_like("टेवन")))
        self.assertNotEqual(stigma.Honey(b"other", "file").digits_like("2345 6789 0123", "AADHAAR"), a)


class PlannerEscalation(unittest.TestCase):
    def test_stigma_patients_get_wider_band_and_state(self):
        pol = load_policy(REPO)
        pats = []
        for i in range(6):   # six alike patients in one district: k=5 holds at level 0
            pats.append({"pkey": "p%d" % i, "amin": 34, "amax": 34, "sex": "M", "district": "dist", "state": "st",
                         "pin": None, "dx": {"common"}, "los": (), "stigma": ()})
        pats.append({"pkey": "hiv", "amin": 34, "amax": 34, "sex": "M", "district": "other", "state": "st",
                     "pin": None, "dx": {"common"}, "los": (), "stigma": ("HIV",)})
        pats.append({"pkey": "tb", "amin": 34, "amax": 34, "sex": "M", "district": "dist", "state": "st",
                     "pin": None, "dx": {"common"}, "los": (), "stigma": ("TB",)})
        pl = Planner(pol)
        lv = pl.plan(pats)
        self.assertEqual(lv["p0"], 0)
        self.assertGreaterEqual(lv["tb"], 1)              # every stigmatised patient: at least 20-year bands
        self.assertIn("hiv", pl.suppressed)               # statutory category alone in its district -> state only
        self.assertNotIn("tb", pl.suppressed)             # TB (notifiable) keeps the district


class SelfcheckFindings(unittest.TestCase):
    """Detector gaps the honey-PII self-check surfaced on invented data, now fixed."""

    @classmethod
    def setUpClass(cls):
        from raksha.detect import Detector as D
        cls.d = D()

    def names(self, t):
        return [s.text for s in self.d.detect(t) if s.kind == "NAME"]

    def test_devanagari_name_ending_in_da_is_not_a_doctor_title(self):
        self.assertIn("सिलाडा रोदाहे", self.names("नाम: सिलाडा रोदाहे   आयु: 34 वर्ष"))
        self.assertTrue(any(s.kind == "DOCTOR" for s in self.d.detect("डॉ. शर्मा ने देखा")))

    def test_age_sex_bracket_frame(self):
        self.assertIn("Kaneshrait", self.names("Kaneshrait (54/M), H.No 3, Rampur"))
        self.assertEqual(self.names("Dengue Fever (34/M)"), [])

    def test_coordinated_name(self):
        self.assertIn("Chakaav", self.names("Explained the procedure to Ramesh and Chakaav."))
        self.assertEqual(self.names("Advised CBC and LFT"), [])

    def test_district_word_not_split(self):
        from raksha.detect import RX_DISTRICT
        self.assertEqual(RX_DISTRICT.search("Ward 4, District Bahraich").group(1), "Bahraich")
        self.assertEqual(RX_DISTRICT.search("Distt. Gonda").group(1), "Gonda")


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = tempfile.mkdtemp(prefix="stigma_")
        cls.out = os.path.join(cls.w, "out")
        r = run(DEMO, cls.out)
        assert r.returncode == 0, r.stderr
        cls.rep = json.load(open(os.path.join(cls.out, "report.json"), encoding="utf-8"))
        cls.txt = {}
        for f in cls.rep["files"]:
            body = open(os.path.join(cls.out, f["output"]), encoding="utf-8").read()
            cls.txt["hiv" if "HIV" in body else "control"] = body

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.w, ignore_errors=True)

    def test_identifiers_gone_clinical_kept(self):
        for body in self.txt.values():
            for bad in ("Orlikar", "Velkaar", "Tevan", "Mirela", "Joran", "Sabeli", "9876501234", "9123405678",
                        "3847 2915 6039", "5291 8364 0719", "271801", "Kesarganj"):
                self.assertNotIn(bad, body)
        h = self.txt["hiv"]
        for good in ("HIV", "on ART since", "ART Centre", "CD4 count 412", "TLD 1-0-0"):
            self.assertIn(good, h)

    def test_shield_only_for_stigmatised_patient(self):
        h, c = self.txt["hiv"], self.txt["control"]
        self.assertIn("[FACILITY]", h)
        self.assertNotIn("Bahraich", h)                    # facility and district both coarsened
        self.assertIn("Uttar Pradesh", h)                  # state stays
        self.assertIn("Govt Medical College Bahraich", c)  # the control patient keeps them
        self.assertIn("Age: 20-39", c)
        self.assertNotIn("Age: 20-39", h)                  # wider band for the HIV patient

    def test_report_counts(self):
        s = self.rep["stigma_shield"]
        self.assertEqual(s["patients_flagged"], 1)
        self.assertEqual(s["facility_names_removed"], 1)
        self.assertEqual(s["selfcheck_files"], 1)
        self.assertGreater(s["selfcheck_planted"], 3)
        self.assertEqual(s["selfcheck_caught"], s["selfcheck_planted"])
        self.assertEqual(s["files_requarantined"], 0)
        self.assertTrue(all(isinstance(v, int) for v in s.values()))
        self.assertEqual(self.rep["counts"]["identifiers_detected"], sum(self.rep["entities"].values()))

    def test_deterministic(self):
        out2 = os.path.join(self.w, "out2")
        self.assertEqual(run(DEMO, out2).returncode, 0)
        for f in self.rep["files"]:
            a = open(os.path.join(self.out, f["output"]), "rb").read()
            b = open(os.path.join(out2, f["output"]), "rb").read()
            self.assertEqual(a, b)
        r2 = json.load(open(os.path.join(out2, "report.json"), encoding="utf-8"))
        self.assertEqual(r2["stigma_shield"], self.rep["stigma_shield"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
