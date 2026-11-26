"""v1.9 leak classes: invisible characters, homoglyphs, percent / entity hiding, obfuscated phones,
data URIs, deep FHIR fields, eponym surnames, unknown names in structural places, malformed-file
quarantine, ID look-alikes. All values are invented for this test."""
import base64, json, os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from raksha.detect import Detector  # noqa: E402
from raksha.ingest import strip_invisible  # noqa: E402

D = Detector()
ROOT = os.path.join(os.path.dirname(__file__), "..")


def kinds(t):
    return [(s.kind, s.text) for s in D.detect(t)]


def run(files):
    d = tempfile.mkdtemp()
    inp, out = os.path.join(d, "in"), os.path.join(d, "out")
    for rel, data in files.items():
        p = os.path.join(inp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    env = dict(os.environ, RAKSHA_SECRET="unit-test-secret")
    subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), "--input", inp, "--output", out], env=env,
                   check=True, capture_output=True)
    blob = []
    for dp, _, fns in os.walk(out):
        for fn in fns:
            blob.append(os.path.relpath(os.path.join(dp, fn), out))
            with open(os.path.join(dp, fn), encoding="utf-8", errors="replace") as fh:
                blob.append(fh.read())
    with open(os.path.join(out, "report.json"), encoding="utf-8") as fh:
        return out, "\n".join(blob), json.load(fh)


class Normalise(unittest.TestCase):
    def test_invisible_homoglyph_hidden(self):
        self.assertEqual(strip_invisible("Gir\u200bdhari 98110\u206055432"), "Girdhari 9811055432")
        self.assertEqual(strip_invisible("Sant\u043esh"), "Santosh")            # Cyrillic o inside a Latin word
        self.assertEqual(strip_invisible("\u041c\u043e\u0441\u043a\u0432\u0430"), "\u041c\u043e\u0441\u043a\u0432\u0430")  # real Cyrillic kept
        self.assertEqual(strip_invisible("n=Ram%2520Lal and 95% SpO2"), "n=Ram Lal and 95% SpO2")
        self.assertEqual(strip_invisible("Sh&#105;v"), "Shiv")


class Phones(unittest.TestCase):
    def test_obfuscated_phones(self):
        for t in ("number 8 1 2 0 3 4 4 5 6 7 hai", "call 8120.344.567", "ph 091-812-034-4567", "mob 81 20 34 45 67",
                  "Mobile: aath ek do shunya teen chaar chaar paanch chhah saat",
                  "\u0906\u0920 \u090f\u0915 \u0926\u094b \u0936\u0942\u0928\u094d\u092f \u0924\u0940\u0928 \u091a\u093e\u0930 \u091a\u093e\u0930 \u092a\u093e\u0901\u091a \u091b\u0939 \u0938\u093e\u0924",
                  "contact 8 - 1 - 2 - 0 - 3 - 4 - 4 - 5 - 6 - 7"):
            self.assertTrue([k for k in kinds(t) if k[0] == "PHONE"], t)

    def test_not_phones(self):
        for t in ("Hb 9.6 TLC 7 8 9", "Tab Dolo 650 1-0-1 x 5 days", "ek do teen char paanch", "BP 120/80 on 12.03.2026"):
            self.assertFalse([k for k in kinds(t) if k[0] == "PHONE"], t)


class Names(unittest.TestCase):
    def test_eponym_surname(self):
        self.assertIn(("NAME", "Leela Graves"), kinds("Patient Name: Leela Graves, 54/F"))
        self.assertIn(("NAME", "KISHORI BELL"), kinds("NAME: KISHORI BELL   Age/Sex: 40 Yrs/F"))
        self.assertFalse([k for k in kinds("K/C/O Graves' disease and Bell's palsy") if k[0] == "NAME"])

    def test_role_and_by_cues(self):
        self.assertIn(("NAME", "Ostrava Pelling"), kinds("caller Ostrava Pelling asked for a copy"))
        self.assertIn(("NAME", "Ostrava Pelling"), kinds("verified by Ostrava Pelling"))
        self.assertFalse([k for k in kinds("VISITOR LOG for ward 5") if k[0] == "NAME"])

    def test_oov_runs(self):
        self.assertTrue(D.oov_proper_runs("notes for Ostrava Pelling"))
        for t in ("Patient Name", "Discharge Summary", "Ward Vitals Sheet", "Lab Results Sitapur District"):
            self.assertFalse(D.oov_proper_runs(t), t)

    def test_lookalikes_kept(self):
        t = "SNOMED CT 234567890123, Batch QX12345678, log 20250412083015, ABHA 91-2345-6789-0123"
        k = kinds(t)
        self.assertFalse([x for x in k if x[0] in ("AADHAAR", "ID") and "234567890123" in x[1]])
        self.assertIn(("ABHA", "91234567890123"), k)


class Pipeline(unittest.TestCase):
    def test_structural_canaries_fhir_and_quarantine(self):
        note = "Patient Tarini Vohra, mobile 8120344567, discharged."
        bundle = {"resourceType": "Bundle", "type": "collection", "entry": [
            {"fullUrl": "urn:uuid:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "resource": {"resourceType": "Patient",
             "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "name": [{"text": "Tarini Vohra"}],
             "text": {"status": "generated", "div": "<div>Tar\u200bini Vohra</div>"},
             "identifier": [{"system": "https://his.example/by-name/tarini-vohra", "value": "QX-77123"}]}},
            {"resource": {"resourceType": "Condition", "code": {"text": "Asthma"},
                          "note": [{"authorString": "Mukund Vohra"}],
                          "contained": [{"resourceType": "RelatedPerson", "id": "k", "name": [{"text": "Mukund Vohra"}]}],
                          "modifierExtension": [{"url": "https://his.example/ext/informant", "valueString": "Mukund"}]}},
            {"resource": {"resourceType": "DocumentReference", "status": "current", "content": [{"attachment": {
                "contentType": "text/plain", "title": "Letter for Tarini Vohra",
                "url": "data:text/plain;base64," + base64.b64encode(note.encode()).decode()}}]}}]}
        out, blob, rep = run({
            "fhir/b.json": json.dumps(bundle),
            "opd/v.json": json.dumps({"visits": [{"visit_date": "14/02/2026", "doctor": "Dr. Mukund Rao",
                                                  "remarks_for_Ostrava Pelling": "call"}]}),
            "lab/p.csv": "sample,test,result,signed_off Brevik Tolland\nS1,Hb,11.4,ok\n",
            "misc/Referral_Ysolde_Marrow.txt": "Referral note, no findings.\n",
            "misc/Quenby_Harrowgate_files/n.txt": "Scan index.\n",
            "misc/nan.json": '{"name": "Tarini Vohra", "spo2": NaN}',
            "misc/dupe.json": '{"name": "Tarini Vohra", "name": "x"}',
            "misc/bad.txt": b"Patient Tarini Vohra \xff\xfe\x00\xc3( 8120344567",
            "misc/json.csv": '{"patient": "Tarini Vohra"}',
        })
        for bad in ("Tarini", "Vohra", "8120344567", "Mukund Vohra", "Ostrava", "Pelling", "Brevik", "Tolland", "Ysolde",
                    "Marrow", "Quenby", "Harrowgate", base64.b64encode(note.encode()).decode()[:20]):
            self.assertNotIn(bad, blob, bad)
        self.assertIn("Dr. Mukund Rao", blob)          # the doctor keeps a name a relative shares
        self.assertNotIn("14/02/2026", blob)           # slash dates in JSON are shifted, not treated as paths
        self.assertEqual(rep["counts"]["files_quarantined"], 4)
        reasons = sorted(e.get("reason") for e in rep["files"] if e["status"] == "quarantined")
        self.assertTrue(all(reasons))


if __name__ == "__main__":
    unittest.main()
