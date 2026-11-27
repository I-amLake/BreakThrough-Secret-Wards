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

    def test_mixed_separator_phones(self):
        for t in ("Call 98.11-20 44 67 tomorrow", "mob 73/20/18/44/90", "ph 98112/04467",
                  "WhatsApp +91 98/1120/4467", "contact (981) 120-4467", "wa 98\u201311\u201320\u201344\u201367"):
            self.assertTrue([k for k in kinds(t) if k[0] == "PHONE"], t)
        for t in ("BP 120/80", "seen on 12/03/2024", "dose 6-8-10 hourly", "Temp 98.6 F", "Hb 10.2 g/dL",
                  "version 1.2.3.4", "RBS 98.4 then 97.8"):
            self.assertFalse([k for k in kinds(t) if k[0] == "PHONE"], t)


class Identifiers(unittest.TestCase):
    def test_units_are_not_licence_labels(self):
        for unit in ("g/dL", "mg/dL", "g/dl", "mg/dl"):
            text = "Haemoglobin 8.6 %s. Random Blood Sugar 235 mg/dL." % unit
            self.assertFalse([s for s in D.detect(text) if s.kind == "ID"], text)
        from raksha.detect import RX_GOV_LABELLED
        self.assertIsNone(RX_GOV_LABELLED.search("Passport Random Blood Sugar 235"))
        match = RX_GOV_LABELLED.search("DL MH12 20110012345 issued")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "MH12 20110012345")

    def test_full_upi_capture_and_nonlinking_metadata(self):
        for handle in ("abcdef@custombank", "abcd.efgh@custombank", "merchant@okaxis"):
            text = "UPI " + handle + " paid"
            spans = [s for s in D.detect(text) if s.kind == "EMAIL"]
            self.assertEqual(len(spans), 1, text)
            self.assertEqual(spans[0].text, handle)
            self.assertEqual(text[spans[0].start:spans[0].end], handle)
            self.assertTrue(spans[0].meta.get("nolink"))

    def test_ipv4_boundaries(self):
        from raksha.detect import _RX_IPV4
        self.assertIsNone(_RX_IPV4.search("IP 192.168.1.24.5"))
        self.assertIsNone(_RX_IPV4.search("prefix192.168.1.24suffix"))
        text = "From 203.0.113.44."
        spans = [s for s in D.detect(text) if s.kind == "ID"]
        self.assertEqual([s.text for s in spans], ["203.0.113.44"])
        self.assertTrue(spans[0].meta.get("nolink"))

    def test_clinical_decimal_readings(self):
        for text in ("98.12 10.44 67", "Serial glucose readings: 98.12 10.44 67"):
            self.assertFalse([s for s in D.detect(text) if s.kind == "PHONE"], text)
        self.assertIn(("PHONE", "9812104467"), kinds("Phone: 98.12 10.44 67"))

    def test_nolink_blocks_all_identity_evidence(self):
        from raksha.core import Unit, spans_evidence
        from raksha.detect import Span
        cases = {"PHONE": "9876543210", "AADHAAR": "234567890128",
                 "ABHA": "91234567890123", "PAN": "ABCDE1234F",
                 "EMAIL": "shared@example.invalid", "MRN": "MRN12345",
                 "ID": "4532015112830366", "INSURANCE": "POL12345"}
        for kind, value in cases.items():
            unit = Unit("doc", "hospital")
            spans_evidence(unit, value, [Span(0, len(value), kind, value, meta={"nolink": True})])
            self.assertFalse(unit.prof.phones, kind)
            self.assertFalse(any(unit.prof.ids.values()), kind)

    def test_format_bent_ids(self):
        self.assertIn(("AADHAAR", "234567890128"), kinds("UID 2345.6789.0128"))
        self.assertTrue([k for k in kinds("UPI id n.keldra@okaxis paid") if k[0] == "EMAIL" and "keldra@okaxis" in k[1]])
        self.assertTrue([k for k in kinds("nira [at] example [dot] in") if k[0] == "EMAIL" and k[1] == "nira@example.in"])
        self.assertFalse([k for k in kinds("pain at night. reviewed at OPD.") if k[0] == "EMAIL"])
        self.assertTrue([k for k in kinds("brought in car RJ14KQ4491") if k[0] == "ID" and "RJ14KQ4491" in k[1]])
        self.assertTrue([k for k in kinds("22 BH 4412 AA parked") if k[0] == "ID"])
        self.assertTrue([k for k in kinds("logged from 203.0.113.44") if k[0] == "ID" and k[1] == "203.0.113.44"])
        self.assertTrue([k for k in kinds("From 203.0.113.44.") if k[0] == "ID" and k[1] == "203.0.113.44"])
        self.assertFalse([k for k in kinds("version 1.2.3.4 of the form") if k[0] == "ID"])
        self.assertTrue([k for k in kinds("GSTIN 27AAPFU0939F1ZV on the bill") if k[0] == "ID" and "27AAPFU0939F1ZV" in k[1]])
        card = [k for k in kinds("card 4111 1111 1111 1111") if k[0] == "ID"]
        self.assertTrue(card and card[0][1] == "4111111111111111")
        dotted = [k for k in kinds("card 4111.1111.1111.1111 exp") if k[0] == "ID"]
        self.assertTrue(dotted and dotted[0][1] == "4111111111111111", dotted)
        self.assertFalse([k for k in kinds("not a card 4111 1111 1111 1112") if k[0] == "ID" and k[1] == "4111111111111112"])
        dl = kinds("DL MH12 20110012345 issued in 2011")
        self.assertTrue(any(k[0] == "ID" and "MH12" in k[1] and "20110012345" in k[1] for k in dl), dl)
        for t in ("HR 26, RR 18, BP 110/70", "OD 1 tab", "Tab Dolo 650 1-0-1", "SNOMED CT 234567890123",
                  "Batch MH12AB1234", "K/C/O Bell's palsy", "three years back", "pain at night. reviewed at OPD."):
            self.assertFalse([k for k in kinds(t) if k[0] in ("PHONE", "ID", "EMAIL", "AADHAAR")], t)


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
            "misc/edge.txt": "Umar chausath saal. Tab Dolo 650 1-0-1. BP 120/80. Hb 10.2 g/dL. K/C/O Bell's palsy.\n"
                             "Phone 98.11-20 44 67. UPI n.keldra@okaxis. Mail nira [at] example [dot] in.\n"
                             "Vehicle RJ14KQ4491. From 203.0.113.44. GSTIN 27AAPFU0939F1ZV.\n"
                             "UID 2345.6789.0128. Card 4111 1111 1111 1111. DL MH12 20110012345.\n"
                             "Dr. Meher Kulkarni reviewed.\n",
        })
        for bad in ("Tarini", "Vohra", "8120344567", "Mukund Vohra", "Ostrava", "Pelling", "Brevik", "Tolland", "Ysolde",
                    "Marrow", "Quenby", "Harrowgate", base64.b64encode(note.encode()).decode()[:20]):
            self.assertNotIn(bad, blob, bad)
        self.assertIn("Dr. Mukund Rao", blob)          # the doctor keeps a name a relative shares
        for leak in ("98.11-20", "9811204467", "keldra", "nira@example", "RJ14KQ4491", "203.0.113.44",
                     "27AAPFU0939F1ZV", "2345.6789.0128", "4111 1111", "4111111111111111", "chausath",
                     "MH12 20110012345", "20110012345"):
            self.assertNotIn(leak, blob, leak)
        for keep in ("Dolo", "1-0-1", "120/80", "10.2", "Bell's palsy", "Dr. Meher Kulkarni"):
            self.assertIn(keep, blob, keep)
        self.assertNotIn("14/02/2026", blob)           # slash dates in JSON are shifted, not treated as paths
        self.assertEqual(rep["counts"]["files_quarantined"], 4)
        reasons = [e.get("reason") for e in rep["files"] if e["status"] == "quarantined"]
        self.assertEqual(len(reasons), 4)
        self.assertTrue(all(reasons))

    def test_shared_facility_ids_do_not_link(self):
        # a hospital GSTIN and an ambulance plate are on many records; they must not merge patients
        out, blob, rep = run({
            "a.txt": "Dengue. Tab Dolo 650 1-0-1. GSTIN 27AAPFU0939F1ZV. Vehicle RJ14KQ4491.\n",
            "b.txt": "Malaria. Tab Dolo 650 1-0-1. GSTIN 27AAPFU0939F1ZV. Vehicle RJ14KQ4491.\n",
        })
        recs = [json.loads(line) for line in blob.splitlines() if line.startswith('{"file":')]
        self.assertEqual(len(recs), 2)
        psns = [r.get("patient") for r in recs]
        self.assertFalse(psns[0] and psns[0] == psns[1])
        self.assertNotIn("27AAPFU0939F1ZV", blob)
        self.assertNotIn("RJ14KQ4491", blob)
        self.assertIn("Dengue", blob)
        self.assertIn("Malaria", blob)

    def test_shared_payment_identifiers_do_not_link(self):
        from pathlib import Path
        from raksha.core import Unit, spans_evidence
        for identifier, raw in (("UPI merchant@okaxis", "merchant@okaxis"),
                                ("UPI abcdef@custombank", "abcdef@custombank"),
                                ("Card 4532 0151 1283 0366", "4532 0151 1283 0366")):
            spans = D.detect(identifier)
            self.assertTrue(any(s.meta.get("nolink") for s in spans), identifier)
            unit = Unit("doc", "hospital")
            spans_evidence(unit, identifier, spans)
            self.assertFalse(any(unit.prof.ids.values()), identifier)
            out, blob, rep = run({
                "a.txt": "Patient: Kavya Mishra. Dengue. " + identifier,
                "b.txt": "Patient: Kavya Mishra. Malaria. " + identifier,
            })
            records = [json.loads(line) for line in Path(out, "records.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), 2)
            left, right = (record.get("patient") for record in records)
            self.assertFalse(left and left == right, identifier)
            self.assertNotIn(raw, blob)
            if "@" in raw:
                self.assertNotIn(raw.split("@")[0], blob)
            for keep in ("Dengue", "Malaria"):
                self.assertIn(keep, blob)

    def test_clinical_units_survive_export(self):
        clinical = "Haemoglobin 8.6 g/dL. Random Blood Sugar 235 mg/dL."
        out, blob, rep = run({"note.txt": clinical})
        self.assertIn(clinical, blob)


if __name__ == "__main__":
    unittest.main()
