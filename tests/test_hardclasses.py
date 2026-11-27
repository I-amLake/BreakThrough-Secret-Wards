"""Leak classes from the adversarial 'hardest' round (invented data only)."""
import json, os, subprocess, sys, tempfile, unittest, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from raksha.detect import Detector  # noqa: E402
from raksha.linkage import Linker  # noqa: E402

D = Detector()


def kinds(t):
    return [(s.kind, s.text) for s in D.detect(t)]


class T(unittest.TestCase):
    def test_spelled_ages(self):
        self.assertIn(("AGE", "seventy-three"), kinds("Patient is seventy-three years old."))
        self.assertIn(("AGE", "pachpan"), kinds("Woh pachpan saal ki hain."))
        self.assertIn(("AGE", "छियासठ"), kinds("मरीज़ (छियासठ वर्षीय) आए"))
        self.assertIn(("AGE", "chausath"), kinds("Umar chausath saal"))
        self.assertIn(("AGE", "paisath"), kinds("age paisath years"))
        for t in ("three years back", "do saal se khansi", "for two years now", "Dolo 650 SOS"):
            self.assertFalse([k for k in kinds(t) if k[0] == "AGE"], t)

    def test_holidays(self):
        self.assertIn(("DATE", "Gandhi Jayanti 2023"), kinds("Pain since Gandhi Jayanti 2023."))
        self.assertIn(("EVENT", "Navratri"), kinds("Navratri ke baad se bukhar"))
        self.assertFalse([k for k in kinds("Id card lost") if k[0] in ("DATE", "EVENT")])

    def test_dates_ids(self):
        self.assertIn(("DOB", "02/08/1979"), kinds("DOB:02/08/1979."))
        self.assertIn(("DATE", "07.11.24"), kinds("DOD: 07.11.24"))
        self.assertFalse([k for k in kinds("version 1.2.25") if k[0] == "DATE"])
        self.assertIn(("PAN", "KMQAZ5512H"), kinds("pan no: kmqaz 5512 h"))
        self.assertIn(("PAN", "XYZQB9876C"), kinds("PAN XYZQB9876C"))
        self.assertIn(("PHONE", "9911233445"), kinds("Call 99112-\n33445 today"))
        self.assertFalse([k for k in kinds("Pan-D 1-0-0") if k[0] == "PAN"])

    def test_aliases_and_addresses(self):
        self.assertIn(("NAME", "Bablu"), kinds("Also known as Bablu in the mohalla."))
        self.assertIn(("NAME", "Tinku"), kinds("ghar mein sab Tinku bulate hain"))
        self.assertIn(("ADDRESS", "Shastri Colony, Ajmer"), kinds("Mob 9812312312. Shastri Colony, Ajmer 305001. Rx Telma"))
        self.assertFalse([k for k in kinds("gaon mein log khush hain") if k[0] == "ADDRESS"])

    def test_initial_names_compatible(self):
        L = Linker({})
        self.assertTrue(L._name_pair(("t", "rawat"), ("taracan", "r"))[1])
        self.assertTrue(L._name_pair(("taracan",), ("t", "rawat"))[1])
        self.assertFalse(L._name_pair(("t", "rawat"), ("tulsi", "pande"))[1])

    def test_pipeline_json_parts_doctor_column_attachment(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        with tempfile.TemporaryDirectory() as d:
            inp, out = os.path.join(d, "in"), os.path.join(d, "out")
            os.makedirs(inp)
            json.dump({"records": [{"mrn": "AJM772211", "patient_name": "Kusumlata Solanki",
                                    "dob_parts": {"day": "07", "month": "Sep", "year": "1961"}}]},
                      open(os.path.join(inp, "r.json"), "w"))
            open(os.path.join(inp, "lab.csv"), "w").write("mrn,patient,test,ordered_by\nAJM772211,Kusumlata Solanki,TSH,Dr. Vinay Saxena\n"
                                                          "AJM772299,Omkar Rawat,HbA1c,Dr. Rehana Siddiqui\n")
            att = base64.b64encode(b"Patient: Kusumlata Solanki. Mob 9812312312. Kalyanpur, Jhansi 284001.").decode()
            json.dump({"resourceType": "Bundle", "type": "collection", "entry": [{"resource": {"resourceType": "DocumentReference",
                       "content": [{"attachment": {"contentType": "text/plain", "data": att}}]}}]}, open(os.path.join(inp, "f.json"), "w"))
            subprocess.run([sys.executable, os.path.join(root, "main.py"), "--input", inp, "--output", out, "--quiet"], check=True,
                           env=dict(os.environ, RAKSHA_SECRET="t"))
            allout = ""
            for f in os.listdir(os.path.join(out, "sanitized")):
                allout += open(os.path.join(out, "sanitized", f), encoding="utf-8").read()
            for m in __import__("re").findall(r'"data": "([^"]+)"', allout):
                allout += base64.b64decode(m).decode()
            for leak in ("1961", "Kusumlata", "Jhansi", "9812312312"):
                self.assertNotIn(leak, allout)
            self.assertIn("Dr. Vinay Saxena", allout)
            self.assertIn("Dr. Rehana Siddiqui", allout)


if __name__ == "__main__":
    unittest.main()
