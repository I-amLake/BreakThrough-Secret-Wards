#!/usr/bin/env python3
"""Extended acceptance test (fixtures are invented here; nothing comes from the kit's dev data).

Covers: Hindi/Hinglish linkage, same-name non-merge, C/O traps, FHIR validity, PII file name,
quarantine with a canary, 9-day stay preservation, determinism, secret sensitivity, clean channels.

    python tests/acceptance_extended.py [--repo .]
"""
import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

CANARY = "Quorlan Vexmoth"
FAILS = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


def build(inp):
    os.makedirs(os.path.join(inp, "registration"))
    os.makedirs(os.path.join(inp, "notes"))
    os.makedirs(os.path.join(inp, "fhir"))
    os.makedirs(os.path.join(inp, "misc"))
    with open(os.path.join(inp, "registration", "reg.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["UHID", "Naam", "Ling", "Umar", "Pita/Pati ka Naam", "Gaon", "Jila", "Mobile", "Diagnosis"])
        w.writerow(["KLX-700101", "कुसुम लता", "F", "52", "W/o हरबंस लाल", "रामपुर खुर्द", "Sitapur", "9876501234", "Hypertension"])
        w.writerow(["KLX-700102", "Ramesh Kumar", "M", "34", "S/o Gopal Kumar", "Bhawanipur", "Hardoi", "9812300001", "Typhoid fever"])
        w.writerow(["KLX-700103", "Ramesh Kumar", "M", "67", "S/o Shiv Narayan", "Kakori", "Lucknow", "9812300002", "Cataract"])
    # Hinglish note about the Devanagari patient, linked by phone + name
    with open(os.path.join(inp, "notes", "opd_note_1.txt"), "w", encoding="utf-8") as f:
        f.write("OPD Note\nPatient: Kusum Lata   Age: 52/F\nMob: +91 98765 01234\n"
                "C/O fever for 3 days. Kusum ji ka BP 150/90 hai.\nAdv: Tab Amlodipine 5 mg 0-0-1 x 1 month\n"
                "Address: C/O Harbans Lal, Ward 12, Rampur Khurd\nWard: 4 (Medicine)\nDr. Anjali Mehrotra\n")
    # discharge with a 9-day stay
    with open(os.path.join(inp, "notes", "discharge_2.txt"), "w", encoding="utf-8") as f:
        f.write("DISCHARGE SUMMARY\nPatient Name: Ramesh Kumar   Age/Sex: 34 Yrs/M\nUHID: KLX-700101X\n"
                "S/o Gopal Kumar\nDate of Admission: 01/03/2026\nDate of Discharge: 10/03/2026\n"
                "Diagnosis: Typhoid fever (A01.0)\nK/C/O asthma. H/O TB.\nTab Azithromycin 500 mg 1-0-0 x 5 days\n")
    # file name carrying PII
    with open(os.path.join(inp, "notes", "9812300002_Ramesh_Kumar_rx.txt"), "w", encoding="utf-8") as f:
        f.write("Rx\nName: Ramesh Kumar  Age: 67 Y/M\nVill. Kakori, Distt. Lucknow\nMob 9812300002\nTab Timolol eye drops 1-0-1\n")
    bundle = {"resourceType": "Bundle", "type": "collection", "entry": [
        {"fullUrl": "urn:uuid:11111111-2222-3333-4444-555555555555",
         "resource": {"resourceType": "Patient", "id": "11111111-2222-3333-4444-555555555555",
                      "identifier": [{"system": "https://klx.example/uhid", "value": "KLX-700102"}],
                      "name": [{"text": "Ramesh Kumar", "given": ["Ramesh"], "family": "Kumar"}],
                      "gender": "male", "birthDate": "1991-05-04",
                      "telecom": [{"system": "phone", "value": "9812300001"}],
                      "address": [{"city": "Bhawanipur", "district": "Hardoi", "state": "Uttar Pradesh", "postalCode": "241001"}]}},
        {"fullUrl": "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
         "resource": {"resourceType": "Encounter", "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "status": "finished",
                      "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode", "code": "IMP"},
                      "subject": {"reference": "urn:uuid:11111111-2222-3333-4444-555555555555", "display": "Ramesh Kumar"},
                      "period": {"start": "2026-03-01", "end": "2026-03-10"}}}]}
    with open(os.path.join(inp, "fhir", "bundle_x.json"), "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=1)
    # truncated JSON containing a canary: must be quarantined, canary must not appear anywhere
    with open(os.path.join(inp, "misc", "broken.json"), "w", encoding="utf-8") as f:
        f.write('{"patient": {"name": "%s", "phone": "9000011111", "notes": "trunc' % CANARY)


def run(repo, inp, out, secret):
    env = dict(os.environ)
    env["RAKSHA_SECRET"] = secret
    r = subprocess.run([sys.executable, os.path.join(repo, "main.py"), "--input", inp, "--output", out],
                       env=env, capture_output=True, text=True, timeout=600)
    return r


def records(out):
    rows = [json.loads(l) for l in open(os.path.join(out, "records.jsonl"), encoding="utf-8") if l.strip()]
    return {(r["file"], r["loc"]): r["patient"] for r in rows}


def all_text(out):
    parts = []
    for dp, _, fns in os.walk(out):
        for n in fns:
            parts.append(n)
            parts.append(open(os.path.join(dp, n), encoding="utf-8", errors="ignore").read())
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    a = ap.parse_args()
    repo = os.path.abspath(a.repo)
    work = tempfile.mkdtemp(prefix="raksha_acc_")
    try:
        inp = os.path.join(work, "in")
        build(inp)
        before = {p: hashlib.sha256(open(os.path.join(dp, p), "rb").read()).hexdigest()
                  for dp, _, fns in os.walk(inp) for p in fns}
        o1, o2, o3 = (os.path.join(work, n) for n in ("o1", "o2", "o3"))
        r1 = run(repo, inp, o1, "alpha-secret")
        check(r1.returncode == 0, "run 1 exits 0")
        r2 = run(repo, inp, o2, "alpha-secret")
        r3 = run(repo, inp, o3, "beta-secret")
        check(sorted(os.listdir(o1)) == ["records.jsonl", "report.json", "sanitized"], "output holds only sanitized/, report.json, records.jsonl")
        after = {p: hashlib.sha256(open(os.path.join(dp, p), "rb").read()).hexdigest()
                 for dp, _, fns in os.walk(inp) for p in fns}
        check(before == after, "input untouched")
        rep = json.load(open(os.path.join(o1, "report.json"), encoding="utf-8"))
        status = {f["output"]: f["status"] for f in rep["files"]}
        outs = {f["input_sha256"]: f for f in rep["files"]}
        broken_sha = hashlib.sha256(open(os.path.join(inp, "misc", "broken.json"), "rb").read()).hexdigest()
        check(outs[broken_sha]["status"] == "quarantined", "truncated JSON quarantined")
        text = all_text(o1) + r1.stdout + r1.stderr
        check(CANARY not in text and "Quorlan" not in text, "canary from a quarantined file appears nowhere")
        for lit in ("Kusum", "कुसुम", "Harbans", "हरबंस", "Gopal", "9876501234", "98765 01234", "9812300001", "9812300002",
                    "KLX-700101", "KLX-700102", "1991-05-04", "Ramesh Kumar", "Rampur Khurd", "Ward 12"):
            check(lit not in text, "no leak of %r" % lit)
        # file name with PII
        names = [f["output"] for f in rep["files"] if f["output"]]
        check(not any(re.search(r"9812300002|Ramesh|Kumar", n) for n in names), "PII removed from output file name")
        recs = records(o1)
        def psn_of(fname_part, loc):
            for (f, l), p in recs.items():
                if fname_part in f and l == loc:
                    return p
            return "missing"
        reg = "sanitized/registration/reg.csv"
        p_kusum, p_r34, p_r67 = recs.get((reg, "row:0")), recs.get((reg, "row:1")), recs.get((reg, "row:2"))
        check(p_kusum and p_kusum == psn_of("opd_note_1", "doc"), "Devanagari registration links to Hinglish OPD note")
        check(p_r34 and p_r67 and p_r34 != p_r67, "same-name different people are not merged")
        check(psn_of("bundle_x", "doc") == p_r34, "FHIR patient links to the right Ramesh Kumar (ID + phone)")
        check(psn_of("discharge_2", "doc") != p_r67, "discharge (34 y) not merged with the 67 y namesake")
        # C/O traps and clinical preservation
        note = open(os.path.join(o1, [n for n in names if "opd_note_1" in n][0]), encoding="utf-8").read()
        check("C/O fever for 3 days" in note, "C/O complaint preserved")
        check("0-0-1" in note and "Amlodipine 5 mg" in note and "BP 150/90" in note, "drug, dose, frequency, vitals preserved")
        check("Ward: 4 (Medicine)" in note and "Dr. Anjali Mehrotra" in note, "hospital ward and doctor preserved")
        # FHIR validity
        fb = json.load(open(os.path.join(o1, [n for n in names if "bundle_x" in n][0]), encoding="utf-8"))
        ids = {e.get("fullUrl") for e in fb["entry"]}
        refs = re.findall(r'"reference":\s*"([^"]+)"', json.dumps(fb))
        check(fb["resourceType"] == "Bundle" and all(r in ids for r in refs), "FHIR bundle valid with resolvable references")
        pat = [e["resource"] for e in fb["entry"] if e["resource"]["resourceType"] == "Patient"][0]
        check("birthDate" not in pat or pat["birthDate"] != "1991-05-04", "FHIR birthDate not exported raw")
        # 9-day stay
        ds = open(os.path.join(o1, [n for n in names if "discharge_2" in n][0]), encoding="utf-8").read()
        dts = re.findall(r"(\d{2})/(\d{2})/(\d{4})", ds)
        ok = False
        if len(dts) >= 2:
            d1 = dt.date(int(dts[0][2]), int(dts[0][1]), int(dts[0][0]))
            d2 = dt.date(int(dts[1][2]), int(dts[1][1]), int(dts[1][0]))
            ok = (d2 - d1).days == 9 and d1 != dt.date(2026, 3, 1)
        check(ok, "9-day stay preserved while dates are shifted")
        # determinism + secret sensitivity
        same = all(open(os.path.join(dp, n), "rb").read() == open(os.path.join(dp.replace(o1, o2), n), "rb").read()
                   for dp, _, fns in os.walk(os.path.join(o1, "sanitized")) for n in fns)
        check(same and open(os.path.join(o1, "records.jsonl"), "rb").read() == open(os.path.join(o2, "records.jsonl"), "rb").read(),
              "byte-identical output for the same secret")
        r3recs = set(records(o3).values())
        check(not (set(recs.values()) & r3recs - {None}), "different secret -> different pseudonyms")
        ds3 = all_text(o3)
        check(re.findall(r"Date of Admission: (\S+)", ds3) != re.findall(r"Date of Admission: (\S+)", text), "different secret -> different date shift")
        # missing secret
        env = {k: v for k, v in os.environ.items() if k != "RAKSHA_SECRET"}
        r4 = subprocess.run([sys.executable, os.path.join(repo, "main.py"), "--input", inp, "--output", os.path.join(work, "o4")],
                            env=env, capture_output=True, text=True)
        check(r4.returncode != 0 and "Kusum" not in r4.stderr + r4.stdout, "missing secret -> non-zero exit, no leak")
        check("alpha-secret" not in text, "secret never written")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("\n%s (%d failures)" % ("ALL PASS" if not FAILS else "FAILED", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
