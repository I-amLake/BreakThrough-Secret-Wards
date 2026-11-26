#!/usr/bin/env python3
"""Synthetic Indian hospital data generator with ground truth (for local evaluation only).

Four hospitals, mixed formats (CSV with BOM / UTF-16 TSV with Hinglish headers / cp1252 CSV with
MM/DD dates / nested JSON / FHIR / free-text notes in Latin, Devanagari and Hinglish), traps
(doctors, C/O complaints, eponyms, ASHA worker, hospital wards, doses), PII in file names, broken
files and canaries. About a third of the names are deliberately NOT in raksha's gazetteer so the
evaluation measures context-based detection rather than list lookups.

    python dev_eval/gen_data.py --out /path/synth --patients 60 --seed 7
Writes <out>/input/... and <out>/truth.json
"""
import argparse
import csv
import datetime as dt
import io
import json
import os
import random

GIVEN_M = ["Ramesh", "Suresh", "Mahesh", "Rajendra", "Arvind", "Imran", "Salim", "Gurpreet", "Harish", "Vinod",
           "Tejpal", "Bhoopendra", "Dharmveer", "Omkar", "Zubair", "Lakhan", "Prabhunath", "Jaswant"]
GIVEN_F = ["Sunita", "Kamla", "Rekha", "Pooja", "Nazia", "Shabnam", "Manjeet", "Savitri", "Lalita", "Geeta",
           "Phoolmati", "Ramrati", "Chandrakala", "Bitto", "Rukhsana", "Jasoda", "Premwati", "Sushila"]
SURN = ["Verma", "Yadav", "Gupta", "Mishra", "Khan", "Ansari", "Singh", "Pal", "Maurya", "Kushwaha", "Rawat",
        "Saroj", "Lodhi", "Kanaujia", "Bhadauria", "Qureshi", "Rajbhar", "Nishad"]
DEVA = {"Ramesh": "रमेश", "Suresh": "सुरेश", "Sunita": "सुनीता", "Kamla": "कमला", "Rekha": "रेखा", "Verma": "वर्मा",
        "Yadav": "यादव", "Gupta": "गुप्ता", "Mishra": "मिश्रा", "Singh": "सिंह", "Pal": "पाल", "Maurya": "मौर्य",
        "Geeta": "गीता", "Mahesh": "महेश", "Vinod": "विनोद", "Lalita": "ललिता", "Savitri": "सावित्री", "Harish": "हरीश"}
VILLAGES = ["Rampur Khurd", "Bhawanipur", "Kakori", "Sarai Akil", "Chandpur Kalan", "Bisalpur", "Mohanlalganj"]
DISTRICTS = [("Sitapur", "261"), ("Hardoi", "241"), ("Lucknow", "226"), ("Unnao", "209"), ("Barabanki", "225")]
DX = [("Essential (primary) hypertension", "I10"), ("Type 2 diabetes mellitus", "E11.9"), ("Typhoid fever", "A01.0"),
      ("Pneumonia, unspecified", "J18.9"), ("Malaria, unspecified", "B54"), ("Pulmonary tuberculosis", "A15.0")]
RARE_DX = [("Wilson disease", "E83.0"), ("Takayasu arteritis", "M31.4")]
DRUGS = ["Tab Amlodipine 5 mg 0-0-1", "Tab Metformin 500 mg 1-0-1", "Tab Paracetamol 650 mg 1-1-1",
         "Inj Ceftriaxone 1 g IV 1-0-1", "Tab Pantoprazole 40 mg 1-0-0", "Cap Doxycycline 100 mg 1-0-1"]
DOCTORS = ["Dr. Alok Tandon", "Dr. Farah Naqvi", "Dr. R.K. Saxena", "Dr. Meenakshi Bajpai"]
CANARY_FIRST = ["Yeshe", "Oindrila", "Thangam", "Kezhavino"]
CANARY_LAST = ["Dorjee", "Lalnunmawia", "Chakma", "Angami"]


def phone(rng):
    return str(rng.choice("6789")) + "".join(str(rng.randint(0, 9)) for _ in range(9))


def aadhaar(rng):
    return str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(11))


def make_people(rng, n):
    people = []
    for i in range(n):
        sex = rng.choice("MF")
        g = rng.choice(GIVEN_M if sex == "M" else GIVEN_F)
        s = rng.choice(SURN)
        age = rng.randint(18, 88)
        dist, pin3 = rng.choice(DISTRICTS)
        people.append({
            "pid": "P%03d" % i, "given": g, "surname": s, "name": "%s %s" % (g, s), "sex": sex, "age": age,
            "dob": dt.date(2026 - age, rng.randint(1, 12), rng.randint(1, 28)),
            "rel_type": "S/o" if sex == "M" else rng.choice(["W/o", "D/o"]),
            "relative": "%s %s" % (rng.choice(GIVEN_M), s), "phone": phone(rng), "aadhaar": aadhaar(rng),
            "village": rng.choice(VILLAGES), "district": dist, "pin": pin3 + "%03d" % rng.randint(1, 999),
            "uhid": "UH%d" % rng.randint(100000, 999999),
            "dx": RARE_DX[i % 2] if i % 23 == 0 else rng.choice(DX),
        })
    # deliberate homonyms: same name, different person
    if n > 4:
        people[3]["given"], people[3]["surname"] = people[2]["given"], people[2]["surname"]
        people[3]["name"] = people[2]["name"]
        people[3]["sex"] = people[2]["sex"]
        people[3]["age"] = (people[2]["age"] + 25) % 70 + 18
    return people


def deva_name(p):
    a, b = DEVA.get(p["given"]), DEVA.get(p["surname"])
    return "%s %s" % (a, b) if a and b else None


class Truth:
    def __init__(self):
        self.files = {}

    def unit(self, rel, loc, pid, pii, preserve, expect="sanitize"):
        f = self.files.setdefault(rel, {"expect": expect, "units": {}})
        f["units"][loc] = {"patient": pid, "pii": [x for x in pii if x], "preserve": [x for x in preserve if x]}


def gen(out, n, seed):
    rng = random.Random(seed)
    people = make_people(rng, n)
    T = Truth()
    inp = os.path.join(out, "input")
    for d in ("registration", "notes", "opd", "fhir", "misc", "lab"):
        os.makedirs(os.path.join(inp, d), exist_ok=True)
    base = dt.date(2026, 1, 5)
    # 1) CSV registration with BOM, day-first
    rows = [["UHID", "Patient Name", "Gender", "Age", "DOB", "Relation", "Relative Name", "Village", "District", "PIN", "Mobile", "Aadhaar No", "Reg Date"]]
    for i, p in enumerate(people[: n // 2]):
        rows.append([p["uhid"], p["name"], p["sex"], p["age"], p["dob"].strftime("%d/%m/%Y"), p["rel_type"], p["relative"],
                     p["village"], p["district"], p["pin"], p["phone"], p["aadhaar"], (base + dt.timedelta(days=i)).strftime("%d/%m/%Y")])
        T.unit("registration/hospA_registration.csv", "row:%d" % i, p["pid"],
               [p["name"], p["relative"], p["phone"], p["aadhaar"], p["uhid"], p["village"], p["pin"]], [])
    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    open(os.path.join(inp, "registration", "hospA_registration.csv"), "w", encoding="utf-8-sig", newline="").write(buf.getvalue())
    # 2) UTF-16 TSV, Hinglish headers
    rows = [["Naam", "Ling", "Umar", "Pita/Pati ka Naam", "Gaon", "Jila", "Mobile"]]
    sub = people[n // 4: 3 * n // 4]
    for i, p in enumerate(sub):
        nm = deva_name(p) if i % 3 == 0 and deva_name(p) else p["name"]
        rows.append([nm, p["sex"], str(p["age"]), "%s %s" % (p["rel_type"], p["relative"]), p["village"], p["district"], p["phone"]])
        T.unit("registration/hospB_patients.tsv", "row:%d" % i, p["pid"], [nm, p["relative"], p["phone"], p["village"]], [])
    open(os.path.join(inp, "registration", "hospB_patients.tsv"), "w", encoding="utf-16").write(
        "\n".join("\t".join(r) for r in rows) + "\n")
    # 3) discharge notes with stays, traps, PII file names
    for i, p in enumerate(people):
        if i % 2:
            continue
        adm = base + dt.timedelta(days=rng.randint(0, 200))
        los = rng.randint(2, 12)
        dis = adm + dt.timedelta(days=los)
        drug = rng.choice(DRUGS)
        doc = rng.choice(DOCTORS)
        dx, icd = p["dx"]
        txt = ("DISCHARGE SUMMARY\nPatient Name: %s   Age/Sex: %d Yrs/%s\nUHID: %s\n%s %s\n"
               "Address: Vill. %s, Distt. %s - %s\nMobile: %s\nDate of Admission: %s\nDate of Discharge: %s\n"
               "Diagnosis: %s (%s)\nPresenting complaints: C/O fever for %d days.\nK/C/O HTN. H/O Koch's.\n"
               "Ward: %d (Medicine)\n%s x 5 days\nBabinski sign negative. Referred by ASHA worker.\n%s\n"
               % (p["name"], p["age"], p["sex"], p["uhid"], p["rel_type"], p["relative"], p["village"], p["district"],
                  p["pin"], p["phone"], adm.strftime("%d/%m/%Y"), dis.strftime("%d/%m/%Y"), dx, icd, rng.randint(2, 9),
                  rng.randint(1, 9), drug, doc))
        if i % 4 == 0:
            txt += "%s ji ka BP 140/90 hai, bukhar utar gaya.\n" % p["given"]
        fname = ("%s_%s_ds.txt" % (p["phone"], p["given"])) if i % 6 == 0 else "ds_%s.txt" % p["uhid"]
        open(os.path.join(inp, "notes", fname), "w", encoding="utf-8").write(txt)
        T.unit("notes/" + fname, "doc", p["pid"], [p["name"], p["relative"], p["uhid"], p["phone"], p["village"], p["pin"]],
               [icd, drug.split(" ")[1], "C/O fever", "Ward: ", doc, "Babinski", "ASHA"])
        T.files["notes/" + fname]["stay"] = los
    # 4) Hindi OPD slips
    for i, p in enumerate(people):
        if i % 3 or not deva_name(p):
            continue
        txt = "ओपीडी पर्चा\nनाम: %s   आयु: %d वर्ष\nग्राम: %s\nमोबाइल: %s\n%s को बुखार है।\nTab Paracetamol 650 mg 1-1-1\n" % (
            deva_name(p), p["age"], p["village"], p["phone"], deva_name(p).split()[0])
        rel = "opd/opd_hi_%03d.txt" % i
        open(os.path.join(inp, rel), "w", encoding="utf-8").write(txt)
        T.unit(rel, "doc", p["pid"], [deva_name(p), p["phone"]], ["1-1-1", "Paracetamol 650 mg"])
    # 5) nested lab JSON
    recs = []
    for i, p in enumerate(people[::3]):
        recs.append({"patient": {"name": p["name"], "age": p["age"], "sex": p["sex"], "phone": p["phone"], "uhid": p["uhid"]},
                     "panels": [{"name": "Routine", "results": [{"test": "Haemoglobin", "value": 11.2, "unit": "g/dL"}]}],
                     "remarks": "Sample received from %s's attendant (%s %s)." % (p["given"], p["rel_type"], p["relative"])})
        T.unit("lab/bulk.json", "/results/%d" % i, p["pid"], [p["name"], p["phone"], p["uhid"], p["relative"]], ["Haemoglobin", "Routine"])
    json.dump({"lab": "City Diagnostics", "results": recs}, open(os.path.join(inp, "lab", "bulk.json"), "w", encoding="utf-8"), indent=1)
    # 6) FHIR bundles
    for i, p in enumerate(people[1::4]):
        pid = "%08x-0000-4000-8000-%012x" % (i + 1, i + 1)
        b = {"resourceType": "Bundle", "type": "collection", "entry": [
            {"fullUrl": "urn:uuid:" + pid, "resource": {"resourceType": "Patient", "id": pid,
             "identifier": [{"system": "https://hospC.example/uhid", "value": p["uhid"]}],
             "name": [{"text": p["name"], "given": [p["given"]], "family": p["surname"]}], "gender": "male" if p["sex"] == "M" else "female",
             "birthDate": p["dob"].isoformat(), "telecom": [{"system": "phone", "value": p["phone"]}],
             "address": [{"city": p["village"], "district": p["district"], "postalCode": p["pin"]}]}},
            {"fullUrl": "urn:uuid:e" + pid[1:], "resource": {"resourceType": "Condition", "id": "e" + pid[1:],
             "subject": {"reference": "urn:uuid:" + pid, "display": p["name"]},
             "code": {"coding": [{"system": "http://hl7.org/fhir/sid/icd-10", "code": p["dx"][1]}]}}}]}
        rel = "fhir/bundle_%03d.json" % i
        json.dump(b, open(os.path.join(inp, rel), "w", encoding="utf-8"), indent=1)
        T.unit(rel, "doc", p["pid"], [p["name"], p["phone"], p["uhid"], p["dob"].isoformat()], [p["dx"][1]])
    # 7) canaries in odd places + broken files
    c = ["%s %s" % (CANARY_FIRST[k], CANARY_LAST[k]) for k in range(4)]
    open(os.path.join(inp, "misc", "visitor_log.txt"), "w", encoding="utf-8").write(
        "VISITOR LOG\n18:40 - %s (attendant, bed 4), mob %s\n" % (c[0], phone(rng)))
    T.unit("misc/visitor_log.txt", "doc", None, [c[0]], [], expect="sanitize")
    json.dump({"tickets": [{"meta": {"raised_by": {"name": c[1], "callback": phone(rng)}}}]},
              open(os.path.join(inp, "misc", "tickets.json"), "w", encoding="utf-8"))
    T.unit("misc/tickets.json", "doc", None, [c[1]], [])
    open(os.path.join(inp, "misc", "truncated.json"), "w", encoding="utf-8").write('{"name": "%s", "x": [1, 2' % c[2])
    T.unit("misc/truncated.json", "doc", None, [c[2]], [], expect="either")
    open(os.path.join(inp, "misc", "empty.csv"), "w").close()
    open(os.path.join(inp, "misc", "scan.pdf"), "wb").write(b"%PDF-1.4\n" + c[3].encode() + b"\n%%EOF")
    T.unit("misc/scan.pdf", "doc", None, [c[3]], [], expect="either")
    json.dump({"people": people_meta(people), "files": T.files, "canaries": c},
              open(os.path.join(out, "truth.json"), "w", encoding="utf-8"), indent=1, default=str)
    return T


def people_meta(people):
    return {p["pid"]: {k: (str(v) if isinstance(v, dt.date) else v) for k, v in p.items()} for p in people}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--patients", type=int, default=60)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    gen(a.out, a.patients, a.seed)
    print("wrote", a.out)
