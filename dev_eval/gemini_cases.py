#!/usr/bin/env python3
"""Tricky test cases written by Gemini 4 Neon (or any person) -> validated, split, used offline.

Development only; never imported by main.py or raksha/. The cases file is JSON Lines, one case per
line (format in dev_eval/GEMINI_PROMPT.md):

    {"id": "c01", "lang": "hinglish", "format": "txt", "filename": "opd_note.txt",
     "text": "Mareez Rameshwar Tiwari (S/o Late Gopal) ka BP 150/90 ...",
     "pii": [{"text": "Rameshwar Tiwari", "type": "PATIENT_NAME"}, {"text": "Gopal", "type": "RELATIVE_NAME"}],
     "must_keep": ["BP 150/90"]}

    python -m dev_eval.gemini_cases cases.jsonl          # check the file, show what is wrong per line
    python -m dev_eval.gemini_cases cases.jsonl --run    # run Raksha on every case, list leaks / lost values

The improvement loop uses it with `python -m dev_eval.improve --gemini-cases cases.jsonl`: about half
of the cases (picked by a hash of the case, so always the same half) teach the name model, the other
half is a held-out leak test that the candidate model must not do worse on.
"""
import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PII_TYPES = {"PATIENT_NAME", "RELATIVE_NAME", "OTHER_PERSON_NAME", "PHONE", "AADHAAR", "ABHA", "PAN", "VOTER_ID", "EMAIL",
             "MRN", "INSURANCE_ID", "OTHER_ID", "DOB", "DATE", "AGE", "ADDRESS", "VILLAGE", "PIN"}
NAME_TYPES = {"PATIENT_NAME", "RELATIVE_NAME", "OTHER_PERSON_NAME"}
FORMATS = {"txt", "csv", "json"}
MAX_TEXT = 20000


def _bad(n, why):
    return "line %d: %s" % (n, why)


def validate_line(n, line):
    """Return (case, None) for a good line, (None, reason) for a bad one. Never raises."""
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("```"):
        return None, None                                   # blank, comment or a markdown fence: ignored
    try:
        c = json.loads(s)
    except ValueError:
        return None, _bad(n, "not valid JSON (one case per line, no line breaks inside a case)")
    if not isinstance(c, dict):
        return None, _bad(n, "a case must be a JSON object {...}")
    text = c.get("text")
    if not isinstance(text, str) or not text.strip():
        return None, _bad(n, "missing \"text\"")
    if len(text) > MAX_TEXT:
        return None, _bad(n, "text longer than %d characters" % MAX_TEXT)
    fmt = str(c.get("format", "txt")).lower()
    if fmt not in FORMATS:
        return None, _bad(n, "format must be txt, csv or json")
    if fmt == "json":
        try:
            json.loads(text)
        except ValueError:
            return None, _bad(n, "format is json but text is not valid JSON")
    if fmt == "csv":
        try:
            rows = list(csv.reader(io.StringIO(text)))
        except csv.Error:
            return None, _bad(n, "format is csv but text is not valid CSV")
        if len(rows) < 2:
            return None, _bad(n, "csv needs a header row and at least one data row")
    pii = c.get("pii")
    if not isinstance(pii, list):
        return None, _bad(n, "\"pii\" must be a list of {\"text\", \"type\"} (it may be empty)")
    clean = []
    for p in pii:
        if not isinstance(p, dict) or not isinstance(p.get("text"), str) or not p["text"].strip():
            return None, _bad(n, "every pii item needs a \"text\"")
        t = str(p.get("type", "")).upper()
        if t not in PII_TYPES:
            return None, _bad(n, "unknown pii type %r (use one of %s)" % (p.get("type"), ", ".join(sorted(PII_TYPES))))
        if p["text"] not in text:
            return None, _bad(n, "pii text %r does not appear exactly in the record text" % p["text"][:40])
        clean.append({"text": p["text"], "type": t})
    keep = c.get("must_keep", [])
    if not isinstance(keep, list) or not all(isinstance(k, str) and k.strip() for k in keep):
        return None, _bad(n, "\"must_keep\" must be a list of strings")
    for k in keep:
        if k not in text:
            return None, _bad(n, "must_keep text %r does not appear exactly in the record text" % k[:40])
        if any(p["text"] in k for p in clean):
            return None, _bad(n, "must_keep %r contains a pii value" % k[:40])
    fn = str(c.get("filename") or "")
    ext = {"txt": ".txt", "csv": ".csv", "json": ".json"}[fmt]
    stem = re.sub(r"[^A-Za-z0-9_\-]+", "_", os.path.splitext(os.path.basename(fn))[0])[:60].strip("_") or "case"
    cid = str(c.get("id") or hashlib.sha256(s.encode()).hexdigest()[:8])
    return {"id": cid, "lang": str(c.get("lang", "")), "format": fmt, "stem": stem, "ext": ext, "text": text,
            "pii": clean, "must_keep": keep, "_key": hashlib.sha256(text.encode("utf-8")).hexdigest()}, None


def load_cases(path):
    """(cases, problems). Malformed lines are skipped with a reason; duplicates (same text) are dropped."""
    cases, problems, seen = [], [], set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            c, why = validate_line(n, line)
            if why:
                problems.append(why)
            elif c and c["_key"] not in seen:
                seen.add(c["_key"])
                cases.append(c)
    return cases, problems


def split(cases):
    """Deterministic ~50/50 split by a hash of the case text: (train, heldout). Both halves non-empty when >= 2 cases."""
    train = [c for c in cases if int(c["_key"][:8], 16) % 2 == 0]
    held = [c for c in cases if int(c["_key"][:8], 16) % 2 == 1]
    if not train and len(held) >= 2:
        train, held = held[:1], held[1:]
    if not held and len(train) >= 2:
        train, held = train[:-1], train[-1:]
    return train, held


def name_training_tokens(cases):
    """(token, label) pairs for the name model: Latin tokens of person-name pii are positives, single
    alphabetic must_keep words (drugs, clinical words) are negatives."""
    out = set()
    for c in cases:
        for p in c["pii"]:
            if p["type"] in NAME_TYPES:
                for t in re.findall(r"[A-Za-z]{3,}", p["text"]):
                    if t.lower() not in ("late", "smt", "shri", "baby", "mrs", "miss"):
                        out.add((t.capitalize(), 1))
        for k in c["must_keep"]:
            for t in re.findall(r"[A-Za-z]{4,}", k):
                out.add((t, 0))
    pos = {t for t, l in out if l == 1}
    return sorted((t, l) for t, l in out if not (l == 0 and t in pos))


def write_inputs(cases, folder):
    os.makedirs(folder, exist_ok=True)
    names = {}
    for i, c in enumerate(cases):
        fn = "%03d_%s%s" % (i, c["stem"], c["ext"])
        with open(os.path.join(folder, fn), "w", encoding="utf-8") as fh:
            fh.write(c["text"])
        names[fn] = c
    return names


def _norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()


def score_run(cases_by_file, inp, out):
    """Count pii strings still visible and must_keep strings lost, per case, in one output folder."""
    rep = json.load(open(os.path.join(out, "report.json"), encoding="utf-8"))
    by = {e["input_sha256"]: e for e in rep["files"]}
    leaks, lost, kept, total_keep, total_pii = [], [], 0, 0, 0
    for fn, c in sorted(cases_by_file.items()):
        raw = open(os.path.join(inp, fn), "rb").read()
        e = by.get(hashlib.sha256(raw).hexdigest(), {})
        o = e.get("output")
        dst = _norm(open(os.path.join(out, o), encoding="utf-8", errors="replace").read()) if o else ""
        dst_name = _norm(re.sub(r"[_\-]", " ", o or ""))
        for p in c["pii"]:
            total_pii += 1
            v = _norm(p["text"])
            pat = r"(?<![\w\u0900-\u097F])" + re.escape(v) + r"(?![\w\u0900-\u097F])"
            if v and (re.search(pat, dst) or re.search(pat, dst_name)):
                leaks.append((c["id"], p["type"], p["text"]))
        for k in c["must_keep"]:
            total_keep += 1
            if o and _norm(k) in dst:
                kept += 1
            else:
                lost.append((c["id"], k))
    return {"leaks": leaks, "lost": lost, "kept": kept, "total_keep": total_keep, "total_pii": total_pii}


def run_cases(repo, cases, work, secret="gemini-cases"):
    inp = os.path.join(work, "gc_in")
    out = os.path.join(work, "gc_out_" + hashlib.sha1(repo.encode()).hexdigest()[:6])
    shutil.rmtree(inp, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)
    names = write_inputs(cases, inp)
    r = subprocess.run([sys.executable, os.path.join(repo, "main.py"), "--input", inp, "--output", out, "--quiet"],
                       env=dict(os.environ, RAKSHA_SECRET=secret), capture_output=True, text=True, timeout=3600)
    if r.returncode:
        raise SystemExit("main.py failed on the Gemini cases")
    return score_run(names, inp, out)


def main():
    ap = argparse.ArgumentParser(description="Check (and optionally run) a Gemini-written cases file.")
    ap.add_argument("cases")
    ap.add_argument("--run", action="store_true", help="run Raksha on every valid case and list leaks / lost values")
    a = ap.parse_args()
    cases, problems = load_cases(a.cases)
    train, held = split(cases)
    print("valid cases: %d   skipped lines: %d   (training half %d, held-out half %d)" % (len(cases), len(problems), len(train), len(held)))
    for p in problems:
        print("  SKIPPED " + p)
    if a.run and cases:
        work = tempfile.mkdtemp(prefix="raksha_gc_")
        try:
            res = run_cases(REPO, cases, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        print("PII still visible: %d of %d   medical values kept: %d of %d" % (len(res["leaks"]), res["total_pii"], res["kept"], res["total_keep"]))
        for x in res["leaks"]:
            print("  LEAK  case %s  %-13s %s" % x)
        for x in res["lost"]:
            print("  LOST  case %s  %s" % x)
    sys.exit(0 if cases else 1)


if __name__ == "__main__":
    main()
