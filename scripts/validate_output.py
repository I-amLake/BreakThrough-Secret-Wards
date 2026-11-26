#!/usr/bin/env python3
"""Minimal output-contract validator (mirrors docs/SPEC.md of the Secret Wards kit).

    python scripts/validate_output.py --input IN --output OUT
Prints CONTRACT OK or the list of problems.
"""
import argparse
import hashlib
import json
import os
import sys

COUNTS = ["files_total", "files_sanitized", "files_quarantined", "records_processed", "identifiers_detected",
          "records_linked", "records_generalized", "records_suppressed", "records_quarantined"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    errs = []
    extra = sorted(set(os.listdir(a.output)) - {"sanitized", "report.json", "records.jsonl"})
    if extra:
        errs.append("unexpected entries in output: %d" % len(extra))
    try:
        rep = json.load(open(os.path.join(a.output, "report.json"), encoding="utf-8"))
    except Exception:
        print("report.json missing or invalid")
        return 1
    if rep.get("schema") != "raksha-report/1":
        errs.append("schema must be raksha-report/1")
    for k in COUNTS:
        if not isinstance(rep.get("counts", {}).get(k), int):
            errs.append("counts.%s missing" % k)
    if not isinstance(rep.get("timing", {}).get("seconds"), (int, float)):
        errs.append("timing.seconds missing")
    if not isinstance(rep.get("resources", {}).get("peak_rss_mb"), (int, float)):
        errs.append("resources.peak_rss_mb missing")
    shas = set()
    for dp, _, fns in os.walk(a.input):
        for n in fns:
            shas.add(hashlib.sha256(open(os.path.join(dp, n), "rb").read()).hexdigest())
    listed = {}
    for f in rep.get("files", []):
        listed[f.get("input_sha256")] = f
        if f.get("status") not in ("sanitized", "quarantined", "suppressed"):
            errs.append("bad status")
        if f.get("status") == "sanitized":
            if not f.get("output") or not os.path.isfile(os.path.join(a.output, f["output"])):
                errs.append("sanitized file missing on disk")
            elif not f["output"].startswith("sanitized/"):
                errs.append("output path must be under sanitized/")
    if shas - set(listed):
        errs.append("%d input files not listed in report.json" % len(shas - set(listed)))
    c = rep.get("counts", {})
    if c.get("files_total") != len(rep.get("files", [])):
        errs.append("files_total does not match files[]")
    if c.get("files_sanitized") != sum(1 for f in rep["files"] if f["status"] == "sanitized"):
        errs.append("files_sanitized dishonest")
    outs = {f["output"] for f in rep["files"] if f.get("output")}
    n = 0
    for line in open(os.path.join(a.output, "records.jsonl"), encoding="utf-8"):
        if not line.strip():
            continue
        n += 1
        r = json.loads(line)
        if not {"file", "loc", "patient"} <= set(r):
            errs.append("records.jsonl line %d lacks file/loc/patient" % n)
            continue
        if r["file"] not in outs:
            errs.append("records.jsonl line %d points to an unlisted file" % n)
        elif r["patient"]:
            body = open(os.path.join(a.output, r["file"]), encoding="utf-8", errors="ignore").read()
            if r["patient"] not in body:
                errs.append("pseudonym of line %d not inside its file" % n)
    for dp, _, fns in os.walk(os.path.join(a.output, "sanitized")):
        for fn in fns:
            try:
                open(os.path.join(dp, fn), encoding="utf-8").read()
            except UnicodeDecodeError:
                errs.append("non-UTF-8 sanitized file")
    for e in sorted(set(errs)):
        print("ERROR:", e)
    print("CONTRACT OK" if not errs else "CONTRACT FAILED (%d)" % len(set(errs)))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
