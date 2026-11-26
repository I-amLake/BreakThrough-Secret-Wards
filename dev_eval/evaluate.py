#!/usr/bin/env python3
"""Local evaluation on synthetic data from dev_eval/gen_data.py (never on hidden data).

Runs main.py twice with one secret and once with another, then reports:
  PII leak rate (by type of surface), canary hits, clinical preservation, pairwise linkage P/R/F0.5,
  length-of-stay preservation, determinism, secret sensitivity, and a simple registry attacker
  (mean 1/|candidates| over released sex + age band + district, vs. raw exact age).

    python dev_eval/gen_data.py --out /tmp/synth && python dev_eval/evaluate.py --data /tmp/synth
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(inp, out, secret):
    env = dict(os.environ, RAKSHA_SECRET=secret)
    r = subprocess.run([sys.executable, os.path.join(REPO, "main.py"), "--input", inp, "--output", out, "--quiet"],
                       env=env, capture_output=True, text=True)
    if r.returncode:
        sys.exit("main.py failed (%d)" % r.returncode)
    return r


def tree_bytes(root):
    out = {}
    for dp, _, fns in os.walk(root):
        for n in fns:
            p = os.path.join(dp, n)
            out[os.path.relpath(p, root)] = open(p, "rb").read()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    a = ap.parse_args()
    truth = json.load(open(os.path.join(a.data, "truth.json"), encoding="utf-8"))
    inp = os.path.join(a.data, "input")
    work = tempfile.mkdtemp(prefix="raksha_eval_")
    o1, o2, o3 = (os.path.join(work, x) for x in ("o1", "o2", "o3"))
    r1 = run(inp, o1, "eval-secret-1")
    run(inp, o2, "eval-secret-1")
    run(inp, o3, "eval-secret-2")
    rep = json.load(open(os.path.join(o1, "report.json"), encoding="utf-8"))
    by_sha = {f["input_sha256"]: f for f in rep["files"]}
    recs = defaultdict(dict)
    for line in open(os.path.join(o1, "records.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        recs[r["file"]][r["loc"]] = r["patient"]
    everything = "\n".join(k + "\n" + v.decode("utf-8", "ignore") for k, v in tree_bytes(o1).items()) + r1.stderr

    leaks = tot = pres = pres_tot = 0
    unit_psn = []
    stays_ok = stays = 0
    for rel, f in truth["files"].items():
        sha = hashlib.sha256(open(os.path.join(inp, rel), "rb").read()).hexdigest()
        info = by_sha.get(sha, {})
        outp = info.get("output")
        text = open(os.path.join(o1, outp), encoding="utf-8", errors="ignore").read() if outp else ""
        name = os.path.basename(outp or "")
        for loc, u in f["units"].items():
            for s in u["pii"]:
                tot += 1
                if s in text or s in name:
                    leaks += 1
                    print("  leak:", rel, loc, repr(s))
            for s in u["preserve"]:
                pres_tot += 1
                pres += s in text
            if u["patient"] and outp:
                unit_psn.append((u["patient"], recs.get(outp, {}).get(loc)))
        if f.get("stay") and outp:
            stays += 1
            ds = re.findall(r"Date of (?:Admission|Discharge): (\d{2})/(\d{2})/(\d{4})", text)
            if len(ds) == 2:
                d1, d2 = (dt.date(int(y), int(m), int(d)) for d, m, y in ds)
                stays_ok += (d2 - d1).days == f["stay"]
    canary_hits = sum(1 for c in truth["canaries"] if c in everything)
    # pairwise linkage
    tp = fp = fn = 0
    for i in range(len(unit_psn)):
        for j in range(i + 1, len(unit_psn)):
            same_t = unit_psn[i][0] == unit_psn[j][0]
            same_y = unit_psn[i][1] is not None and unit_psn[i][1] == unit_psn[j][1]
            tp += same_t and same_y
            fp += (not same_t) and same_y
            fn += same_t and not same_y
    P = tp / (tp + fp) if tp + fp else 1.0
    R = tp / (tp + fn) if tp + fn else 1.0
    F05 = (1.25 * P * R / (0.25 * P + R)) if P + R else 0.0
    # determinism / secret sensitivity
    b1, b2, b3 = tree_bytes(o1), tree_bytes(o2), tree_bytes(o3)
    b1.pop("report.json"), b2.pop("report.json"), b3.pop("report.json")
    det = b1 == b2
    psn1 = set(re.findall(r"PSN-[0-9A-Z]{6}", "".join(v.decode("utf-8", "ignore") for v in b1.values())))
    psn3 = set(re.findall(r"PSN-[0-9A-Z]{6}", "".join(v.decode("utf-8", "ignore") for v in b3.values())))
    # registry attacker on discharge notes: released sex + age band + district
    people = truth["people"]
    risks, raw_risks = [], []
    for rel, f in truth["files"].items():
        if not rel.startswith("notes/"):
            continue
        sha = hashlib.sha256(open(os.path.join(inp, rel), "rb").read()).hexdigest()
        outp = by_sha.get(sha, {}).get("output")
        if not outp:
            continue
        text = open(os.path.join(o1, outp), encoding="utf-8").read()
        pid = list(f["units"].values())[0]["patient"]
        m = re.search(r"Age/Sex: (\d+)(?:-(\d+)|\+)? Yrs/([MF])", text)
        lo, hi = (int(m.group(1)), int(m.group(2) or 120)) if m else (0, 120)
        dm = re.search(r"Distt\. ([A-Z][a-z]+)", text)
        cands = [q for q in people.values() if (not m or q["sex"] == m.group(3)) and lo <= q["age"] <= hi
                 and (not dm or q["district"] == dm.group(1))]
        risks.append(1.0 / len(cands) if any(c["pid"] == pid for c in cands) else 0.0)
        p = people[pid]
        raw = [q for q in people.values() if q["sex"] == p["sex"] and q["age"] == p["age"] and q["district"] == p["district"]]
        raw_risks.append(1.0 / max(1, len(raw)))
    res = {
        "pii_leak_rate": round(leaks / max(1, tot), 4), "pii_surfaces": tot, "canary_hits": canary_hits,
        "clinical_preservation": round(pres / max(1, pres_tot), 4),
        "linkage": {"precision": round(P, 4), "recall": round(R, 4), "f0.5": round(F05, 4)},
        "length_of_stay_preserved": "%d/%d" % (stays_ok, stays), "deterministic": det,
        "secret_changes_pseudonyms": bool(psn1) and not (psn1 & psn3),
        "registry_attack_risk": round(sum(risks) / max(1, len(risks)), 4),
        "registry_attack_risk_raw": round(sum(raw_risks) / max(1, len(raw_risks)), 4),
        "files_quarantined": rep["counts"]["files_quarantined"], "seconds": rep["timing"]["seconds"],
        "peak_rss_mb": rep["resources"]["peak_rss_mb"],
    }
    print(json.dumps(res, indent=2))
    import shutil
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
