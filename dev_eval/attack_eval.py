#!/usr/bin/env python3
"""Approximate the kit's registry attacker (ATTACKS.md A2/A3 record linkage + A4 profile pooling)
on an OUTPUT folder, for development only. Needs the practice truth and the attacker registry; it
is never imported by the pipeline (the registry is attacker knowledge, not runtime input).

    python dev_eval/attack_eval.py --kit /workspace/kit --output OUT

Evidence read from each released record (generic, like the attacker): gender, age / age bands,
district, tehsil, village (Latin or Devanagari), PIN and PIN prefix. Filters are applied in the
attacker's order and skipped when they would empty the candidate set. Record risk = probability
mass on the true person (uniform over survivors). No name weights: names are removed (A1 covers them).
"""
import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from raksha.translit import devanagari_to_latin, fold, has_devanagari  # noqa: E402

RX_BAND = re.compile(r"(?<![\w./-])(\d{1,3})\s?-\s?(\d{1,3})(?![\w.]|\s?-\s?\d)")
RX_PLUS = re.compile(r"(?<![\d.])(\d{2,3})\+")
RX_AGE = re.compile(r"(?i)(?:\bage[d]?|umar|आयु|उम्र)[^0-9\n]{0,12}?(\d{1,3})(?![\d\-])|(?<![\d./-])(\d{1,3})\s?(?:yrs?|years?|y|वर्ष)\b|(?<![\d./-])(\d{1,3})\s?/\s?[MF]\b")
RX_PIN = re.compile(r"(?<!\d)([1-9]\d{5})(?!\d)")
RX_PIN3 = re.compile(r"(?<!\d)([1-9]\d{2})(?:XXX|xxx|\*\*\*)")


def norm_place(s):
    if has_devanagari(s):
        s = devanagari_to_latin(s)
    return "".join(fold(t) for t in re.findall(r"[a-z]+", s.lower()))


def evidence(text, places):
    ev = {}
    t = text
    sex = set()
    if re.search(r"(?i)\"(?:sex|gender)\":\s*\"(?:M|male)\"|\b(?:male|पुरुष)\b|\d\s?/\s?M\b|\bS/o\b|\bYrs/M\b", t):
        sex.add("M")
    if re.search(r"(?i)\"(?:sex|gender)\":\s*\"(?:F|female)\"|\b(?:female|महिला)\b|\d\s?/\s?F\b|\b[WD]/o\b|\bYrs/F\b", t):
        sex.add("F")
    if len(sex) == 1:
        ev["gender"] = sex.pop()
    ranges = []
    for m in RX_BAND.finditer(t):
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo % 5 == 0 and (hi - lo + 1) in (5, 10, 20, 40) and hi <= 110:
            ranges.append((lo, hi))
    for m in RX_PLUS.finditer(t):
        lo = int(m.group(1))
        if lo % 5 == 0 and lo >= 60:
            ranges.append((lo, 120))
    for m in RX_AGE.finditer(t):
        g = next(x for x in m.groups() if x)
        a = int(g)
        if 0 <= a <= 110 and not any(lo <= a <= hi and hi > lo for lo, hi in ranges):
            ranges.append((a, a))
    if ranges:
        ev["age"] = ranges
    words = norm_place(t)
    for kind in ("district", "tehsil", "village"):
        hits = sorted({p for p in places[kind] if len(p) >= 4 and p in words})
        if hits:
            ev[kind] = hits
    pins = RX_PIN.findall(t)
    if pins:
        ev["pin"] = sorted(set(pins))
    p3 = RX_PIN3.findall(t)
    if p3:
        ev["pin3"] = sorted(set(p3))
    return ev


def merge(evs):
    out = {}
    for ev in evs:
        for k, v in ev.items():
            if k == "gender":
                out.setdefault("gender_set", set()).add(v)
            else:
                out.setdefault(k, [])
                out[k] = sorted(set(out[k]) | set(v))
    if len(out.get("gender_set", ())) == 1:
        out["gender"] = next(iter(out["gender_set"]))
    out.pop("gender_set", None)
    return out


def attack(ev, reg, pooled=False):
    cands = list(reg)

    def apply(pred):
        nonlocal cands
        nxt = [r for r in cands if pred(r)]
        if nxt:
            cands = nxt
    if ev.get("district"):
        apply(lambda r: r["_d"] in ev["district"])
    if ev.get("gender"):
        apply(lambda r: r["gender"] == ev["gender"])
    if ev.get("age"):
        if pooled:   # every released range must hold (at different visits, +-1/+2 drift)
            apply(lambda r: all(lo - 1 <= r["_age"] <= hi + 2 for lo, hi in ev["age"]))
        else:
            apply(lambda r: any(lo - 1 <= r["_age"] <= hi + 2 for lo, hi in ev["age"]))
    if ev.get("tehsil"):
        apply(lambda r: r["_t"] in ev["tehsil"])
    if ev.get("village"):
        apply(lambda r: r["_v"] in ev["village"])
    if ev.get("pin"):
        apply(lambda r: r["pin"] in ev["pin"])
    if ev.get("pin3"):
        apply(lambda r: r["pin"][:3] in ev["pin3"])
    return cands


def record_text(path, loc):
    raw = open(path, encoding="utf-8", errors="ignore").read()
    if loc.startswith("row:"):
        rows = list(csv.reader(io.StringIO(raw), dialect=csv.Sniffer().sniff(raw[:2000], delimiters=",\t;|") if raw else "excel"))
        i = int(loc[4:]) + 1
        if i < len(rows):
            return " | ".join(f"{h}: {c}" for h, c in zip(rows[0], rows[i]))
        return ""
    if loc.startswith("/"):
        try:
            node = json.loads(raw)
            for part in loc.split("/")[1:]:
                part = part.replace("~1", "/").replace("~0", "~")
                node = node[int(part)] if isinstance(node, list) else node[part]
            return json.dumps(node, ensure_ascii=False)
        except Exception:
            return raw
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--raw", action="store_true", help="attack the raw input instead (calibration; perfect pooling)")
    a = ap.parse_args()
    with open(os.path.join(a.kit, "dev", "attacker", "registry.csv"), encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        cols = set(reader.fieldnames or ())
        missing = {"rid", "age", "district", "village"} - cols
        if missing:
            raise ValueError("registry.csv missing required columns: %s" % sorted(missing))
        reg = list(reader)
    for r in reg:
        r["_age"] = int(r["age"])
        r["_d"], r["_t"], r["_v"] = norm_place(r.get("district", "")), norm_place(r.get("tehsil", "")), norm_place(r.get("village", ""))
    places = {"district": {r["_d"] for r in reg}, "tehsil": {r["_t"] for r in reg}, "village": {r["_v"] for r in reg}}
    truth = json.load(open(os.path.join(a.kit, "dev", "truth", "truth.json"), encoding="utf-8"))
    rid_of = {pt: p["rid"] for pt, p in truth["patients"].items()}
    rep = json.load(open(os.path.join(a.output, "report.json"), encoding="utf-8"))
    out_of = {f["input_sha256"]: f.get("output") for f in rep["files"]}
    psn = {}
    for line in open(os.path.join(a.output, "records.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        psn[(r["file"], r["loc"])] = r["patient"]
    rec_risk, items, age_u, geo_u = [], [], [], []
    by_psn = defaultdict(list)
    for rel, f in truth["files"].items():
        sha = hashlib.sha256(open(os.path.join(a.kit, "dev", "input", rel), "rb").read()).hexdigest()
        outp = out_of.get(sha)
        if a.raw:
            outp = rel
        if not outp:
            continue
        for loc, u in f["units"].items():
            pt = u.get("patient")
            if not pt or pt not in rid_of or loc.startswith("@"):
                continue
            base = os.path.join(a.kit, "dev", "input") if a.raw else a.output
            try:
                ev = evidence(record_text(os.path.join(base, outp), loc), places)
            except Exception:
                continue
            c = attack(ev, reg)
            risk = (1.0 / len(c)) if any(x["rid"] == rid_of[pt] for x in c) else 0.0
            rec_risk.append(risk)
            fld = {f["kind"]: f["true"] for f in (u.get("fields") or []) if f.get("patient", pt) == pt}
            ta = fld.get("age")
            if isinstance(ta, (int, float)):
                sc = 0.0
                for lo, hi in ev.get("age", []):
                    if lo <= ta <= hi:
                        w = hi - lo + 1
                        sc = max(sc, 1.0 if w == 1 else 0.9 if w <= 5 else 0.8 if w <= 10 else 0.6 if w <= 20 else 0.3)
                age_u.append(sc)
            if fld.get("district"):
                geo_u.append(0.7 if ev.get("district") else 0.0)
            items.append((pt, ev, risk))
            p = pt if a.raw else psn.get((outp, loc))
            if p:
                by_psn[p].append((pt, ev))
    # A4: pool evidence per pseudonym
    prof_risk = {}
    for p, lst in by_psn.items():
        ev = merge(e for _, e in lst)
        c = attack(ev, reg, pooled=True)
        for pt, _ in lst:
            r = (1.0 / len(c)) if any(x["rid"] == rid_of[pt] for x in c) else 0.0
            prof_risk[pt] = max(prof_risk.get(pt, 0.0), r)
    pts = sorted({pt for pt, _, _ in items})
    for pt, _, r in items:
        prof_risk[pt] = max(prof_risk.get(pt, 0.0), r)
    raw = {}
    rawp = os.path.join(a.kit, "dev", "truth", "raw_attack.json")
    if os.path.exists(rawp):
        raw = json.load(open(rawp))["result"]
    res = {
        "records": len(rec_risk),
        "A2_mean_record_risk": round(sum(rec_risk) / max(1, len(rec_risk)), 4),
        "A2_raw_reference": raw.get("record_linkage_risk"),
        "A4_patients_ge_0.5": round(sum(1 for pt in pts if prof_risk.get(pt, 0) >= 0.5) / max(1, len(pts)), 4),
        "A4_raw_reference": raw.get("patients_reidentified"),
        "A4_mean_profile_risk": round(sum(prof_risk.get(pt, 0) for pt in pts) / max(1, len(pts)), 4),
        "patients": len(pts),
        "utility_age_mean": round(sum(age_u) / max(1, len(age_u)), 3),
        "utility_district_mean": round(sum(geo_u) / max(1, len(geo_u)), 3),
    }
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
