#!/usr/bin/env python3
"""Self-improvement loop for the unseen-name model (development only; never imported by main.py).

    python -m dev_eval.improve                     # one round, seed picked from the changelog
    python -m dev_eval.improve --rounds 5 --kit /path/to/kit   # also gate on the kit's check_dev
    python -m dev_eval.improve --extra-words my_false_alarms.txt      # teach it words it over-redacts
    python -m dev_eval.improve --gemini-cases cases.jsonl             # learn from / test on Gemini-written cases

Each round, fully offline and stdlib-only:
  1. trains a CANDIDATE char n-gram logistic regression on freshly generated synthetic tokens
     (scripts/train_namefind.py generators, new seed, slightly varied hyper-parameters);
  2. generates a FRESH held-out set the current model has never seen: invented names (random
     syllables, filtered against every list shipped in raksha/data and the name module), dropped
     into English / Hinglish / Devanagari note templates, plus person-frame sentences with no name;
  3. runs the whole pipeline (main.py) with the current weights and with the candidate weights in a
     temporary copy of the repo, and scores: held-out token F1, name recall, non-PII token
     retention, and dev_eval/gen_data.py end-to-end leaks / clinical / linkage; optionally the
     kit's check_dev (leaks, medical values kept, linkage); with --gemini-cases, the held-out half of
     the cases file (dev_eval/gemini_cases.py) is a further leak / kept-values test;
  4. PROMOTES the candidate only if nothing regresses, dev leaks stay 0 and at least one metric
     improves; otherwise keeps the current weights. Every round is appended to
     dev_eval/IMPROVE_LOG.md. Nothing real is ever used for training.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEIGHTS = os.path.join(REPO, "raksha", "namefind_weights.json")
LOG = os.path.join(REPO, "dev_eval", "IMPROVE_LOG.md")
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))


# ------------------------------------------------------------------ fresh held-out notes
ON = ["k", "kh", "g", "ch", "j", "t", "d", "dh", "n", "p", "b", "bh", "m", "y", "r", "l", "v", "sh", "s", "h", "pr", "tr"]
VW = ["a", "aa", "i", "ee", "u", "e", "ai", "o"]
END = ["", "n", "m", "sh", "l", "t", "v", "nt", "ika", "esh", "an", "ita", "ini", "endra", "pal", "deep", "veer"]
D_ON = {"k": "क", "kh": "ख", "g": "ग", "ch": "च", "j": "ज", "t": "त", "d": "द", "dh": "ध", "n": "न", "p": "प", "b": "ब",
        "bh": "भ", "m": "म", "y": "य", "r": "र", "l": "ल", "v": "व", "sh": "श", "s": "स", "h": "ह", "pr": "प्र", "tr": "त्र"}
D_VW = {"a": "", "aa": "ा", "i": "ि", "ee": "ी", "u": "ु", "e": "े", "ai": "ै", "o": "ो"}
D_END = {"": "", "n": "न", "m": "म", "sh": "श", "l": "ल", "t": "त", "v": "व", "nt": "ंत", "ika": "िका", "esh": "ेश", "an": "न",
         "ita": "िता", "ini": "िनी", "endra": "ेंद्र", "pal": "पाल", "deep": "दीप", "veer": "वीर"}
POS = [("{N} has been discharged today.", "en"), ("Counselled {N} regarding diet.", "en"),
       ("Explained the procedure to {N} and {M}.", "en"), ("{N} complained of giddiness at night.", "en"),
       ("Shaam ko {N} wapas aaye.", "hinglish"), ("{N} ne dawa nahi li.", "hinglish"), ("{N} bole ki dard kam hai.", "hinglish"),
       ("{n} ko neend nahi aa rahi.", "hinglish_lower"), ("{D} ने दवा ली।", "deva"), ("रात को {D} आए।", "deva"),
       ("{D} बोलीं कि दर्द है।", "deva"), ("Patient {N} {S}, 45/M, seen in OPD.", "cued")]
NEG = ["Counselled Housekeeping about the spill.", "Shaam ko Lab wale aaye.", "Thand mein kampkampi aayi.",
       "Explained the plan to Security at the gate.", "Pharmacy ne dawa bhej di.", "रात को बुखार आया।",
       "Dressing ke baad Sister ne chart bhara.", "Ambulance driver ko bulaya.", "Diet kitchen ne khana bheja.",
       "Ward boy ne bed badla.", "BP 130/80, pulse 84.", "Tab Paracetamol 650 mg 1-0-1 x 5 days."]
FILL = ["Vitals stable, afebrile.", "Urine output adequate.", "सुबह नाश्ता किया।", "IV fluids continued.", "Report kal aayegi.",
        "Hb 10.2 g/dL, TLC 8400.", "Plan: review after 2 weeks."]
SUR = ["Devi", "Kumari", "Singh", "Begum"]


def _exclusion():
    """Every word shipped in raksha/data or written in the name module: held-out names avoid them all."""
    import ast
    from raksha.translit import fold
    ex = set()
    data = os.path.join(REPO, "raksha", "data")
    for fn in sorted(os.listdir(data)):
        if fn.endswith(".txt"):
            ex |= set(open(os.path.join(data, fn), encoding="utf-8").read().lower().split())
    for fn in (os.path.join(REPO, "raksha", "namefind.py"), os.path.join(REPO, "scripts", "train_namefind.py")):
        for node in ast.walk(ast.parse(open(fn, encoding="utf-8").read())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                ex |= {w.lower() for w in re.findall(r"[A-Za-z]{3,}", node.value)}
    return ex, {fold(w) for w in ex if w.isascii()}


def gen_heldout(out, seed, n_files=120):
    from raksha.translit import fold
    rnd = random.Random(seed)
    ex, exf = _exclusion()
    names, seen = [], set()
    while len(names) < 260:
        parts = [(rnd.choice(ON), rnd.choice(VW)) for _ in range(rnd.choice((2, 2, 3)))]
        e = rnd.choice(END)
        lat = "".join(c + v for c, v in parts) + e
        dev = "".join(D_ON[c] + D_VW[v] for c, v in parts) + D_END[e]
        if not 5 <= len(lat) <= 12 or lat in seen or lat in ex or fold(lat) in exf:
            continue
        seen.add(lat)
        names.append((lat.capitalize(), dev))
    os.makedirs(os.path.join(out, "input"), exist_ok=True)
    truth = []
    for i in range(n_files):
        lines, nm = [], []
        for _ in range(rnd.randint(2, 3)):
            (a, ad), (b, _) = rnd.choice(names), rnd.choice(names)
            t, kind = rnd.choice(POS)
            lines.append(t.format(N=a, M=b, n=a.lower(), D=ad, S=rnd.choice(SUR)))
            nm.append({"kind": kind, "name": ad if "{D}" in t else (a.lower() if "{n}" in t else a)})
            if "{M}" in t:
                nm.append({"kind": kind, "name": b})
        lines += rnd.sample(NEG, 2) + rnd.sample(FILL, 2)
        rnd.shuffle(lines)
        fn = "note_%03d.txt" % i
        with open(os.path.join(out, "input", fn), "w", encoding="utf-8") as fh:
            fh.write("NOTE\n" + "\n".join(lines) + "\n")
        truth.append({"file": fn, "names": nm})
    with open(os.path.join(out, "truth.json"), "w", encoding="utf-8") as fh:
        json.dump({"truth": truth}, fh, ensure_ascii=False)


def score_notes(data, out):
    from collections import Counter
    T = json.load(open(os.path.join(data, "truth.json"), encoding="utf-8"))
    rep = json.load(open(os.path.join(out, "report.json"), encoding="utf-8"))
    outp = {f["input_sha256"]: f.get("output") for f in rep["files"]}
    tok = re.compile(r"[A-Za-z]+|[\u0900-\u097F]+")
    neutral = {w.lower() for w in SUR} | {"nan"}
    tot = rec = kin = kout = 0
    for t in T["truth"]:
        src = open(os.path.join(data, "input", t["file"]), encoding="utf-8").read()
        o = outp.get(hashlib.sha256(src.encode()).hexdigest())
        dst = open(os.path.join(out, o), encoding="utf-8").read() if o else ""
        for n in t["names"]:
            tot += 1
            rec += re.search(r"(?<![\w\u0900-\u097F])" + re.escape(n["name"]) + r"(?![\w\u0900-\u097F])", dst, re.I) is None
        ntoks = {w.lower() for n in t["names"] for w in tok.findall(n["name"])}
        cin = Counter(w.lower() for w in tok.findall(src) if w.lower() not in ntoks and w.lower() not in neutral)
        cout = Counter(w.lower() for w in tok.findall(dst))
        kin += sum(cin.values())
        kout += sum(min(c, cout[w]) for w, c in cin.items())
    return {"name_recall": round(rec / max(1, tot), 4), "retention": round(kout / max(1, kin), 4)}


# ------------------------------------------------------------------ helpers
def run_main(repo, inp, out, secret="improve-loop"):
    shutil.rmtree(out, ignore_errors=True)
    r = subprocess.run([sys.executable, os.path.join(repo, "main.py"), "--input", inp, "--output", out, "--quiet"],
                       env=dict(os.environ, RAKSHA_SECRET=secret), capture_output=True, text=True, timeout=3600)
    if r.returncode:
        raise SystemExit("main.py failed in %s" % repo)


def copy_repo(dst, weights_payload=None):
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", "IMPROVE_LOG.md"))
    if weights_payload is not None:
        with open(os.path.join(dst, "raksha", "namefind_weights.json"), "w", encoding="utf-8") as fh:
            fh.write(weights_payload)


def e2e(repo, work, seed):
    data = os.path.join(work, "synth_%d" % seed)
    if not os.path.isdir(data):
        subprocess.run([sys.executable, os.path.join(REPO, "dev_eval", "gen_data.py"), "--out", data, "--seed", str(seed),
                        "--patients", "60"], check=True, capture_output=True)
    r = subprocess.run([sys.executable, os.path.join(repo, "dev_eval", "evaluate.py"), "--data", data],
                       capture_output=True, text=True, timeout=3600)
    res = json.loads(r.stdout[r.stdout.index("{"):])
    return {"e2e_leak_rate": res["pii_leak_rate"], "e2e_clinical": res["clinical_preservation"], "e2e_link_f05": res["linkage"]["f0.5"]}


def check_dev(repo, kit, work):
    out = os.path.join(work, "dev_" + hashlib.sha1(repo.encode()).hexdigest()[:6])
    run_main(repo, os.path.join(kit, "dev", "input"), out, secret="practice")
    r = subprocess.run([sys.executable, os.path.join(kit, "check_dev.py"), "--output", out], capture_output=True, text=True)
    t = r.stdout
    leak = re.search(r"PERSONAL DATA: (\d+) of", t)
    med = re.search(r"MEDICAL DATA KEPT: (\d+) of", t)
    link = re.search(r"F0\.5 ([0-9.]+)", t)
    return {"dev_leaks": int(leak.group(1)) if leak else 10 ** 6, "dev_medical": int(med.group(1)) if med else 0,
            "dev_link_f05": float(link.group(1)) if link else 0.0}


def token_f1(bias, weights, val):
    import train_namefind as T
    return T.evaluate(bias, weights, val)["f1"]


HIGHER = ("token_f1", "name_recall", "retention", "e2e_clinical", "e2e_link_f05", "dev_medical", "dev_link_f05", "gemini_kept")
LOWER = ("e2e_leak_rate", "dev_leaks", "gemini_leaks")


def _extra(path, label):
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        return [(w.strip(), label) for w in fh if w.strip() and not w.startswith("#")]


def one_round(seed, kit, work, extra=(), gemini_held=None):
    import train_namefind as T
    rnd = random.Random(seed)
    hp = {"epochs": rnd.randint(16, 22), "lr": round(rnd.uniform(0.10, 0.14), 3), "min_df": rnd.choice((3, 3, 4))}
    # the base synthetic set (seed 42, as shipped) plus a fresh one: every round adds new invented tokens
    base = T.build_synthetic_dataset(seed=42)
    data = sorted(set(base) | set(T.build_synthetic_dataset(seed=seed)) | set(extra))
    rnd.shuffle(data)
    bias, weights = T.train_logistic(data, epochs=hp["epochs"], lr=hp["lr"], min_df=hp["min_df"], seed=seed)
    payload = json.dumps({"_about": "Raksha unseen-name scorer: logistic regression over char n-gram + morphology features, "
                                    "trained on synthetic tokens only by dev_eval/improve.py (seed %d, %s). params = %d weights + 1 bias"
                                    % (seed, json.dumps(hp, sort_keys=True), len(weights)), "bias": bias, "weights": weights},
                         separators=(",", ":"), sort_keys=True)
    cur = json.load(open(WEIGHTS, encoding="utf-8"))
    val = T.build_synthetic_dataset(seed=seed + 100003)       # held-out tokens from a seed neither model saw
    held = os.path.join(work, "heldout_%d" % seed)
    gen_heldout(held, seed + 200003)
    repos = {"current": os.path.join(work, "cur_%d" % seed), "candidate": os.path.join(work, "cand_%d" % seed)}
    copy_repo(repos["current"])
    copy_repo(repos["candidate"], payload)
    m = {}
    for k, repo in repos.items():
        r = {"token_f1": token_f1(cur["bias"], cur["weights"], val) if k == "current" else token_f1(bias, weights, val)}
        out = os.path.join(work, "out_%s_%d" % (k, seed))
        run_main(repo, os.path.join(held, "input"), out)
        r.update(score_notes(held, out))
        r.update(e2e(repo, work, seed % 1000 + 1))
        if kit:
            r.update(check_dev(repo, kit, work))
        if gemini_held:
            from dev_eval.gemini_cases import run_cases
            g = run_cases(repo, gemini_held, work)
            r.update({"gemini_leaks": len(g["leaks"]), "gemini_kept": g["kept"]})
        m[k] = r
    c, n = m["current"], m["candidate"]
    regress = [x for x in HIGHER if x in n and n[x] < c[x]] + [x for x in LOWER if x in n and n[x] > c[x]]
    better = [x for x in HIGHER if x in n and n[x] > c[x]] + [x for x in LOWER if x in n and n[x] < c[x]]
    if kit and n.get("dev_leaks", 1) != 0:
        regress.append("dev_leaks!=0")
    promote = not regress and bool(better)
    if promote:
        with open(WEIGHTS, "w", encoding="utf-8") as fh:
            fh.write(payload)
    return {"seed": seed, "hp": hp, "params": len(weights) + 1, "current": c, "candidate": n,
            "regressed": regress, "improved": better, "promoted": promote}


def next_seed():
    if not os.path.exists(LOG):
        return 1001
    seeds = [int(x) for x in re.findall(r"seed (\d+)", open(LOG, encoding="utf-8").read())]
    return (max(seeds) + 1) if seeds else 1001


def log(res):
    new = not os.path.exists(LOG)
    with open(LOG, "a", encoding="utf-8") as fh:
        if new:
            fh.write("# Name-model improvement log\n\nWritten by `python -m dev_eval.improve`. Synthetic data only.\n\n")
        fh.write("## %s seed %d: %s\n" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M"), res["seed"],
                                           "PROMOTED" if res["promoted"] else "kept current weights"))
        fh.write("- hyper-parameters %s, %d params\n" % (json.dumps(res["hp"], sort_keys=True), res["params"]))
        for k in sorted(res["current"]):
            fh.write("- %s: current %s, candidate %s\n" % (k, res["current"][k], res["candidate"][k]))
        if res["regressed"]:
            fh.write("- regressed: %s\n" % ", ".join(res["regressed"]))
        if res["improved"]:
            fh.write("- improved: %s\n" % ", ".join(res["improved"]))
        fh.write("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--seed", type=int, default=None, help="first seed (default: next unused seed in the log)")
    ap.add_argument("--kit", default=None, help="kit folder with check_dev.py and dev/input (optional gate)")
    ap.add_argument("--extra-names", default=None, help="file of INVENTED name tokens to add as positives (one per line)")
    ap.add_argument("--extra-words", default=None, help="file of ordinary words the model wrongly scores as names (negatives)")
    ap.add_argument("--gemini-cases", default=None,
                    help="JSON Lines file of cases written with dev_eval/GEMINI_PROMPT.md: half trains, half is a held-out leak test")
    ap.add_argument("--no-log", action="store_true")
    a = ap.parse_args()
    seed = a.seed if a.seed is not None else next_seed()
    g_train, g_held = [], None
    if a.gemini_cases:
        from dev_eval.gemini_cases import load_cases, name_training_tokens, split
        cases, problems = load_cases(a.gemini_cases)
        for p in problems:
            print("gemini-cases: skipped " + p)
        if not cases:
            raise SystemExit("gemini-cases: no valid case in %s (see the lines above)" % a.gemini_cases)
        train, g_held = split(cases)
        g_train = name_training_tokens(train)
        print("gemini-cases: %d valid (%d train -> %d tokens, %d held-out), %d lines skipped"
              % (len(cases), len(train), len(g_train), len(g_held), len(problems)))
    for i in range(a.rounds):
        work = tempfile.mkdtemp(prefix="raksha_improve_")
        try:
            res = one_round(seed + i, a.kit, work, _extra(a.extra_names, 1) + _extra(a.extra_words, 0) + g_train, g_held)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if not a.no_log:
            log(res)
        print(json.dumps({k: res[k] for k in ("seed", "promoted", "improved", "regressed")}))
        for k in sorted(res["current"]):
            print("  %-15s current %-8s candidate %s" % (k, res["current"][k], res["candidate"][k]))
    print("weights: %s" % os.path.relpath(WEIGHTS, REPO))


if __name__ == "__main__":
    main()
