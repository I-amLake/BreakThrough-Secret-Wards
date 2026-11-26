#!/usr/bin/env python3
"""Train a compact, deterministic char n-gram + morphology logistic regression model on synthetic data.

Generates purely synthetic compositional Indian names vs. synthetic/standard clinical, pharma,
place, Hinglish, and English negative tokens (zero memorized benchmark data).
Outputs: raksha/namefind_weights.json (typically ~20-40 KB).
"""
from __future__ import annotations

import json
import math
import random
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from raksha.namefind import (
    MED_SUFFIXES,
    PHARMA_SUFFIXES,
    PLACE_SUFFIXES,
    STOP_LATIN,
    SURNAMES_LATIN,
    extract_token_features,
    norm_latin,
)

# Synthetic compositional Indian name morphemes (roots + endings across regions/communities)
_SANSKRIT_STEMS = [
    "ram", "shiv", "har", "dev", "raj", "sur", "nar", "kam", "man", "sun", "vin", "pra", "sudh", "sukh", "sanj", "saty", "dhar", "brij", "gaj", "gov", "hem", "jag",
    "jay", "jit", "kesh", "kul", "lal", "mah", "muk", "nav", "nir", "padm", "pank",
    "push", "radh", "ragh", "ranj", "rash", "ratn", "rav", "roh", "rup", "sadh",
    "sant", "sarv", "sav", "shak", "shan", "shar", "shil", "shob", "shw", "sneh", "sum",
    "sush", "tar", "uday", "um", "up", "urm", "vand", "vas", "ved", "venk", "vid", "vij",
    "vik", "vim", "vir", "vish", "yash", "yog", "abhi", "anur", "bhag", "bhan", "chandr",
    "dhan", "gan", "gir", "indr", "kail", "kalp", "kanh", "kar", "kaush", "kir", "krish",
    "laksh", "madh", "mang", "meen", "mit", "moh", "nand", "neel", "nirm", "omk", "parm",
    "phul", "prem", "priy", "purn", "rek", "rit", "sach", "sagar", "shya", "siddh",
]
_INDIC_ENDINGS = [
    "esh", "ish", "endra", "indra", "anshu", "deep", "dip", "jeet", "jit", "preet", "prit",
    "veer", "vir", "kant", "kanta", "shankar", "shekhar", "bhushan",
    "kishor", "wati", "vati", "lata", "bala", "kala", "mani", "mati", "priya",
    "shri", "nand", "nandan", "nandini", "dhar", "nath", "prasad", "ram", "lal", "chand",
    "dev", "devi", "vardhan", "ranjan", "ranjani", "eshwar", "mini", "shmi", "kshi",
    "ita", "ika", "ini", "ina", "iya", "oj", "aj", "ak", "al", "am", "an",
    "ar", "av", "ash", "pal", "raj", "das", "sen", "kumar", "kumari",
]
_DIMINUTIVE_ONSETS = [
    "bab", "gud", "mun", "pap", "chhot", "chot", "son", "mon", "ton", "pink", "rink",
    "tink", "golu", "bhol", "lall", "kall", "ball", "mall", "nall",
    "pintu", "mintu", "chintu", "bittu", "kittu", "nitu", "ritu", "situ", "mitu", "gudi",
    "bul", "chul", "phul", "dul", "kul", "mul", "tul", "shib", "tapp", "ladd", "gapp",
]
_DIMINUTIVE_TAILS = ["lu", "du", "tu", "bu", "nu", "ku", "pu", "ru", "ya", "ia", "iy", "i", "u", "a"]

_PERSO_ARABIC_ONSETS = [
    "abd", "far", "gul", "has", "hus", "imr", "irf", "jav", "kamr", "khal", "khur",
    "mahm", "maz", "moh", "muh", "mus", "nad", "nas", "naz", "nur", "parv", "raf",
    "rah", "rash", "riz", "sab", "saf", "sal", "sam", "shab", "shah", "sham",
    "shar", "soh", "tab", "tah", "tar", "tas", "wah", "was", "yas", "zah", "zai", "zar",
    "zub", "afz", "akb", "akht", "amin", "anwar", "ashr", "asif", "asla", "azh", "azim",
    "bil", "dan", "faiz", "firoz", "ham", "han", "iqb", "ishr", "ism", "jamil", "kab",
]
_PERSO_ARABIC_TAILS = [
    "an", "in", "im", "ir", "is", "iz", "ar", "at", "ad", "id", "ul", "ullah", "udin",
    "a", "i", "na", "za", "ma", "ra", "sa", "ya", "bano", "banu", "nisa", "ina", "iya",
    "een", "eem", "eed", "eer", "ood", "oor", "han", "man", "zan", "wan", "shad", "baz",
]
_SOUTH_ONSETS = [
    "venkat", "subram", "krishn", "lakshm", "naray", "sriniv", "padman", "balasub",
    "ramach", "viswan", "partha", "rangan", "chandr", "rajagop", "thirum", "murug",
    "senth", "karth", "vign", "prabh", "sarav", "anand", "arav", "bask", "dhanush",
    "ganap", "gopa", "govind", "haris", "jagad", "janak", "kalai", "kann", "kaviy",
    "kumaran", "madhav", "mahend", "manik", "meenak", "muth", "nagar", "natar", "naveen",
    "padm", "palan", "panch", "perum", "ponn", "raghav", "rajend", "ramak", "rame",
    "selv", "shanm", "sivak", "somas", "sound", "sundar", "sury", "swamin", "tamizh",
    "thang", "tyag", "umam", "vasanth", "velay", "vidy", "vija", "yogan",
]
_SOUTH_TAILS = [
    "an", "am", "ar", "esh", "appa", "amma", "iah", "ayya", "nathan", "swamy", "murthy",
    "rajan", "kumar", "devi", "priya", "vani", "valli", "mani", "selvi",
    "reddy", "naidu", "rao", "pillai", "nair", "menon", "iyer", "goud",
]

# Synthetic negative generators (pharma INN stems, clinical roots, place roots, English words)
_PHARMA_ROOTS = [
    "amox", "azithro", "ceftri", "cipro", "oflox", "levo", "panto", "ome", "rabe", "eso",
    "telmi", "losar", "olme", "amlo", "nifed", "ator", "rosu", "simva", "meto", "aten",
    "biso", "carve", "rami", "enala", "lisino", "furo", "torse", "spiro", "hydro", "glime",
    "glicla", "sita", "vilda", "tene", "empa", "dapa", "diclo", "aceclo", "ibu", "napro",
    "etori", "piro", "keto", "trama", "onda", "dompe", "metro", "tini", "orni", "alben",
    "fluco", "clotri", "acyclo", "oselta", "fexo", "cetir", "monte", "bude", "fluti",
    "predni", "dexa", "enoxa", "apixa", "rivaro", "dabi", "pheny", "leveti", "valpro",
    "carba", "gaba", "prega", "clona", "lora", "diaze", "midazo", "alpra", "escita",
    "sertra", "fluox", "olanza", "rispe", "quetia", "halo", "propo", "merop", "pipera",
    "vanco", "linezo", "doxy", "clinda", "genta", "amika", "tobra", "nitro", "isoso",
]
_MED_ROOTS = [
    "gastr", "hepat", "nephr", "cardi", "neur", "pneum", "bronch", "arthr", "dermat",
    "hemat", "haemat", "encephal", "mening", "periton", "appendic", "cholecyst", "pancreat",
    "col", "enter", "esophag", "laryng", "pharyng", "rhin", "sinus", "ot", "ophthalm",
    "cyst", "urethr", "prostat", "endometr", "myometr", "salping", "oophor", "mast",
    "thyroid", "parathyroid", "adren", "splen", "lymph", "thromb", "leuk", "erythr",
    "oste", "chondr", "myel", "spondyl", "tendin", "burs", "vascul", "phleb", "angi",
    "ather", "arteri", "amyloid", "sarcoid", "fibr", "lip", "aden", "carcin", "melan",
    "gli", "schwann", "meningi", "hemangi", "lymphangi", "terat", "myx", "chondr",
]
_PLACE_ROOTS = [
    # generic non-person place roots (directions, landforms, trades, colours, numbers)
    "sadar", "purana", "naya", "nai", "uttar", "dakshin", "purab", "paschim", "pahad", "talab",
    "bagh", "bazar", "mandi", "kila", "station", "civil", "cantt", "rail", "nahar", "pul",
    "lal", "neel", "hara", "safed", "kala", "char", "panch", "sat", "das", "hazar",
    "ganj", "kot", "garh", "pur", "abad", "khera", "tal", "pokhar", "ghat", "tila",
]
_ENGLISH_EXTRA_NEG = [
    "clinical", "medical", "hospital", "emergency", "outpatient", "inpatient", "admission",
    "discharge", "summary", "diagnosis", "prognosis", "treatment", "management", "therapy",
    "medication", "prescription", "dosage", "frequency", "duration", "morning", "evening",
    "afternoon", "bedtime", "breakfast", "dinner", "injection", "intravenous", "intramuscular",
    "subcutaneous", "sublingual", "nebulization", "infusion", "transfusion", "catheter",
    "ventilator", "oxygen", "saturation", "temperature", "respiratory", "cardiovascular",
    "neurological", "gastrointestinal", "musculoskeletal", "genitourinary", "endocrine",
    "hematological", "dermatological", "psychiatric", "obstetric", "gynecological",
    "pediatric", "geriatric", "surgical", "orthopedic", "ophthalmic", "radiological",
    "pathological", "biochemical", "microbiological", "serological", "immunological",
    "baseline", "followup", "monitoring", "observation", "examination", "auscultation",
    "palpation", "percussion", "inspection", "tenderness", "guarding", "rigidity",
    "rebound", "distension", "crepitations", "wheezing", "rhonchi", "murmurs", "gallop",
    "oriented", "conscious", "coherent", "relevant", "cooperative", "ambulatory",
    "hydrated", "nourished", "built", "afebrile", "febrile", "tachycardia", "bradycardia",
    "tachypnea", "hypotension", "hypertension", "hypoxia", "acidosis", "alkalosis",
    "bilateral", "unilateral", "proximal", "distal", "anterior", "posterior", "superior",
    "inferior", "medial", "lateral", "superficial", "deep", "localized", "generalized",
    "intermittent", "continuous", "progressive", "recurrent", "persistent", "transient",
    "resolving", "improving", "worsening", "deteriorating", "unchanged", "unremarkable",
    "significant", "nonsignificant", "inconclusive", "equivocal", "borderline", "elevated",
    "decreased", "reduced", "increased", "prolonged", "shortened", "dilated", "constricted",
    "enlarged", "atrophic", "hypertrophic", "calcified", "ossified", "fibrotic", "necrotic",
    "hemorrhagic", "ischemic", "infarcted", "occluded", "stenosed", "perforated", "ruptured",
    "fractured", "dislocated", "subluxated", "swollen", "erythematous", "indurated",
    "fluctuant", "purulent", "serous", "mucoid", "bloody", "watery", "frothy", "foul",
    "tablets", "capsules", "syrups", "ointments", "solutions", "suspensions", "powders",
    "sachets", "inhalers", "sprays", "lotions", "creams", "patches", "suppositories",
    "department", "building", "ground", "corridor", "reception", "counter", "billing",
    "insurance", "document", "certificate", "register", "records", "archive", "sample",
    "specimen", "container", "vacutainer", "syringe", "needle", "cannula", "dressing",
    "bandage", "splint", "plaster", "sutures", "staples", "drains", "tubing", "monitor",
]


def build_synthetic_dataset(seed: int = 42) -> list[tuple[str, int]]:
    rng = random.Random(seed)
    pos: set[str] = set()
    neg: set[str] = set()

    # Positive class: synthetic compositional Indian names + pan-Indian surnames
    for s in SURNAMES_LATIN:
        if len(s) >= 3:
            pos.add(s)

    for _ in range(2600):
        st = rng.choice(_SANSKRIT_STEMS)
        en = rng.choice(_INDIC_ENDINGS)
        w = norm_latin(st + en)
        if 4 <= len(w) <= 13:
            pos.add(w)

    for _ in range(900):
        st = rng.choice(_DIMINUTIVE_ONSETS)
        en = rng.choice(_DIMINUTIVE_TAILS)
        w = norm_latin(st + en)
        if 4 <= len(w) <= 9:
            pos.add(w)

    for _ in range(1100):
        st = rng.choice(_PERSO_ARABIC_ONSETS)
        en = rng.choice(_PERSO_ARABIC_TAILS)
        w = norm_latin(st + en)
        if 4 <= len(w) <= 12:
            pos.add(w)

    for _ in range(900):
        st = rng.choice(_SOUTH_ONSETS)
        en = rng.choice(_SOUTH_TAILS)
        w = norm_latin(st + en)
        if 4 <= len(w) <= 14:
            pos.add(w)

    # Negative class: stoplist + synthetic pharma + synthetic clinical + synthetic places + English
    for w in STOP_LATIN:
        nl = norm_latin(w)
        if len(nl) >= 3 and nl not in SURNAMES_LATIN:
            neg.add(nl)
    for w in _ENGLISH_EXTRA_NEG:
        nl = norm_latin(w)
        if len(nl) >= 3:
            neg.add(nl)

    for _ in range(1600):
        w = norm_latin(rng.choice(_PHARMA_ROOTS) + rng.choice(PHARMA_SUFFIXES))
        if len(w) >= 5:
            neg.add(w)

    for _ in range(1400):
        w = norm_latin(rng.choice(_MED_ROOTS) + rng.choice(MED_SUFFIXES))
        if len(w) >= 5:
            neg.add(w)

    for _ in range(600):
        w = norm_latin(rng.choice(_PLACE_ROOTS) + rng.choice(PLACE_SUFFIXES))
        if len(w) >= 5:
            neg.add(w)

    # Generic vocabulary shipped with Raksha (no names): stop/common words, clinical terms, public places
    from raksha.lexicon import get_lexicon
    lex = get_lexicon()
    for w in sorted(lex.common | lex.stop_latin | lex.medical | lex.places):
        nl = norm_latin(w)
        if len(nl) >= 3 and re.fullmatch(r"[a-z]+", w or "") and nl not in SURNAMES_LATIN:
            neg.add(nl)

    # Ensure disjoint sets
    pos -= neg

    data = [(w, 1) for w in sorted(pos)] + [(w, 0) for w in sorted(neg)]
    rng.shuffle(data)
    return data


def train_logistic(
    train_data: list[tuple[str, int]],
    epochs: int = 18,
    lr: float = 0.12,
    l2: float = 1e-4,
    min_df: int = 3,
    seed: int = 42,
) -> tuple[float, dict[str, float]]:
    # Filter rare features to keep weights compact & prevent overfitting
    df = Counter()
    cached = []
    for tok, y in train_data:
        feats = list(dict.fromkeys(extract_token_features(tok)))
        df.update(feats)
        cached.append((feats, y))

    vocab = {f for f, c in df.items() if c >= min_df}
    cached = [([f for f in feats if f in vocab], y) for feats, y in cached]

    weights: dict[str, float] = {f: 0.0 for f in sorted(vocab)}
    bias = 0.0
    rng = random.Random(seed)

    for ep in range(epochs):
        rng.shuffle(cached)
        step_lr = lr / (1.0 + 0.15 * ep)
        for feats, y in cached:
            z = bias + sum(weights[f] for f in feats)
            if z >= 0:
                p = 1.0 / (1.0 + math.exp(-min(z, 30.0)))
            else:
                ez = math.exp(max(z, -30.0))
                p = ez / (1.0 + ez)
            err = y - p
            bias += step_lr * err
            for f in feats:
                weights[f] += step_lr * (err - l2 * weights[f])

    # Prune near-zero weights & round for compact JSON
    pruned = {f: round(w, 4) for f, w in sorted(weights.items()) if abs(w) >= 0.06}
    return round(bias, 4), pruned


def evaluate(bias: float, weights: dict[str, float], val_data: list[tuple[str, int]]) -> dict[str, float]:
    tp = fp = fn = tn = 0
    for tok, y in val_data:
        z = bias + sum(weights.get(f, 0.0) for f in extract_token_features(tok))
        pred = 1 if z >= 0.0 else 0
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 1:
            fn += 1
        else:
            tn += 1
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    return {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4), "n": len(val_data)}


def main() -> None:
    data = build_synthetic_dataset(seed=42)
    split = int(0.85 * len(data))
    train_data, val_data = data[:split], data[split:]

    bias, weights = train_logistic(train_data)
    metrics = evaluate(bias, weights, val_data)

    out_path = ROOT / "raksha" / "namefind_weights.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"_about": "Raksha unseen-name scorer: logistic regression over char n-gram + morphology "
                         "features, trained by scripts/train_namefind.py on synthetic tokens only (seed 42). "
                         "params = %d weights + 1 bias" % len(weights), "bias": bias, "weights": weights}
    out_path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    size_kb = out_path.stat().st_size / 1024.0
    print(f"Saved {len(weights)} weights ({size_kb:.1f} KB) -> {out_path}")
    print(f"Synthetic holdout metrics: {metrics}")


if __name__ == "__main__":
    main()