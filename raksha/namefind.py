"""Offline, deterministic unseen Indian name detector for English, Hinglish, and Devanagari.

Combines:
  1. Hard clinical/medical/drug/doctor/hospital/eponym/Hinglish guards & stoplists.
  2. Indian name morphology & surname/suffix cues (Latin + Devanagari).
  3. Hinglish & Hindi grammar cues (postpositions ne/ko/ka/ki/ke, kinship/honorifics,
     temporal-clinical predicates).
  4. Lightweight L2-regularized character n-gram + phonological linear classifier
     (loads compact JSON weights from raksha/namefind_weights.json, with built-in fallback).
  5. Cross-script within-document and batch-level name propagation.

Stdlib only; zero network/LLM dependencies; strictly deterministic.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

try:
    from .translit import devanagari_to_latin as _ext_deva_to_latin
    from .translit import fold as _ext_fold
    from .translit import has_devanagari as _ext_has_deva
except ImportError:  # standalone fallback for tests/scripts
    _ext_deva_to_latin = None
    _ext_fold = None
    _ext_has_deva = None


# ------------------------------------------------------------------ Transliteration & folding
_DEVA_RE = re.compile(r"[\u0900-\u097F]")
_TOK_RX = re.compile(r"[A-Za-z]+(?:'(?![sS]\b)[A-Za-z]+)*\.?|[\u0900-\u0963\u0970-\u097F]+\.?")

_IND_VOWELS = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo", "ऋ": "ri",
    "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au", "ऑ": "o", "ऍ": "e",
}
_MATRAS = {
    "ा": "a", "ि": "i", "ी": "i", "ु": "u", "ू": "u", "ृ": "ri",
    "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "ॉ": "o", "ॅ": "e",
}
_CONSONANTS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n",
    "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "n",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n",
    "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m",
    "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh",
    "ष": "sh", "स": "s", "ह": "h", "ळ": "l",
    "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh", "फ़": "f", "य़": "y",
}
_VIRAMA = "्"
_NUKTA = "़"


def has_devanagari(s: str) -> bool:
    if _ext_has_deva is not None:
        return _ext_has_deva(s)
    return bool(_DEVA_RE.search(s))


def deva_to_latin_soft(word: str) -> str:
    """Lossless-leaning Devanagari->Latin transliteration preserving vowels/aspirates for n-grams."""
    out = []
    n = len(word)
    i = 0
    while i < n:
        ch = word[i]
        # Handle nukta digraphs
        if i + 1 < n and word[i + 1] == _NUKTA and (ch + _NUKTA) in _CONSONANTS:
            base = _CONSONANTS[ch + _NUKTA]
            i += 2
            if i < n and word[i] == _VIRAMA:
                out.append(base)
                i += 1
            elif i < n and word[i] in _MATRAS:
                out.append(base + _MATRAS[word[i]])
                i += 1
            else:
                # Word-final schwa deletion
                out.append(base if i >= n else base + "a")
            continue
        if ch in _IND_VOWELS:
            out.append(_IND_VOWELS[ch])
            i += 1
        elif ch in _CONSONANTS:
            base = _CONSONANTS[ch]
            i += 1
            if i < n and word[i] == _VIRAMA:
                out.append(base)
                i += 1
            elif i < n and word[i] in _MATRAS:
                out.append(base + _MATRAS[word[i]])
                i += 1
            else:
                # Simple Hindi schwa deletion at word end or before C+matra in 3+ syllable words
                is_end = (i >= n) or (word[i] in "ंँः")
                if is_end and out:
                    out.append(base)
                elif (
                    len(out) >= 1
                    and i + 1 < n
                    and word[i] in _CONSONANTS
                    and word[i + 1] in _MATRAS
                    and not out[-1].endswith(("k", "g", "t", "d", "p", "b", "r", "l", "m", "n", "s", "h", "v", "y"))
                ):
                    out.append(base)
                else:
                    out.append(base + "a")
        elif ch in ("ं", "ँ"):
            out.append("n")
            i += 1
        elif ch == "ः":
            out.append("h")
            i += 1
        else:
            i += 1
    return "".join(out)


def norm_latin(word: str) -> str:
    """Light phonetic normalization preserving vowels & aspirates for morphology + n-grams."""
    w = word.strip().rstrip(".")
    if has_devanagari(w):
        w = deva_to_latin_soft(w)
    w = w.lower()
    w = re.sub(r"[^a-z]", "", w)
    if not w:
        return ""
    w = w.replace("aa", "a").replace("ee", "i").replace("oo", "u")
    w = re.sub(r"([bcdfghjklmnpqrstvwxyz])\1+", r"\1", w)
    return w


def prop_key(word: str) -> str:
    """Cross-script key for document/batch propagation."""
    w = word.strip().rstrip(".")
    if _ext_fold is not None:
        if has_devanagari(w) and _ext_deva_to_latin is not None:
            return _ext_fold(_ext_deva_to_latin(w))
        return _ext_fold(w)
    # Fallback folding: collapse aspirates and long vowels
    nl = norm_latin(w)
    for a, b in (("ph", "f"), ("bh", "b"), ("dh", "d"), ("gh", "g"), ("jh", "j"),
                 ("kh", "k"), ("th", "t"), ("chh", "c"), ("ch", "c"), ("sh", "s"), ("w", "v")):
        nl = nl.replace(a, b)
    return nl


# ------------------------------------------------------------------ Lightweight fallback Span
class NameSpan:
    __slots__ = ("start", "end", "kind", "text", "role", "meta")

    def __init__(self, start, end, kind, text, role=None, meta=None):
        self.start = start
        self.end = end
        self.kind = kind
        self.text = text
        self.role = role
        self.meta = meta or {}

    def __repr__(self):
        return f"NameSpan({self.start},{self.end},{self.kind},{self.text!r},{self.role})"


# ------------------------------------------------------------------ Domain guards & stoplists
DOCTOR_TITLES = frozenset({"dr", "doctor", "prof", "professor", "डॉ", "डा", "डॉक्टर"})
MED_DEGREES = frozenset({
    "mbbs", "md", "ms", "dm", "mch", "dnb", "bams", "bhms", "bums", "bds", "mds",
    "frcs", "mrcp", "dch", "dgo", "doms", "ddvl", "fcps", "phd",
})
DRUG_PREFIXES = frozenset({
    "tab", "tabs", "tablet", "tablets", "cap", "caps", "capsule", "capsules",
    "inj", "injection", "syr", "syrup", "susp", "suspension", "oint", "ointment",
    "drop", "drops", "gel", "cream", "lotion", "powder", "sachet", "neb",
    "inhaler", "spray", "sol", "solution", "inf", "infusion", "iv", "im", "sc",
    "rx", "t", "c", "s", "टैब", "कैप", "इंजेक्शन", "सिरप", "गोली",
})

FACILITY_HEADS = frozenset({
    "hospital", "hospitals", "ward", "wards", "icu", "nicu", "picu", "micu", "sicu", "ccu",
    "opd", "ipd", "ot", "clinic", "polyclinic", "dispensary", "sadan", "bhawan", "bhavan",
    "nursing", "medical", "college", "institute", "centre", "center", "lab", "labs",
    "laboratory", "diagnostics", "diagnostic", "pathology", "radiology", "pharmacy",
    "chemist", "druggist", "trust", "foundation", "memorial", "charitable", "mission",
    "chikitsalaya", "aushadhalaya", "aspatal", "haspatal", "dawakhana", "health",
    "nagar", "vihar", "colony", "enclave", "extension", "extn", "road", "marg", "path",
    "chowk", "chauk", "bazar", "bazaar", "market", "gali", "mohalla", "street", "lane",
    "sector", "phase", "block", "wing", "unit", "floor", "room", "bed", "cabin",
    "dept", "department", "division", "section", "campus", "building", "complex",
    "district", "dist", "distt", "tehsil", "tahsil", "thana", "village", "gram", "gaon",
    "mandir", "temple", "masjid", "mosque", "gurudwara", "church", "station", "junction",
    "airport", "depot", "stand", "plaza", "tower", "towers", "apartments", "residency",
    "अस्पताल", "चिकित्सालय", "औषधालय", "वार्ड", "क्लिनिक", "भवन", "सदन", "संस्थान",
    "नगर", "विहार", "कॉलोनी", "रोड", "मार्ग", "चौक", "बाजार", "गली", "मोहल्ला",
    "जिला", "तहसील", "थाना", "ग्राम", "गाँव", "गांव", "मंदिर", "मस्जिद", "विभाग",
})

EPONYM_HEADS_RX = re.compile(
    r"^(?:'s?|s)?\s+(?:disease|syndrome|palsy|sign|test|law|tube|catheter|score|lactate|"
    r"solution|phenomenon|fracture|ulcer|lymphoma|point|reflex|maneuver|manoeuvre|triad|"
    r"criteria|scale|index|classification|grading|staging|procedure|operation|incision|"
    r"anemia|anaemia|thyroiditis|nephropathy|cardiomyopathy|fever|azar)\b",
    re.I,
)
DOSE_RIGHT_RX = re.compile(
    r"^\s*(?:"
    r"\d+(?:\.\d+)?\s*(?:mg|mcg|ug|µg|gm|g|kg|ml|l|iu|u|units?|meq|%|mmhg|bpm|tabs?|caps?|drops?|puffs?)(?![a-z])"
    r"|[0-5]\s*-\s*[0-5]\s*-\s*[0-5](?:\s*-\s*[0-5])?\b"
    r"|(?:od|bd|tds|qid|hs|sos|stat|iv|im|sc|po|pr|sl)\b"
    r"|(?:tablet|tab|capsule|cap|syrup|syr|injection|inj|ointment|oint|drops|cream|gel|suspension|inhaler)\b"
    r")",
    re.I,
)
LAB_RIGHT_RX = re.compile(
    r"^\s*(?:"
    r"[:=]\s*\d+(?:\.\d+)?\s*(?:g/dl|mg/dl|mmol/l|meq/l|iu/l|u/l|%|/cumm|/ul)"
    r"|(?:positive|negative|reactive|non-?reactive|elevated|raised|deranged|normal|high|low|borderline|equivocal)\b"
    r")",
    re.I,
)

# Unambiguous pharmacological & clinical suffixes (checked on norm_latin, min len >= 6)
PHARMA_SUFFIXES = (
    "cillin", "mycin", "floxacin", "prazole", "sartan", "statin", "pril", "olol",
    "dipine", "gliptin", "formin", "parin", "zole", "tidine", "setron", "triptan",
    "cycline", "profen", "fenac", "codone", "phylline", "caine", "sone", "lone",
    "cort", "vir", "mab", "nib", "pam", "lam", "conazole", "lukast", "pamide",
    "semide", "thiazide", "glitazone", "gliflozin", "vaptan", "dronate", "mustine",
    "platin", "rubicin", "taxel", "tecan", "tinib", "zumab", "ximab", "umab",
    "vastatin", "oxacin", "navir", "ciclovir", "ganciclovir", "barb", "barbital",
)
MED_SUFFIXES = (
    "itis", "osis", "emia", "aemia", "pathy", "ectomy", "otomy", "ostomy", "plasty",
    "scopy", "graphy", "gram", "algia", "rrhea", "rrhoea", "megaly", "penia",
    "plasia", "trophy", "lysis", "stasis", "oma", "cyte", "blast", "meter",
    "metric", "genic", "static", "cidal", "uretic", "biotic", "mycosis", "spasm",
    "plegia", "paresis", "phobia", "thorax", "cele", "rrhexis", "sclerosis",
    "stenosis", "malacia", "lithiasis", "tripsy", "centesis", "desis",
)
PLACE_SUFFIXES = (
    "pur", "puram", "pura", "ganj", "abad", "garh", "nagar", "vihar", "palli",
    "patnam", "pattinam", "wadi", "wada", "gaon", "gram", "kheda", "khera",
    "kot", "kote", "guda", "pet", "peta", "bazar", "bazaar", "chowk", "ghat",
    "sarai", "bagh", "tola", "patti", "dih", "chak", "mau", "khurd", "kalan",
)

# Comprehensive Latin stoplist (English + Hinglish + Indian clinic drugs/terms/cities)
STOP_LATIN = frozenset({
    # English function & clinical discourse words
    "a", "an", "the", "and", "or", "but", "if", "then", "else", "for", "of", "in", "on", "at",
    "to", "from", "by", "with", "without", "within", "about", "above", "below", "under", "over",
    "between", "into", "onto", "through", "during", "before", "after", "since", "until", "till",
    "as", "is", "am", "are", "was", "were", "be", "been", "being", "has", "have", "had", "do",
    "does", "did", "done", "will", "would", "shall", "should", "can", "could", "may", "might",
    "must", "not", "no", "nor", "yes", "so", "too", "very", "just", "only", "also", "even",
    "still", "yet", "already", "now", "here", "there", "where", "when", "why", "how", "who",
    "whom", "whose", "which", "what", "that", "this", "these", "those", "he", "him", "his",
    "she", "her", "hers", "it", "its", "we", "us", "our", "you", "your", "they", "them", "their",
    "all", "any", "some", "many", "much", "more", "most", "few", "several", "both", "each",
    "every", "other", "another", "same", "such", "own", "new", "old", "good", "bad", "well",
    "better", "best", "worse", "worst", "first", "second", "third", "last", "next", "previous",
    "per", "via", "due", "non", "nil", "none", "na", "ok", "okay", "etc", "eg", "ie", "vs",
    "please", "kindly", "thanks", "thank", "dear", "hello", "hi", "regards", "sincerely",
    "today", "tomorrow", "yesterday", "morning", "evening", "night", "afternoon", "noon",
    "daily", "weekly", "monthly", "yearly", "hourly", "regular", "irregular", "often", "always",
    "never", "sometimes", "recently", "suddenly", "gradually", "slowly", "rapidly",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "mon", "tue", "tues", "wed", "thu", "thur", "thurs", "fri", "sat", "sun",
    "january", "february", "march", "april", "june", "july", "august", "september",
    "october", "november", "december", "jan", "feb", "mar", "apr", "jun", "jul", "aug",
    "sep", "sept", "oct", "nov", "dec",
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    "year", "years", "yr", "yrs", "month", "months", "week", "weeks", "day", "days",
    "hour", "hours", "hr", "hrs", "minute", "minutes", "min", "mins", "time", "date",
    # Admin / Roles / Form headers
    "name", "patient", "pt", "pts", "age", "sex", "gender", "male", "female", "man", "woman",
    "boy", "girl", "child", "infant", "neonate", "adult", "elderly", "baby", "master",
    "address", "addr", "phone", "mobile", "mob", "contact", "tel", "email", "pin", "pincode",
    "id", "uhid", "mrn", "ipd", "opd", "abha", "aadhaar", "aadhar", "pan", "uid", "num", "number",
    "doctor", "dr", "nurse", "sister", "brother", "staff", "wardboy", "ayah", "attendant",
    "guardian", "relative", "family", "informant", "witness", "visitor", "sir", "madam", "maam",
    "father", "mother", "husband", "wife", "son", "daughter", "spouse", "parent", "parents",
    "bill", "billing", "paid", "unpaid", "due", "total", "amount", "balance", "cash", "card",
    "receipt", "invoice", "insurance", "policy", "claim", "tpa", "cghs", "esic", "pmjay",
    # Clinical verbs / statuses / discourse
    "admitted", "admit", "admission", "discharged", "discharge", "referred", "referral",
    "transferred", "transfer", "shifted", "shift", "expired", "death", "died", "lama", "dama",
    "absconded", "followup", "follow", "review", "revisit", "visit", "visited", "came", "come",
    "went", "brought", "accompanied", "presents", "presented", "presenting", "complains",
    "complained", "complaining", "complaints", "complaint", "reports", "reported", "reporting",
    "states", "stated", "denies", "denied", "gives", "given", "takes", "taken", "taking",
    "started", "start", "stopped", "stop", "continued", "continue", "continuing", "advised",
    "advice", "prescribed", "planned", "plan", "scheduled", "pending", "awaited", "done",
    "performed", "conducted", "checked", "check", "examined", "exam", "examination", "assessed",
    "evaluated", "monitored", "monitor", "observed", "treated", "treatment", "managed",
    "operated", "operation", "surgery", "surgical", "procedure", "intubated", "extubated",
    "catheterized", "transfused", "vaccinated", "immunized", "counseled", "counselled",
    "explained", "discussed", "informed", "seen", "found", "noted", "shows", "showed",
    "showing", "suggests", "suggestive", "confirmed", "suspected", "probable", "possible",
    "likely", "unlikely", "ruled", "rule", "known", "case", "history", "summary", "note",
    "notes", "sheet", "chart", "record", "report", "result", "results", "finding", "findings",
    "impression", "diagnosis", "provisional", "final", "differential", "order", "orders",
    "urgent", "routine", "emergency", "elective", "repeat", "avoid", "increase", "decrease",
    "increased", "decreased", "taper", "tapering", "switch", "switched", "refused", "agreed",
    "normal", "abnormal", "stable", "unstable", "critical", "serious", "guarded", "poor",
    "fair", "improving", "improved", "worsening", "worsened", "resolved", "persistent",
    "recurrent", "acute", "chronic", "subacute", "mild", "moderate", "severe", "high", "low",
    "positive", "negative", "reactive", "nonreactive", "afebrile", "febrile", "conscious",
    "oriented", "alert", "drowsy", "unconscious", "cooperative", "ambulatory", "bedridden",
    "hydrated", "dehydrated", "anemic", "anaemic", "icteric", "cyanotic", "pallor", "icterus",
    "cyanosis", "clubbing", "edema", "oedema", "lymphadenopathy", "vitals", "stable",
    # Hospital / medical specialties / anatomy / symptoms / diseases
    "hospital", "ward", "icu", "nicu", "picu", "micu", "sicu", "ccu", "ot", "er", "triage",
    "casualty", "clinic", "medical", "medicine", "general", "private", "deluxe", "cabin",
    "bed", "room", "floor", "wing", "block", "unit", "dept", "department", "centre", "center",
    "institute", "pharmacy", "lab", "labs", "pathology", "radiology", "cardiology", "neurology",
    "orthopedic", "orthopaedic", "pediatric", "paediatric", "gynae", "gynec", "obgyn", "ent",
    "ophthalmology", "dermatology", "oncology", "nephrology", "urology", "gastro", "maternity",
    "labour", "labor", "trauma", "burn", "burns", "dialysis", "isolation", "nursing", "home",
    "fever", "cough", "cold", "coryza", "pain", "ache", "headache", "backache", "bodyache",
    "vomiting", "vomit", "nausea", "diarrhea", "diarrhoea", "loose", "motions", "constipation",
    "weakness", "fatigue", "lethargy", "giddiness", "dizziness", "vertigo", "syncope",
    "breathlessness", "dyspnea", "dyspnoea", "sob", "wheezing", "stridor", "palpitation",
    "palpitations", "bleeding", "hemorrhage", "haemorrhage", "swelling", "lump", "mass",
    "itching", "pruritus", "rash", "rashes", "ulcer", "wound", "abscess", "boil", "injury",
    "fracture", "sprain", "strain", "dislocation", "spasm", "cramp", "cramps", "numbness",
    "tingling", "tremor", "seizure", "seizures", "convulsion", "fit", "fits", "chills",
    "rigors", "sweating", "anorexia", "weight", "loss", "gain", "insomnia", "burning",
    "micturition", "hematuria", "oliguria", "dysuria", "polyuria", "polydipsia",
    "covid", "dengue", "malaria", "typhoid", "chikungunya", "jaundice", "pneumonia", "asthma",
    "copd", "diabetes", "diabetic", "hypertension", "hypertensive", "htn", "dm", "cad", "ckd",
    "aki", "cld", "uti", "urti", "lrti", "gerd", "pud", "tb", "tuberculosis", "sepsis",
    "shock", "stroke", "cva", "tia", "angina", "mi", "chf", "ccf", "afib", "arrhythmia",
    "anemia", "anaemia", "thrombocytopenia", "leukocytosis", "hypoglycemia", "hyperglycemia",
    "hyponatremia", "hyperkalemia", "hypokalemia", "hypothyroidism", "hyperthyroidism",
    "hepatitis", "cirrhosis", "ascites", "effusion", "hernia", "migraine", "epilepsy",
    "allergy", "allergic", "infection", "infectious", "viral", "bacterial", "fungal",
    "parasitic", "inflammation", "inflammatory", "cellulitis", "gangrene", "ischemia",
    "infarction", "embolism", "thrombosis", "aneurysm", "stenosis", "prolapse", "calculi",
    "stone", "stones", "cyst", "polyp", "tumor", "tumour", "cancer", "malignancy", "benign",
    "malignant", "pregnant", "pregnancy", "antenatal", "postnatal", "delivery", "cesarean",
    "caesarean", "lscs", "abortion", "miscarriage", "menorrhagia", "amenorrhea", "pcos",
    # Anatomy & directions
    "head", "scalp", "face", "forehead", "eye", "eyes", "ear", "ears", "nose", "nasal",
    "mouth", "oral", "tongue", "tooth", "teeth", "throat", "pharynx", "larynx", "neck",
    "chest", "thorax", "breast", "heart", "lung", "lungs", "abdomen", "abdominal", "stomach",
    "liver", "spleen", "pancreas", "gallbladder", "kidney", "kidneys", "renal", "bladder",
    "bowel", "intestine", "colon", "rectum", "rectal", "pelvis", "pelvic", "uterus", "ovary",
    "prostate", "vaginal", "groin", "back", "spine", "spinal", "lumbar", "cervical",
    "shoulder", "arm", "elbow", "forearm", "wrist", "hand", "finger", "thumb", "hip",
    "thigh", "knee", "leg", "calf", "ankle", "foot", "feet", "toe", "skin", "muscle",
    "bone", "joint", "nerve", "vein", "artery", "blood", "urine", "stool", "sputum", "swab",
    "plasma", "serum", "fluid", "csf", "pus", "mucus", "tissue", "biopsy", "brain",
    "left", "right", "bilateral", "unilateral", "upper", "lower", "anterior", "posterior",
    "medial", "lateral", "proximal", "distal", "central", "peripheral", "diffuse", "focal",
    # Labs, diagnostics, vitals
    "bp", "hr", "pr", "rr", "spo2", "temp", "temperature", "pulse", "bmi", "gcs", "height",
    "xray", "usg", "ultrasound", "sonography", "ct", "mri", "ecg", "ekg", "echo", "eeg",
    "emg", "endoscopy", "colonoscopy", "bronchoscopy", "angiography", "mammography",
    "cbc", "hb", "hemoglobin", "haemoglobin", "tlc", "dlc", "plt", "platelet", "platelets",
    "rbc", "wbc", "pcv", "mcv", "mch", "mchc", "esr", "crp", "pct", "procalcitonin",
    "lft", "kft", "rft", "tft", "abg", "vbg", "rbs", "fbs", "ppbs", "hba1c", "sugar",
    "glucose", "bilirubin", "sgot", "sgpt", "ast", "alt", "alp", "ggt", "albumin", "globulin",
    "protein", "urea", "bun", "creatinine", "uric", "sodium", "potassium", "chloride",
    "calcium", "magnesium", "phosphate", "bicarbonate", "lactate", "ammonia", "amylase",
    "lipase", "cholesterol", "triglycerides", "hdl", "ldl", "vldl", "lipid", "tsh", "t3", "t4",
    "widal", "ns1", "mp", "hiv", "hbsag", "hcv", "vdrl", "pt", "inr", "aptt", "ddimer",
    "troponin", "bnp", "ferritin", "iron", "folate", "vitamin", "culture", "sensitivity",
    # Common Indian clinical drugs & brands (non-exhaustive; suffix & prefix guards cover unseen ones)
    "paracetamol", "acetaminophen", "dolo", "crocin", "calpol", "pacimol", "combiflam",
    "ibuprofen", "brufen", "diclofenac", "voveran", "zerodol", "aceclofenac", "meftal",
    "mefenamic", "aspirin", "ecosprin", "disprin", "clopidogrel", "clopitab", "tramadol",
    "morphine", "fentanyl", "ketorolac", "piroxicam", "etoricoxib", "naproxen", "ultram",
    "augmentin", "amoxycillin", "amoxicillin", "ampicillin", "azithral", "azithromycin",
    "ciplox", "ciprofloxacin", "ofloxacin", "levofloxacin", "norflox", "norfloxacin",
    "monocef", "taxim", "ceftriaxone", "cefixime", "cefuroxime", "cephalexin", "cefpodoxime",
    "meropenem", "imipenem", "piperacillin", "tazobactam", "vancomycin", "linezolid",
    "doxycycline", "doxy", "metrogyl", "flagyl", "metronidazole", "tinidazole", "ornidazole",
    "albendazole", "ivermectin", "fluconazole", "clotrimazole", "acyclovir", "oseltamivir",
    "pan", "pantop", "pantocid", "pantoprazole", "omeprazole", "omez", "rabeprazole", "razo",
    "esomeprazole", "nexpro", "rantac", "ranitidine", "famotidine", "gelusil", "digene",
    "mucaine", "sucralfate", "ondem", "emeset", "ondansetron", "perinorm", "domperidone",
    "domstal", "duphalac", "lactulose", "cremaffin", "dulcolax", "isabgol", "loperamide",
    "metformin", "glycomet", "glimepiride", "amaryl", "gliclazide", "sitagliptin", "januvia",
    "vildagliptin", "teneligliptin", "empagliflozin", "dapagliflozin", "insulin", "lantus",
    "mixtard", "novorapid", "humalog", "actrapid", "glargine",
    "telma", "telmisartan", "losartan", "olmesartan", "amlokind", "amlodipine", "stamlo",
    "atenolol", "metoprolol", "bisoprolol", "nebivolol", "propranolol", "carvedilol",
    "ramipril", "enalapril", "lisinopril", "lasix", "furosemide", "dytor", "torsemide",
    "spironolactone", "aldactone", "hydrochlorothiazide", "prazosin", "clonidine",
    "atorva", "atorvastatin", "rosuvas", "rosuvastatin", "fenofibrate", "ezetimibe",
    "shelcal", "calcimax", "becosules", "neurobion", "optineuron", "cobadex", "limcee",
    "zincovit", "supradyn", "revital", "folvite", "orofer", "autrin", "dexorange", "liv",
    "ors", "electral", "saline", "ringer", "dextrose", "dns", "rl", "ns", "mannitol",
    "betadine", "savlon", "dettol", "soframycin", "mupirocin", "neomycin", "fusidic",
    "allegra", "fexofenadine", "cetirizine", "levocetirizine", "montair", "montelukast",
    "avil", "pheniramine", "atarax", "hydroxyzine", "chlorpheniramine",
    "deriphyllin", "theophylline", "doxofylline", "budecort", "budesonide", "duolin",
    "asthalin", "salbutamol", "levosalbutamol", "ipratropium", "tiotropium", "foracort",
    "seretide", "fluticasone", "prednisolone", "wysolone", "methylprednisolone", "dexona",
    "dexamethasone", "hydrocortisone", "defcort",
    "thyronorm", "eltroxin", "levothyroxine", "neomercazole", "carbimazole",
    "heparin", "enoxaparin", "clexane", "warfarin", "acitrom", "apixaban", "rivaroxaban",
    "dabigatran", "tranexamic", "pause", "ethamsylate", "adrenaline", "atropine",
    "dopamine", "dobutamine", "norad", "noradrenaline", "vasopressin", "amiodarone",
    "digoxin", "nitroglycerin", "sorbitrate", "isosorbide", "nicorandil", "ivabradine",
    "phenytoin", "eptoin", "levetiracetam", "levipil", "valproate", "encorate",
    "carbamazepine", "tegretol", "oxcarbazepine", "gabapentin", "pregabalin", "clonazepam",
    "lorazepam", "diazepam", "midazolam", "alprazolam", "zolpidem", "escitalopram",
    "sertraline", "fluoxetine", "amitriptyline", "olanzapine", "risperidone", "quetiapine",
    "haloperidol", "propofol", "ketamine", "bicarb", "kcl", "albumin",
    "tab", "tablet", "cap", "capsule", "syr", "syrup", "inj", "injection", "oint", "ointment",
    "drop", "drops", "susp", "gel", "cream", "lotion", "powder", "sachet", "inhaler", "neb",
    "drip", "infusion", "dose", "dosage", "regimen", "course", "stat", "sos", "od", "bd",
    "tds", "qid", "hs", "ac", "pc", "iv", "im", "sc", "po",
    # Hinglish clinical, symptom & everyday vocabulary
    "bukhar", "bukhaar", "dard", "khansi", "khaansi", "zukam", "zukaam", "jukam", "sardi",
    "garmi", "ulti", "ultiya", "ultiyan", "dast", "pechis", "chakkar", "kamzori", "kamjori",
    "sujan", "soojan", "khujli", "jalan", "ghabrahat", "bechaini", "saans", "sans", "dum",
    "pet", "sir", "sar", "kamar", "ghutna", "ghutne", "pair", "pairo", "haath", "hath",
    "gala", "aankh", "ankh", "aankhe", "kaan", "naak", "daant", "chhati", "seena", "peeth",
    "khoon", "khun", "peshab", "peshaab", "tatti", "latrine", "mal", "kaf", "balgam",
    "dawai", "dawa", "dawaiya", "dawaiyan", "goli", "goliya", "goliyan", "suyi", "sui",
    "patti", "tanka", "tanke", "jaanch", "janch", "parchi", "parcha", "kagaz",
    "mareez", "mariz", "marij", "rogi", "bimar", "beemar", "bimari", "beemari", "takleef",
    "taklif", "pareshani", "ilaaj", "ilaj", "upchar", "aspatal", "haspatal", "dawakhana",
    "aaj", "aj", "kal", "parso", "parson", "subah", "subha", "shaam", "sham", "raat", "rat",
    "dopahar", "din", "mahina", "mahine", "saal", "sal", "baras", "hafta", "hafte", "ghanta",
    "ghante", "abhi", "pehle", "pahle", "baad", "bad", "phir", "fir", "dobara", "hamesha",
    "kabhi", "roz", "roj", "rozana", "lagatar", "achanak", "dheere", "tez", "halka", "halki",
    "khana", "khaana", "khaya", "khayi", "khaye", "khake", "peena", "pina", "piya", "piyi",
    "pani", "paani", "doodh", "dudh", "chai", "roti", "chawal", "dal", "sabzi", "fal",
    "neend", "nind", "aaram", "aram", "chutti", "chhutti", "bharti", "bharati", "dakhil",
    "daakhil", "theek", "thik", "achha", "accha", "acha", "bura", "zyada", "jyada", "zada",
    "kam", "thoda", "thodi", "thode", "bahut", "bohot", "bohat", "bilkul", "poora", "pura",
    "nahi", "nahin", "nai", "na", "mat", "haan", "han", "ji", "kya", "kyu", "kyun", "kaise",
    "kahan", "kaha", "kab", "kaun", "kon", "kis", "kisko", "kiska", "kiski", "kiske",
    "yeh", "ye", "woh", "wo", "usko", "uska", "uski", "uske", "usse", "usne", "unhe", "unhen",
    "unke", "unka", "unki", "unse", "unhone", "isko", "iska", "iski", "iske", "isse", "isne",
    "inhe", "inke", "inka", "inki", "hum", "ham", "humne", "humko", "main", "mein", "me",
    "maine", "mujhe", "mujhko", "tum", "tumne", "tumko", "aap", "ap", "aapne", "aapko",
    "apna", "apni", "apne", "mera", "meri", "mere", "tera", "teri", "tere", "sab", "sabhi",
    "kuch", "kuchh", "koi", "aur", "ya", "par", "lekin", "magar", "kyunki", "agar", "toh",
    "to", "bhi", "hi", "tak", "se", "ko", "ne", "ka", "ki", "ke", "liye", "liya", "li", "di",
    "diya", "diye", "dena", "lena", "kar", "kara", "kari", "kare", "karna", "karni", "karne",
    "karta", "karti", "karte", "kiya", "kiye", "hota", "hoti", "hote", "hona", "hua", "hui",
    "hue", "hai", "hain", "he", "tha", "thi", "the", "hoga", "hogi", "honge", "raha", "rahi",
    "rahe", "rehna", "gaya", "gayi", "gaye", "gai", "aaya", "aayi", "aaye", "aya", "ayi",
    "aye", "jana", "jaana", "aana", "ana", "ja", "aa", "la", "laya", "layi", "laye", "lana",
    "bata", "bataya", "batayi", "bataye", "bola", "boli", "bole", "bolna", "dekha", "dekhi",
    "dekhe", "dekhna", "sun", "suna", "suni", "laga", "lagi", "lage", "lagna", "mil", "mila",
    "mili", "mile", "milna", "rakha", "rakhi", "rakhna", "pad", "pada", "padi", "pade",
    "chahiye", "chahte", "sakta", "sakti", "sakte", "chuka", "chuki", "chuke", "wala", "wali",
    "wale", "pas", "paas", "saath", "sath", "bina", "andar", "bahar", "upar", "neeche",
    "niche", "samne", "peeche", "piche", "taraf", "bare", "baare", "wajah", "karan", "naam",
    "umar", "umr", "pata", "ghar", "gaon", "shahar", "zila", "zilla", "jila", "thana",
    "ek", "do", "teen", "char", "paanch", "panch", "chhe", "saat", "aath", "nau", "das",
    "gyarah", "barah", "pandrah", "bees", "tees", "chalis", "pachas", "sau", "hazaar", "hazar",
    "somvar", "mangalvar", "budhvar", "guruvar", "shukravar", "shanivar", "ravivar",
    "beta", "beti", "bete", "papa", "mummy", "maa", "mata", "pita", "pati", "patni", "biwi",
    "bahu", "damad", "bhai", "behen", "bahan", "bhabhi", "didi", "bhaiya", "chacha", "chachu",
    "chachi", "mama", "mami", "mausi", "bua", "dada", "dadi", "nana", "nani", "sahab", "saheb",
    "sahib", "saab", "bacha", "bachcha", "bachi", "bachchi", "aadmi", "aurat", "ladka", "ladki",
    # Major Indian cities & states (avoid false positives in unlabelled free text)
    "india", "indian", "bharat", "hindi", "english", "hinglish", "urdu",
    "delhi", "mumbai", "bombay", "kolkata", "calcutta", "chennai", "madras", "bengaluru",
    "bangalore", "hyderabad", "pune", "jaipur", "lucknow", "patna", "bhopal", "indore",
    "kanpur", "varanasi", "banaras", "agra", "noida", "gurgaon", "gurugram", "faridabad",
    "ghaziabad", "meerut", "prayagraj", "allahabad", "gorakhpur", "bareilly", "aligarh",
    "moradabad", "jhansi", "mathura", "ayodhya", "faizabad", "chandigarh", "ahmedabad",
    "surat", "vadodara", "rajkot", "nagpur", "nashik", "thane", "aurangabad", "ranchi",
    "jamshedpur", "dhanbad", "guwahati", "shillong", "shimla", "dehradun", "haridwar",
    "jammu", "srinagar", "amritsar", "ludhiana", "jalandhar", "patiala", "jodhpur", "udaipur",
    "kota", "ajmer", "bikaner", "gwalior", "jabalpur", "ujjain", "raipur", "bilaspur",
    "bhubaneswar", "cuttack", "puri", "kochi", "cochin", "trivandrum", "thiruvananthapuram",
    "madurai", "coimbatore", "mysore", "mysuru", "mangalore", "vijayawada", "visakhapatnam",
    "tirupati", "goa", "punjab", "haryana", "rajasthan", "gujarat", "maharashtra", "bihar",
    "jharkhand", "odisha", "orissa", "assam", "kerala", "karnataka", "telangana", "sikkim",
    "tripura", "manipur", "meghalaya", "mizoram", "nagaland", "uttarakhand", "chhattisgarh",
    "pradesh", "bengal", "kashmir", "ladakh", "tamil", "nadu", "andhra", "himachal",
})

STOP_DEVA = frozenset({
    "बुखार", "दर्द", "खांसी", "खाँसी", "जुकाम", "सर्दी", "गर्मी", "उल्टी", "उल्टियां", "दस्त",
    "पेचिश", "चक्कर", "कमजोरी", "सूजन", "खुजली", "जलन", "घबराहट", "बेचैनी", "सांस", "साँस",
    "पेट", "सिर", "कमर", "घुटना", "घुटने", "पैर", "हाथ", "गला", "आंख", "आँख", "कान", "नाक",
    "दांत", "छाती", "सीना", "पीठ", "खून", "पेशाब", "दवाई", "दवा", "दवाइयां", "गोली", "गोलियां",
    "सुई", "पट्टी", "टांका", "जांच", "जाँच", "पर्ची", "कागज", "मरीज", "मरीज़", "रोगी", "बीमार",
    "बीमारी", "तकलीफ", "परेशानी", "इलाज", "उपचार", "अस्पताल", "वार्ड", "बेड", "कमरा", "विभाग",
    "रिपोर्ट", "डिस्चार्ज", "भर्ती", "दाखिल", "छुट्टी", "आराम", "नींद", "चिकित्सालय",
    "आज", "कल", "परसों", "सुबह", "शाम", "रात", "दोपहर", "दिन", "महीना", "महीने", "साल", "वर्ष",
    "हफ्ता", "हफ्ते", "घंटा", "घंटे", "अभी", "पहले", "बाद", "फिर", "दोबारा", "हमेशा", "कभी",
    "रोज", "लगातार", "अचानक", "धीरे", "तेज", "हल्का", "हल्की", "खाना", "खाया", "पीना", "पिया",
    "पानी", "दूध", "चाय", "रोटी", "चावल", "दाल", "सब्जी", "फल",
    "ठीक", "अच्छा", "अच्छी", "बुरा", "ज्यादा", "ज़्यादा", "कम", "थोड़ा", "थोड़ी", "बहुत",
    "बिल्कुल", "पूरा", "नहीं", "नही", "मत", "हाँ", "हां", "क्या", "क्यों", "कैसे", "कहाँ", "कहां",
    "कब", "कौन", "किस", "किसको", "किसका", "किसकी", "यह", "ये", "वह", "वो", "उसको", "उसका",
    "उसकी", "उसके", "उसने", "उससे", "उन्हें", "उनके", "उनका", "उनकी", "उन्होंने", "इसको", "इसका",
    "इसकी", "इसके", "इसने", "हम", "हमने", "मैं", "मैंने", "मुझे", "तुम", "तुमने", "आप", "आपने",
    "अपना", "अपनी", "अपने", "मेरा", "मेरी", "मेरे", "सब", "सभी", "कुछ", "कोई", "और", "या",
    "पर", "लेकिन", "मगर", "क्योंकि", "अगर", "तो", "भी", "ही", "तक", "से", "को", "ने", "का",
    "की", "के", "में", "लिया", "लिये", "लिए", "ली", "दी", "दिया", "दिये", "दिए", "देना", "लेना",
    "कर", "करना", "करनी", "करने", "करता", "करती", "करते", "किया", "किये", "किए", "होता",
    "होती", "होते", "होना", "हुआ", "हुई", "हुए", "है", "हैं", "था", "थी", "थे", "होगा", "होगी",
    "होंगे", "रहा", "रही", "रहे", "गया", "गयी", "गई", "गये", "गए", "आया", "आयी", "आई", "आये",
    "आए", "जाना", "आना", "लाया", "लायी", "बताया", "बताई", "बोला", "बोली", "देखा", "देखी",
    "सुना", "लगा", "लगी", "लगे", "मिला", "मिली", "मिले", "रखा", "रखी", "पड़ा", "पड़ी", "चाहिए",
    "सकता", "सकती", "सकते", "चुका", "चुकी", "चुके", "वाला", "वाली", "वाले", "पास", "साथ",
    "बिना", "अंदर", "बाहर", "ऊपर", "नीचे", "सामने", "पीछे", "तरफ", "वजह", "कारण",
    "एक", "दो", "तीन", "चार", "पांच", "पाँच", "छह", "सात", "आठ", "नौ", "दस", "बीस", "सौ",
    "डॉक्टर", "डॉ", "डा", "नर्स", "सिस्टर", "सामान्य", "निजी", "आपातकालीन", "तारीख", "समय",
    "नाम", "उम्र", "आयु", "लिंग", "पता", "फोन", "मोबाइल", "आधार", "पुरुष", "महिला", "स्त्री",
    "लड़का", "लड़की", "बच्चा", "बच्ची", "आदमी", "औरत", "पिता", "माता", "माँ", "पति", "पत्नी",
    "पुत्र", "पुत्री", "बेटा", "बेटी", "बेटे", "बहू", "भाई", "बहन", "चाचा", "चाचू", "चाची",
    "मामा", "मामी", "मौसी", "बुआ", "दादा", "दादी", "नाना", "नानी", "भाभी", "दीदी", "भैया",
    "साहब", "साहेब", "जी", "टैब", "सिरप", "इंजेक्शन", "दिल्ली", "मुंबई", "पटना", "लखनऊ",
    "जयपुर", "भोपाल", "इंदौर", "कानपुर", "वाराणसी", "आगरा", "कोलकाता", "चेन्नई", "भारत",
})

# ------------------------------------------------------------------ Indian surname, suffix & grammar cues
# Pan-Indian census-level surnames / honorific middle names (norm_latin keys)
SURNAMES_LATIN = frozenset({
    # Female middle / surname markers
    "devi", "kumari", "bai", "ben", "bano", "banu", "begum", "begam", "khatun", "khaton",
    "bibi", "kaur", "nisa",
    "bala", "lata", "vati", "wati", "rani", "mati", "dasi",
    # Male middle / patronymic markers
    "kumar", "singh", "lal", "ram", "prasad", "das", "nath", "chand", "chandra", "dev",
    "dut", "data", "kant",
    "saran", "sharan", "dayal", "sahai", "sahay", "svarup", "swarup",
    # North / Central / East / West / South / Muslim / Sikh / Christian surnames
    "yadav", "sharma", "verma", "varma", "gupta", "agarwal", "agrawal", "bansal", "goyal",
    "goel", "mital", "jain", "mishra", "misra", "tiwari", "tripathi", "pandey", "pande",
    "dubey", "dube", "dwivedi", "shukla", "pathak", "upadhyay", "chaturvedi", "trivedi",
    "joshi", "bhat", "pant", "rawat", "bisht", "negi", "chauhan", "rathore", "rathor",
    "thakur", "rajput", "tomar", "solanki", "sisodia", "parmar", "patel", "patil", "pawar",
    "jadhav", "shinde", "deshmukh", "kulkarni", "deshpande", "sawant", "gaikwad", "chavan",
    "kadam", "bhosale", "naik", "kamble", "hegde", "shety", "rao", "redy", "naidu",
    "murthy", "murti", "shastri", "iyer", "iyengar", "nair", "menon", "pilai", "kurian",
    "varghese", "mathew", "fernandes", "dsouza", "pereira", "rodrigues",
    "khan", "ansari", "qureshi", "sidiqui", "sheikh", "shaikh", "syed", "saiyed", "mirza",
    "baig", "pathan", "malik", "rizvi", "zaidi", "naqvi", "husain", "ali", "ahmed", "ahmad",
    "mohamad", "muhamad", "alam", "akhtar", "rahman", "rehman", "faruqui", "usmani", "hashmi",
    "chaudhary", "choudhary", "chaudhry", "huda", "dahiya", "gil", "grewal", "sandhu",
    "sidhu", "dhilon", "brar", "bains", "chema", "bajwa", "khana", "kapur", "kapoor",
    "malhotra", "mehra", "bhatia", "arora", "sethi", "chawla", "ahuja", "tandon", "bajaj",
    "chopra", "kohli", "sud", "grover", "bhardwaj", "kaushik", "vashisht", "tyagi", "gautam",
    "maurya", "kushwaha", "saini", "prajapati", "vishwakarma", "srivastava", "shrivastava",
    "saxena", "mathur", "nigam", "asthana", "bhatnagar", "johri", "sinha", "paswan", "manjhi",
    "mandal", "mahato", "mahto", "sahu", "bose", "sen", "roy", "ray", "ghosh", "mukherji",
    "mukherjee", "banerji", "banerjee", "chaterji", "chatterjee", "ganguly", "bhatacharya",
    "chakraborty", "sarkar", "sengupta", "mazumdar", "majumdar", "mitra", "pal", "dey",
    "barua", "gogoi", "bora", "kalita", "hazarika", "sarma", "behera", "mohanty", "patnaik",
    "panda", "nayak", "swain", "parida", "rout", "tripathy", "samal", "barik", "lenka",
    "biswal", "kumawat", "mina", "gurjar", "gujar", "bairwa", "jatav", "valmiki", "koli",
    "lodhi", "kurmi", "koeri", "kahar", "nishad", "kashyap", "bind", "baghel", "dhangar",
    "ahir", "raidas", "sonkar", "bharti", "khatik", "kamboj", "bishnoi", "chahal", "virk",
    "sekhon", "randhawa", "deol", "chandel", "parihar", "jadeja", "gohil", "vaghela",
    "desai", "shah", "mehta", "parekh", "parikh", "kothari", "dave", "vyas", "pandya",
    "thakar", "modi", "amin", "panchal", "gajar", "mistry", "rathi", "maheshwari",
    "khandelwal", "singhal", "garg", "jindal", "kansal", "rastogi", "mehrotra", "khare",
    "bhargava", "soni", "tiwary", "dubay", "pandit", "ojha", "jha", "thakore",
})

SURNAMES_DEVA = frozenset({
    "देवी", "कुमारी", "बाई", "बेन", "बानो", "बेगम", "खातून", "खातुन", "बीबी", "कौर", "निशा",
    "फातिमा", "परवीन", "सुल्ताना", "रानी", "बाला", "लता", "वती",
    "कुमार", "सिंह", "लाल", "राम", "प्रसाद", "दास", "नाथ", "चंद", "चन्द्र", "देव", "दत्त",
    "यादव", "शर्मा", "वर्मा", "गुप्ता", "अग्रवाल", "बंसल", "गोयल", "मित्तल", "जैन", "मिश्रा",
    "मिश्र", "तिवारी", "त्रिपाठी", "पांडे", "पांडेय", "पाण्डेय", "दुबे", "द्विवेदी", "शुक्ला",
    "शुक्ल", "पाठक", "उपाध्याय", "चतुर्वेदी", "त्रिवेदी", "जोशी", "भट्ट", "पंत", "रावत", "बिष्ट",
    "नेगी", "चौहान", "राठौर", "ठाकुर", "राजपूत", "तोमर", "सोलंकी", "परमार", "पटेल", "पाटिल",
    "पवार", "जाधव", "शिंदे", "देशमुख", "कुलकर्णी", "देशपांडे", "सावंत", "गायकवाड़", "कदम",
    "नायक", "कांबले", "हेगड़े", "शेट्टी", "राव", "रेड्डी", "नायडू", "राजू", "मूर्ति", "शास्त्री",
    "अय्यर", "नायर", "मेनन", "पिल्लई",
    "खान", "अंसारी", "कुरैशी", "सिद्दीकी", "शेख", "सैयद", "मिर्जा", "बेग", "पठान", "मलिक",
    "रिजवी", "जैदी", "हुसैन", "अली", "अहमद", "मोहम्मद", "आलम", "अख्तर", "रहमान", "उस्मानी",
    "चौधरी", "गिल", "संधू", "सिद्धू", "ढिल्लों", "खन्ना", "कपूर", "मल्होत्रा", "मेहरा", "भाटिया",
    "अरोड़ा", "सेठी", "चावला", "आहूजा", "टंडन", "बजाज", "चोपड़ा", "कोहली", "सूद", "ग्रोवर",
    "भारद्वाज", "कौशिक", "त्यागी", "गौतम", "मौर्य", "कुशवाहा", "सैनी", "प्रजापति", "विश्वकर्मा",
    "श्रीवास्तव", "सक्सेना", "माथुर", "निगम", "अस्थाना", "भटनागर", "सिन्हा", "पासवान", "मांझी",
    "मंडल", "महतो", "साहू", "बोस", "सेन", "रॉय", "घोष", "मुखर्जी", "बनर्जी", "चटर्जी", "गांगुली",
    "भट्टाचार्य", "चक्रवर्ती", "सरकार", "मित्रा", "पाल", "मीणा", "गुर्जर", "जाटव", "वाल्मीकि",
    "लोधी", "कुर्मी", "निषाद", "कश्यप", "बघेल", "भारती", "सोनी", "देसाई", "शाह", "मेहता",
    "पारेख", "कोठारी", "व्यास", "पंड्या", "मोदी", "राठी", "माहेश्वरी", "खंडेलवाल", "सिंघल",
    "गर्ग", "जिंदल", "रस्तोगी", "मेहरोत्रा", "खरे", "भार्गव", "झा", "ओझा", "पंडित",
})

# High-value morphological suffixes of Indian given names (checked on norm_latin)
# Tuple of (suffix, weight)
INDIC_NAME_SUFFIXES = (
    ("eshwar", 1.8), ("ishwar", 1.8), ("vardhan", 1.7), ("wardhan", 1.7),
    ("narayan", 1.7), ("shankar", 1.7), ("shekhar", 1.7), ("bhushan", 1.7),
    ("nandini", 1.7), ("ranjani", 1.6), ("swaroop", 1.6),
    ("swarup", 1.6), ("kumari", 1.6), ("kishor", 1.5), ("kishore", 1.5),
    ("endra", 1.6), ("indra", 1.6), ("anshu", 1.6), ("nandan", 1.5),
    ("ranjan", 1.5), ("prasad", 1.5), ("chandra", 1.5), ("sharan", 1.4),
    ("udhin", 1.6), ("udin", 1.6), ("ulah", 1.6), ("nisa", 1.4),
    ("preet", 1.5), ("prit", 1.5), ("deep", 1.3), ("dip", 1.2),
    ("jeet", 1.4), ("jit", 1.3), ("veer", 1.3), ("vir", 1.1),
    ("wati", 1.5), ("vati", 1.5), ("lata", 1.4), ("bala", 1.3),
    ("kala", 1.1), ("mani", 1.2), ("mati", 1.3), ("priya", 1.4),
    ("shri", 1.3), ("nand", 1.2), ("dhar", 1.2),
    ("nath", 1.3), ("kant", 1.3), ("kanta", 1.4),
    ("dev", 1.0), ("devi", 1.5), ("chand", 1.3), ("bhan", 1.2),
    ("dayal", 1.3), ("bano", 1.5), ("banu", 1.5), ("bibi", 1.4),
    ("esh", 1.3), ("ish", 1.1), ("ram", 1.1), ("lal", 1.1),
    ("das", 1.0), ("raj", 1.0), ("pal", 0.9),
    ("mini", 1.3), ("shmi", 1.4), ("kshi", 1.4), ("mita", 1.2),
    ("ita", 0.8), ("ika", 0.9), ("ini", 1.1), ("ina", 0.8),
    ("iya", 0.8), ("shu", 0.9), ("dhu", 0.9), ("bhu", 0.9),
    ("lu", 0.7), ("tu", 0.6), ("du", 0.6), ("bu", 0.7), ("nu", 0.6), ("ku", 0.6),
)

INDIC_NAME_PREFIXES = (
    "subh", "shubh", "sri", "shri", "ram", "har", "gur", "brij", "braj",
    "dhar", "krish", "kris", "laksh", "madh", "ragh", "siddh", "sidh", "vishw",
    "vish", "yash", "prab", "prat", "pras", "prav", "prem", "abhi", "anur", "ashv",
    "bhag", "bhan", "chh", "dev", "dhan", "dhin", "gaj", "gan", "gov", "hem",
    "jag", "jay", "jit", "kam", "kanh", "kaush", "kesh", "kul", "lal", "mah",
    "manj", "manm", "mano", "meen", "minak", "muk", "nar", "nav", "nir", "om",
    "padm", "pank", "parv", "phul", "push", "radh", "raj", "rakh", "ramb", "ranj",
    "rash", "ratn", "rav", "rek", "rit", "roh", "ruk", "rup", "sadh", "sanj",
    "sant", "sarv", "saty", "sav", "shab", "shah", "shak", "sham", "shan", "shar",
    "shil", "shob", "shw", "sneh", "soh", "subo", "sudh", "sukh", "sum", "sun",
    "sur", "sush", "swat", "tab", "tar", "trib", "uday", "upen", "urm",
    "ush", "vand", "varsh", "vas", "ved", "venk", "vid", "vij", "vik", "vim",
    "vin", "vir", "yog", "abd", "far", "gul", "has", "imr", "irf", "khur",
    "moh", "muh", "mus", "nad", "nas", "nur", "raf", "rah", "riz", "sab", "saf",
    "sal", "tah", "tas", "wah", "was", "yas", "zah", "zai", "zar", "zub",
)

# Hinglish / Hindi grammar cues immediately following a candidate name
HINGLISH_ERGATIVE = frozenset({"ne", "ने"})
HINGLISH_DATIVE = frozenset({"ko", "को"})
HINGLISH_GENITIVE = frozenset({"ka", "ki", "ke", "का", "की", "के"})
HINGLISH_ABLATIVE = frozenset({"se", "से"})

HINGLISH_HONOR_KIN = frozenset({
    "ji", "jee", "sahab", "saheb", "sahib", "saab", "didi", "bhaiya", "bhayya", "bhai",
    "bhaisahab", "chacha", "chachu", "chachi", "mama", "mami", "mausi", "bua", "fufa",
    "dada", "dadi", "nana", "nani", "bhabhi", "behen", "bahan", "amma", "ammi", "abba",
    "abbu", "baba", "tai", "tau", "kaka", "kaki", "apa", "aapa", "khala", "miya", "miyan",
    "जी", "साहब", "साहेब", "दीदी", "भैया", "भाई", "चाचा", "चाचू", "चाची", "मामा", "मामी",
    "मौसी", "बुआ", "दादा", "दादी", "नाना", "नानी", "भाभी", "अम्मा", "अम्मी", "अब्बा",
    "काका", "काकी", "ताऊ", "ताई", "आपा", "खाला", "मियां", "मियाँ",
})

GENITIVE_FOLLOW_CLUES = frozenset({
    "bukhar", "bukhaar", "dard", "khansi", "ulti", "chakkar", "bp", "sugar", "hb", "temp",
    "report", "reports", "dawai", "dawa", "jaanch", "janch", "test", "xray", "usg", "ecg",
    "pet", "sir", "sar", "gala", "chhati", "kamar", "pair", "haath", "aankh", "ilaaj", "ilaj",
    "operation", "surgery", "discharge", "admission", "bharti", "halat", "tabiyat", "tabiyet",
    "umar", "umr", "age", "phone", "mobile", "number", "naam", "pata", "ghar",
    "beta", "beti", "bete", "papa", "maa", "mata", "pita", "pati", "patni", "biwi", "wife",
    "husband", "son", "daughter", "father", "mother", "bhai", "behen", "bahu", "parivar",
    "बुखार", "दर्द", "खांसी", "उल्टी", "चक्कर", "रिपोर्ट", "दवाई", "दवा", "जांच", "जाँच",
    "पेट", "सिर", "गला", "छाती", "कमर", "पैर", "हाथ", "इलाज", "ऑपरेशन", "डिस्चार्ज", "भर्ती",
    "हालत", "तबीयत", "उम्र", "फोन", "मोबाइल", "नंबर", "नाम", "पता", "घर",
    "बेटा", "बेटी", "बेटे", "पिता", "माता", "माँ", "पति", "पत्नी", "भाई", "बहन", "बहू",
})

TEMPORAL_CLUES = frozenset({"aaj", "kal", "abhi", "subah", "shaam", "raat", "आज", "कल", "अभी", "सुबह", "शाम", "रात"})
CLINICAL_PREDICATES = frozenset({
    "discharge", "discharged", "admit", "admitted", "bharti", "dakhil", "aaya", "aayi", "aaye",
    "aya", "ayi", "aye", "gaya", "gayi", "gaye", "theek", "thik", "stable", "better", "ok",
    "fine", "bukhar", "dard", "dawai", "came", "visited", "discharged", "referred", "shifted",
    "डिस्चार्ज", "भर्ती", "दाखिल", "आया", "आयी", "आई", "आये", "गया", "गयी", "गई", "ठीक",
    "छुट्टी", "बुखार", "दर्द", "दवाई",
})
ENG_SUBJECT_VERBS = frozenset({
    "admitted", "discharged", "complains", "complained", "presents", "presented",
    "reports", "reported", "denies", "denied", "visited", "called", "states", "stated",
})

# Generic surnames that should NOT propagate alone as bare single tokens
NON_PROPAGABLE_SINGLE = frozenset({
    "devi", "kumari", "kumar", "singh", "kaur", "bai", "ben", "begum", "begam", "bano",
    "banu", "khatun", "khaton", "bibi", "lal", "ram", "prasad", "das", "nath", "chand",
    "chandra", "dev", "khan", "ali", "ahmed", "ahmad", "shaikh", "sheikh", "syed", "rao",
    "roy", "ray", "sen", "pal", "dey", "sharma", "verma", "varma", "gupta", "yadav",
    "patel", "patil", "jain", "shah", "mehta", "redy", "naidu", "nair", "menon", "iyer",
    "mishra", "tiwari", "pandey", "dubey", "shukla", "chauhan", "thakur", "malik", "ansari",
    "bose", "ghosh", "duta", "data", "sinha", "sahu", "mandal", "paswan", "maurya", "saini",
    "joshi", "bhat", "rawat", "pawar", "jadhav", "shinde", "deshmukh", "kulkarni",
})


# ------------------------------------------------------------------ Character N-gram Classifier
_VOWELS = frozenset("aeiou")
_ASPIRATES = ("bh", "ch", "dh", "gh", "jh", "kh", "ph", "sh", "th")


def extract_token_features(norm_tok: str) -> list[str]:
    """Extract deterministic morphological + character n-gram features from a norm_latin token."""
    if not norm_tok:
        return []
    feats: list[str] = []
    n = len(norm_tok)

    # Length bucket
    if n <= 3:
        feats.append("L:3")
    elif n <= 5:
        feats.append("L:4_5")
    elif n <= 8:
        feats.append("L:6_8")
    else:
        feats.append("L:9+")

    # Vowel ratio bucket
    v_cnt = sum(1 for c in norm_tok if c in _VOWELS)
    vr = v_cnt / n
    if vr < 0.25:
        feats.append("VR:low")
    elif vr <= 0.55:
        feats.append("VR:mid")
    else:
        feats.append("VR:high")

    # Consonant cluster length
    max_cc = cur_cc = 0
    for c in norm_tok:
        if c in _VOWELS:
            cur_cc = 0
        else:
            cur_cc += 1
            if cur_cc > max_cc:
                max_cc = cur_cc
    if max_cc >= 4:
        feats.append("CC:4+")
    elif max_cc == 3:
        feats.append("CC:3")
    else:
        feats.append("CC:1_2")

    # Aspirate digraphs (strongly indicative of Indic romanization)
    if any(a in norm_tok for a in _ASPIRATES):
        feats.append("PH:aspirate")

    # Open ending vowel
    if norm_tok[-1] in ("a", "i", "u"):
        feats.append(f"END:{norm_tok[-1]}")

    # Morphological suffix / prefix flags
    for suf, _ in INDIC_NAME_SUFFIXES:
        if n >= len(suf) + 2 and norm_tok.endswith(suf):
            feats.append(f"ISUF:{suf}")
            break
    for pre in INDIC_NAME_PREFIXES:
        if n >= len(pre) + 2 and norm_tok.startswith(pre):
            feats.append("IPRE:1")
            break
    if n >= 6 and any(norm_tok.endswith(s) for s in PHARMA_SUFFIXES):
        feats.append("BAD:pharma")
    if n >= 6 and any(norm_tok.endswith(s) for s in MED_SUFFIXES):
        feats.append("BAD:med")
    if n >= 6 and any(norm_tok.endswith(s) for s in PLACE_SUFFIXES):
        feats.append("BAD:place")

    # Boundary-marked character 2, 3, 4-grams
    padded = f"^{norm_tok}$"
    plen = len(padded)
    for k in (2, 3, 4):
        for i in range(plen - k + 1):
            feats.append(f"G{k}:{padded[i:i + k]}")

    return feats


# Compact built-in fallback weights (overridden automatically when namefind_weights.json exists)
DEFAULT_MODEL: dict = {"bias": 0.0, "weights": {}}   # neutral fallback; the shipped JSON is trained on synthetic data only


class CharNgramScorer:
    """Tiny deterministic linear classifier over morphological + char n-gram features."""

    def __init__(self, weights_path: str | Path | None = None):
        self.bias: float = DEFAULT_MODEL["bias"]
        self.weights: dict[str, float] = dict(DEFAULT_MODEL["weights"])
        path = Path(weights_path) if weights_path is not None else Path(__file__).with_name("namefind_weights.json")
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            self.bias = float(data.get("bias", 0.0))
            self.weights = {str(k): float(v) for k, v in data.get("weights", {}).items()}

    def logit(self, norm_tok: str) -> float:
        s = self.bias
        w = self.weights
        for f in extract_token_features(norm_tok):
            if f in w:
                s += w[f]
        return s

    def prob(self, norm_tok: str) -> float:
        cache = self.__dict__.setdefault("_prob_cache", {})
        p = cache.get(norm_tok)
        if p is None:
            if len(cache) > 200000:
                cache.clear()
            p = cache[norm_tok] = self._prob(norm_tok)
        return p

    def _prob(self, norm_tok: str) -> float:
        z = self.logit(norm_tok)
        if z >= 0:
            ez = math.exp(-min(z, 30.0))
            return 1.0 / (1.0 + ez)
        ez = math.exp(max(z, -30.0))
        return ez / (1.0 + ez)


# ------------------------------------------------------------------ NameFinder
class NameFinder:
    """Detects unseen Indian names in English, Hinglish, and Devanagari free text."""

    def __init__(self, lex=None, scorer: CharNgramScorer | None = None, weights_path: str | Path | None = None):
        self.lex = lex
        self.scorer = scorer or CharNgramScorer(weights_path=weights_path)

    # -------------------------------------------------------------- Token guards
    def _is_stop_or_med(self, raw_tok: str, nl: str) -> bool:
        w = raw_tok.rstrip(".")
        wl = w.lower()
        if not w or len(w) < 2:
            return True
        if self.lex is not None and getattr(self.lex, "is_place", None) and self.lex.is_place(w):
            return True
        if has_devanagari(w):
            if w in STOP_DEVA or w in FACILITY_HEADS or w in HINGLISH_HONOR_KIN:
                return True
            if self.lex is not None and _ext_deva_to_latin is not None:
                lat = _ext_deva_to_latin(w)
                if lat in getattr(self.lex, "medical", ()) or lat in getattr(self.lex, "common", ()):
                    return True
            if self.lex is not None:
                if w in getattr(self.lex, "stop_hindi", ()) or w in getattr(self.lex, "honor_pre", ()):
                    return True
                if w in getattr(self.lex, "honor_suf", ()):
                    return True
            if not nl or len(nl) < 2:
                return True
            if nl in STOP_LATIN and nl not in SURNAMES_LATIN:
                return True
            return False

        # Latin checks
        if wl in STOP_LATIN or nl in STOP_LATIN:
            # Allow known surnames that don't collide with medical words (e.g. "devi", "yadav")
            if wl not in SURNAMES_LATIN and nl not in SURNAMES_LATIN:
                return True
        if wl in DOCTOR_TITLES or wl in MED_DEGREES or wl in DRUG_PREFIXES or wl in FACILITY_HEADS:
            return True
        if wl in HINGLISH_HONOR_KIN:
            return True
        if len(nl) >= 6 and (any(nl.endswith(s) for s in PHARMA_SUFFIXES) or any(nl.endswith(s) for s in MED_SUFFIXES)):
            return True
        if self.lex is not None:
            if wl in getattr(self.lex, "stop_latin", ()) or wl in getattr(self.lex, "honor_pre", ()):
                return True
            if wl in getattr(self.lex, "common", ()):
                return True
            if wl in getattr(self.lex, "honor_suf", ()):
                return True
            is_med = getattr(self.lex, "is_medical", None)
            if callable(is_med) and is_med(wl):
                names_set = getattr(self.lex, "names", ())
                ambig_set = getattr(self.lex, "ambiguous", ())
                if wl not in names_set and wl not in ambig_set and wl not in SURNAMES_LATIN:
                    return True
        return False

    def _is_surname(self, raw_tok: str, nl: str) -> bool:
        w = raw_tok.rstrip(".")
        if has_devanagari(w):
            if w in SURNAMES_DEVA:
                return True
        return w.lower() in SURNAMES_LATIN or nl in SURNAMES_LATIN

    @staticmethod
    def _is_initial(raw_tok: str) -> bool:
        return bool(re.fullmatch(r"[A-Z]\.?|(?:[A-Z]\.){2,3}[A-Z]?", raw_tok))

    @staticmethod
    def _joinable(text: str, prev_tok: tuple, next_tok: tuple) -> bool:
        between = text[prev_tok[1]:next_tok[0]]
        if re.fullmatch(r"[ \t]{1,2}", between):
            # Don't cross sentence period after non-initial word
            pw = prev_tok[2]
            if pw.endswith(".") and len(pw.rstrip(".")) > 1 and not re.fullmatch(r"(?:[A-Z]\.)+", pw):
                return False
            # Don't join Latin and Devanagari inside one name span
            if has_devanagari(pw) != has_devanagari(next_tok[2]):
                return False
            return True
        if between == "" and prev_tok[2].endswith(".") and re.fullmatch(r"(?:[A-Z]\.)+", prev_tok[2]):
            return True
        return False

    @staticmethod
    def _overlaps_protected(start: int, end: int, protected: list[tuple[int, int]]) -> bool:
        for ps, pe in protected:
            if start < pe and ps < end:
                return True
        return False

    @staticmethod
    def _preceded_by_doctor(text: str, toks: list[tuple], idx: int) -> bool:
        """True if token idx sits inside a Dr./Doctor/Prof./डॉ. name chain."""
        j = idx - 1
        steps = 0
        while j >= 0 and steps < 4:
            gap = text[toks[j][1]:toks[j + 1][0]]
            if re.search(r"[,;\n|()।:]", gap):
                break
            pw = toks[j][2]
            pw_clean = pw.rstrip(".").lower()
            if pw_clean in DOCTOR_TITLES or pw.rstrip(".") in DOCTOR_TITLES:
                return True
            if pw.endswith(".") and len(pw.rstrip(".")) > 1 and not re.fullmatch(r"(?:[A-Z]\.)+", pw):
                break
            # Only step back across plausible doctor-name tokens / initials
            if not (pw[0].isupper() or has_devanagari(pw)):
                break
            j -= 1
            steps += 1
        return False

    @staticmethod
    def _preceded_by_drug_prefix(text: str, toks: list[tuple], idx: int) -> bool:
        if idx <= 0:
            return False
        gap = text[toks[idx - 1][1]:toks[idx][0]]
        if len(gap) > 3 or re.search(r"[,;\n|()।]", gap):
            return False
        pw = toks[idx - 1][2].rstrip(".")
        return pw.lower() in DRUG_PREFIXES or pw in DRUG_PREFIXES

    @staticmethod
    def _followed_by_facility_or_degree(text: str, toks: list[tuple], end_idx: int) -> bool:
        """True if span ending at end_idx is immediately followed by a hospital/ward/place/degree head."""
        for step in (1, 2):
            k = end_idx + step
            if k >= len(toks):
                break
            prev = toks[k - 1]
            cur = toks[k]
            gap = text[prev[1]:cur[0]]
            if re.search(r"[,;\n|()।:]", gap) or len(gap) > 3:
                break
            if prev[2].endswith(".") and len(prev[2].rstrip(".")) > 1 and not re.fullmatch(r"(?:[A-Z]\.)+", prev[2]):
                break
            cw = cur[2].rstrip(".")
            cwl = cw.lower()
            if cwl in FACILITY_HEADS or cw in FACILITY_HEADS or cwl in MED_DEGREES:
                return True
            # Only look 2 tokens ahead if the intermediate token is also capitalized/Devanagari (e.g. "Nehru Memorial Hospital")
            if step == 1 and not (cw[:1].isupper() or has_devanagari(cw)):
                break
        return False

    @staticmethod
    def _at_sentence_start(text: str, start: int) -> bool:
        prefix = text[:start].rstrip()
        if not prefix:
            return True
        return prefix[-1] in ".!?\n।;:|-"

    # -------------------------------------------------------------- Per-token morphology score
    def score_token(self, raw_tok: str, allcaps_doc: bool = False) -> tuple[float, bool]:
        """Return (morph_score, is_surname). Negative large value if disallowed (memoised)."""
        cache = self.__dict__.setdefault("_score_cache", {})
        key = (raw_tok, allcaps_doc)
        hit = cache.get(key)
        if hit is None:
            if len(cache) > 200000:
                cache.clear()
            hit = cache[key] = self._score_token(raw_tok, allcaps_doc)
        return hit

    def _score_token(self, raw_tok: str, allcaps_doc: bool = False) -> tuple[float, bool]:
        w = raw_tok.rstrip(".")
        if self._is_initial(raw_tok):
            return 0.2, False
        nl = norm_latin(w)
        if self._is_stop_or_med(raw_tok, nl):
            return -10.0, False
        if not has_devanagari(w):
            # Reject ALL-CAPS short acronyms (e.g., "WBC", "NSAID", "COPD") unless document is all-caps
            if w.isupper() and len(w) <= 5 and not allcaps_doc:
                return -10.0, False
            if len(nl) < 3:
                return -10.0, False
        else:
            if len(w) < 2:
                return -10.0, False

        is_sur = self._is_surname(raw_tok, nl)
        # Classifier probability -> centered log-odds contribution
        p = self.scorer.prob(nl)
        score = (p - 0.5) * 3.0  # range [-1.5, +1.5]

        # Explicit Indian morphological suffix bonus
        for suf, wt in INDIC_NAME_SUFFIXES:
            if len(nl) >= len(suf) + 2 and nl.endswith(suf):
                score += wt
                break

        # Place-name suffix penalty (unless paired with surname later)
        if len(nl) >= 6 and any(nl.endswith(ps) for ps in PLACE_SUFFIXES) and not is_sur:
            score -= 1.6

        if is_sur:
            score = max(score, 0.8) + 1.4

        return score, is_sur

    # -------------------------------------------------------------- Context cue score
    def _right_context_score(self, text: str, toks: list[tuple], end_idx: int) -> tuple[float, str | None]:
        """Score Hinglish/Hindi/English grammatical cues immediately after end_idx."""
        if end_idx + 1 >= len(toks):
            return 0.0, None
        cur = toks[end_idx]
        nxt = toks[end_idx + 1]
        gap = text[cur[1]:nxt[0]]
        if len(gap) > 2 or re.search(r"[,;\n|()।:]", gap):
            return 0.0, None
        if cur[2].endswith(".") and len(cur[2].rstrip(".")) > 1:
            return 0.0, None

        nw_raw = nxt[2].rstrip(".")
        nwl = nw_raw.lower()

        if nwl in HINGLISH_HONOR_KIN or nw_raw in HINGLISH_HONOR_KIN:
            return 2.5, "honor_kin"
        if nwl in HINGLISH_ERGATIVE or nw_raw in HINGLISH_ERGATIVE:
            return 2.3, "ergative_ne"
        if nwl in HINGLISH_DATIVE or nw_raw in HINGLISH_DATIVE:
            return 1.9, "dative_ko"
        if nwl in HINGLISH_GENITIVE or nw_raw in HINGLISH_GENITIVE:
            if end_idx + 2 < len(toks):
                nn = toks[end_idx + 2][2].rstrip(".")
                if nn.lower() in GENITIVE_FOLLOW_CLUES or nn in GENITIVE_FOLLOW_CLUES:
                    return 1.6, "genitive_clinical"
            return 0.75, "genitive"
        if nwl in TEMPORAL_CLUES or nw_raw in TEMPORAL_CLUES:
            # Look ahead up to 3 tokens for a clinical/discharge/action predicate
            for k in range(end_idx + 2, min(len(toks), end_idx + 5)):
                kw = toks[k][2].rstrip(".")
                if kw.lower() in CLINICAL_PREDICATES or kw in CLINICAL_PREDICATES:
                    return 1.4, "temporal_clinical"
            return 0.35, "temporal"
        if nwl in HINGLISH_ABLATIVE or nw_raw in HINGLISH_ABLATIVE:
            return 0.65, "ablative_se"
        if nwl in ENG_SUBJECT_VERBS:
            return 0.9, "eng_verb"
        return 0.0, None

    # -------------------------------------------------------------- Main detection
    def find(
        self,
        text: str,
        existing_spans=None,
        dyn_names: set[str] | None = None,
        span_cls=NameSpan,
    ) -> list:
        """Return candidate NAME spans found by morphology, surname cues, and Hinglish grammar."""
        if not text or not text.strip():
            return []

        toks = [(m.start(), m.end(), m.group(0)) for m in _TOK_RX.finditer(text)]
        if not toks:
            return []

        # Protected character intervals from earlier stages
        protected: list[tuple[int, int]] = []
        if existing_spans:
            for sp in existing_spans:
                protected.append((sp.start, sp.end))

        allcaps_doc = sum(1 for _, _, w in toks if w.isupper() and len(w) > 2) > 0.6 * max(1, len(toks))
        dyn = dyn_names or set()

        # Precompute per-token scores
        n = len(toks)
        tok_scores: list[float] = []
        tok_sur: list[bool] = []
        tok_deva: list[bool] = []
        tok_cap: list[bool] = []
        for s, e, w in toks:
            sc, is_sur = self.score_token(w, allcaps_doc=allcaps_doc)
            if sc > -5.0 and prop_key(w) in dyn:
                sc += 1.5
            tok_scores.append(sc)
            tok_sur.append(is_sur)
            tok_deva.append(has_devanagari(w))
            tok_cap.append(bool(w[0].isupper()) and not (w.isupper() and len(w) > 1 and not allcaps_doc))

        candidates: list[tuple[float, int, int, int, int, str, dict]] = []

        for i in range(n):
            if tok_scores[i] < -5.0:
                continue
            if self._preceded_by_doctor(text, toks, i) or self._preceded_by_drug_prefix(text, toks, i):
                continue

            # Explore windows of 1..3 tokens starting at i
            for length in (1, 2, 3):
                j = i + length - 1
                if j >= n:
                    break
                if length > 1 and not self._joinable(text, toks[j - 1], toks[j]):
                    break
                if tok_scores[j] < -5.0:
                    break

                st = toks[i][0]
                en = toks[j][1]
                # Trim trailing sentence period (keep initial period like "R.")
                if text[st:en].endswith(".") and not re.search(r"\b[A-Z]\.$", text[st:en]):
                    en -= 1
                if en <= st:
                    break

                # Span cannot be all initials or end on a bare initial
                if all(self._is_initial(toks[k][2]) for k in range(i, j + 1)):
                    continue
                if self._is_initial(toks[j][2]):
                    continue

                if self._overlaps_protected(st, en, protected):
                    continue

                # Right-side clinical/facility/eponym/dose guards
                tail = text[en:en + 40]
                if EPONYM_HEADS_RX.match(tail) or DOSE_RIGHT_RX.match(tail) or LAB_RIGHT_RX.match(tail):
                    continue
                if self._followed_by_facility_or_degree(text, toks, j):
                    continue

                # Aggregate span score
                ctx_score, ctx_cue = self._right_context_score(text, toks, j)
                is_deva = tok_deva[i]
                has_surname = any(tok_sur[k] for k in range(i, j + 1))
                ends_surname = tok_sur[j] and length >= 2
                all_cap = all(tok_cap[k] or tok_deva[k] for k in range(i, j + 1))
                sent_start = self._at_sentence_start(text, st)

                # Guard: lowercase Latin tokens need a strong Hinglish cue or surname anchor
                if not is_deva and not all_cap and not allcaps_doc:
                    if ctx_score < 1.3 and not (ends_surname and ctx_score >= 0.65):
                        continue

                # Base morphology score
                non_init = [tok_scores[k] for k in range(i, j + 1) if not self._is_initial(toks[k][2])]
                mean_morph = sum(non_init) / max(1, len(non_init))
                min_morph = min(non_init)

                # Reject multi-token span if any constituent token looks clearly non-name
                if length >= 2 and min_morph < -0.55 and not (ends_surname and min_morph >= -0.85):
                    continue

                total = mean_morph + ctx_score

                # Capitalization / script / structural bonuses
                if is_deva:
                    total += 0.45
                elif all_cap:
                    total += 0.35 if sent_start else 0.70

                if ends_surname:
                    total += 1.65
                elif has_surname and length >= 2:
                    total += 1.00

                # Multi-token full-name bonus when all tokens are plausible names
                if length == 2 and min_morph >= 0.25:
                    total += 0.60
                elif length == 3 and min_morph >= 0.25:
                    total += 0.85

                # Decision threshold (stricter for bare single tokens with no grammar cue)
                if length == 1:
                    if ctx_score >= 1.3:
                        thr = 1.95
                    elif is_deva and tok_scores[i] >= 1.6:
                        thr = 2.05
                    elif not sent_start and all_cap and not has_surname:
                        thr = 2.35  # high bar for bare unseen single English-script token
                    else:
                        thr = 2.75
                else:
                    thr = 2.15 if not ends_surname else 1.85

                if total >= thr:
                    role = "ctx" if ctx_score >= 1.3 else "morph"
                    meta = {"score": round(total, 3), "cue": ctx_cue, "surname": ends_surname}
                    # Slight preference for longer valid spans when scores are close
                    rank_score = total + 0.35 * (length - 1)
                    candidates.append((rank_score, st, en, i, j, role, meta))

        # Greedy non-overlapping selection (highest rank_score, then longest, then earliest)
        candidates.sort(key=lambda x: (-x[0], -(x[2] - x[1]), x[1]))
        chosen = []
        occ: list[tuple[int, int]] = []
        for _, st, en, _, _, role, meta in candidates:
            if any(st < oe and os < en for os, oe in occ):
                continue
            occ.append((st, en))
            chosen.append(span_cls(st, en, "NAME", text[st:en], role=role, meta=meta))
        chosen.sort(key=lambda sp: sp.start)
        return chosen


# ------------------------------------------------------------------ Document & Batch Propagation
class NamePropagator:
    """Propagates confirmed person names across a document or batch (cross-script)."""

    def __init__(self, lex=None):
        self.lex = lex
        self.token_keys: set[str] = set()     # folded cross-script keys of safe single name tokens
        self.exact_short: set[str] = set()    # norm_latin of 3-char tokens (avoid aggressive fold collisions)
        self.phrases: set[tuple[str, ...]] = set()  # folded multi-token name sequences
        self.doctor_keys: set[str] = set()    # surnames/tokens seen in DOCTOR spans

    def _safe_single_token(self, raw_tok: str) -> bool:
        w = raw_tok.rstrip(".")
        if len(w) < 3:
            return False
        nl = norm_latin(w)
        if len(nl) < 3:
            return False
        if w.lower() in STOP_LATIN or nl in STOP_LATIN or w in STOP_DEVA:
            return False
        if w.lower() in NON_PROPAGABLE_SINGLE or nl in NON_PROPAGABLE_SINGLE:
            return False
        if w.lower() in FACILITY_HEADS or w in FACILITY_HEADS or w.lower() in HINGLISH_HONOR_KIN:
            return False
        if self.lex is not None:
            if w.lower() in getattr(self.lex, "ambiguous", ()) or w.lower() in getattr(self.lex, "stop_latin", ()):
                return False
            is_med = getattr(self.lex, "is_medical", None)
            if callable(is_med) and is_med(w.lower()):
                return False
        return True

    def register_spans(self, text: str, spans) -> None:
        """Learn safe name tokens & full phrases from detected NAME spans (ignoring DOCTOR)."""
        for sp in spans:
            if sp.kind == "DOCTOR":
                for _, _, w in [(m.start(), m.end(), m.group(0)) for m in _TOK_RX.finditer(sp.text)]:
                    k = prop_key(w)
                    if len(k) >= 3:
                        self.doctor_keys.add(k)
                continue
            if sp.kind != "NAME":
                continue
            parts = [m.group(0).rstrip(".") for m in _TOK_RX.finditer(sp.text)]
            parts = [p for p in parts if len(p) >= 2]
            if not parts:
                continue
            if len(parts) >= 2:
                pkey = tuple(prop_key(p) for p in parts)
                if all(len(x) >= 2 for x in pkey):
                    self.phrases.add(pkey)
            # Propagate safe individual tokens (typically given names / rare names, not generic surnames)
            for p in parts:
                if not self._safe_single_token(p):
                    continue
                nl = norm_latin(p)
                pk = prop_key(p)
                if len(nl) == 3:
                    self.exact_short.add(nl)
                elif len(pk) >= 3:
                    self.token_keys.add(pk)

    def propagate(self, text: str, existing_spans=None, span_cls=NameSpan) -> list:
        """Find all unmasked occurrences of previously seen names in text."""
        if not text or (not self.token_keys and not self.exact_short and not self.phrases):
            return []

        toks = [(m.start(), m.end(), m.group(0)) for m in _TOK_RX.finditer(text)]
        if not toks:
            return []

        protected = [(sp.start, sp.end) for sp in (existing_spans or ())]
        out = []
        n = len(toks)
        used: list[tuple[int, int]] = []

        # 1. Multi-token phrase propagation first (handles even generic surnames when paired)
        if self.phrases:
            tkeys = [prop_key(w) for _, _, w in toks]
            for i in range(n):
                if NameFinder._preceded_by_doctor(text, toks, i) or NameFinder._preceded_by_drug_prefix(text, toks, i):
                    continue
                for length in (3, 2):
                    j = i + length - 1
                    if j >= n:
                        continue
                    if not all(NameFinder._joinable(text, toks[k], toks[k + 1]) for k in range(i, j)):
                        continue
                    seq = tuple(tkeys[i:j + 1])
                    if seq not in self.phrases:
                        continue
                    st, en = toks[i][0], toks[j][1]
                    if text[st:en].endswith(".") and not re.search(r"\b[A-Z]\.$", text[st:en]):
                        en -= 1
                    if NameFinder._overlaps_protected(st, en, protected) or NameFinder._overlaps_protected(st, en, used):
                        continue
                    tail = text[en:en + 40]
                    if EPONYM_HEADS_RX.match(tail) or DOSE_RIGHT_RX.match(tail):
                        continue
                    if NameFinder._followed_by_facility_or_degree(text, toks, j):
                        continue
                    used.append((st, en))
                    out.append(span_cls(st, en, "NAME", text[st:en], role="prop", meta={"prop": "phrase"}))
                    break

        # 2. Single-token propagation
        for i, (st, en, w) in enumerate(toks):
            _nl0 = norm_latin(w)
            if not ((len(_nl0) == 3 and _nl0 in self.exact_short) or (len(_nl0) >= 4 and prop_key(w) in self.token_keys)):
                continue
            if text[st:en].endswith(".") and len(w.rstrip(".")) > 1:
                en -= 1
            if NameFinder._overlaps_protected(st, en, protected) or NameFinder._overlaps_protected(st, en, used):
                continue
            if NameFinder._preceded_by_doctor(text, toks, i) or NameFinder._preceded_by_drug_prefix(text, toks, i):
                continue
            tail = text[en:en + 40]
            if EPONYM_HEADS_RX.match(tail) or DOSE_RIGHT_RX.match(tail) or LAB_RIGHT_RX.match(tail):
                continue
            if NameFinder._followed_by_facility_or_degree(text, toks, i):
                continue

            nl = norm_latin(w)
            pk = prop_key(w)
            matched = False
            if len(nl) == 3 and nl in self.exact_short:
                # 3-char token: require Devanagari or capitalization to avoid random lowercase clashes
                if has_devanagari(w) or w[0].isupper():
                    matched = True
            elif len(nl) >= 4 and pk in self.token_keys and pk not in self.doctor_keys:
                matched = True

            if matched:
                # Never propagate over a hard stop/medical word
                if w.lower() in STOP_LATIN or w in STOP_DEVA or nl in STOP_LATIN:
                    continue
                used.append((st, en))
                out.append(span_cls(st, en, "NAME", text[st:en], role="prop", meta={"prop": "token"}))

        out.sort(key=lambda sp: sp.start)
        return out