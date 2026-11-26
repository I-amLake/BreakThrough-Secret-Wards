"""Classify column headers / JSON keys / free-text labels into semantic field types.

Works on English, Hinglish and Devanagari labels. For labels never seen before, a value
profiler (infer_from_values) decides from the content itself.
"""
import re

from .lexicon import get_lexicon

DIRECT = {"name", "first_name", "last_name", "relative", "phone", "email", "aadhaar", "abha", "pan", "mrn",
          "insurance", "address", "dob", "contact"}
QUASI = {"age", "sex", "pin", "city", "district", "state", "date", "diagnosis"}

_RULES = [
    ("text", r"\b(notes?|remarks?|comments?|history|summary|complaints?|chief complaint|observations?|findings|advice|instructions?|narrative|description|text|impression|course|टिप्पणी|शिकायत|विवरण|सारांश|नोट)\b"),
    ("doctor", r"\b(doctor|dr|consultant|physician|surgeon|treating|attending|referred by|ref by|referring|ordered by|requested by|reported by|entered by|signed by|verified by|reviewed by|examined by|seen by|authori[sz]ed by|approved by|pathologist|radiologist|clinician|prescriber|practitioner|डॉक्टर|चिकित्सक|डॉ)\b"),
    ("abha", r"\b(abha|health id|healthid|ndhm|abdm|आभा)\b"),
    ("aadhaar", r"\b(aadhaar|aadhar|adhaar|adhar|uidai|uid|आधार)\b"),
    ("pan", r"\b(pan|pan no|pan card|pan number|payer pan|permanent account)\b"),
    ("insurance", r"\b(insurance|policy|policy no|insurer|tpa|pmjay|pmjay id|ayushman|cghs|esic|echs|member id|card no|scheme id|beneficiary id|बीमा)\b"),
    ("record_id", r"\b(visit id|visit no|bill no|bill id|sample id|sample no|claim id|order id|report id|encounter id|episode id|lab no|accession|package code|invoice no|receipt no|token no|bed no|ward no)\b"),
    ("mrn", r"\b(uhid|mrn|mr no|mrd|medical record|patient id|pat id|pt id|pid|reg no|regn no|registration no|registration|ip no|op no|ipd no|opd no|cr no|hospital no|hosp no|case no|patient no|record id|patient ref|patient number|पंजीकरण|यूएचआईडी|id)\b"),
    ("email", r"\b(email|e mail|mail id|mail|ईमेल)\b"),
    ("phone", r"\b(phone|mobile|mobile no|mob|mob no|tel|telephone|cell|whatsapp|ph no|contact no|contact number|contact#|फोन|मोबाइल|फ़ोन)\b"),
    ("relative", r"\b(fathers?|husbands?|mothers?|spouses?|guardians?|relative name|pita pati|relative|kin|attendant|nok|next of kin|s o|d o|w o|h o|care of|so do wo|pita|pati|patni|wife|son of|daughter of|wife of|पिता|पति|पत्नी|माता|अभिभावक|परिजन)\b"),
    ("dob", r"\b(dob|d o b|date of birth|birth date|birthdate|born|janm|janam|janm tithi|जन्म|जन्मतिथि)\b"),
    ("date", r"\b(date|dt|admission|admitted|admit|discharge|discharged|visit|doa|dod|dated|tarikh|timestamp|datetime|time|दिनांक|तारीख|तिथि)\b"),
    ("age", r"\b(age|umar|umr|umra|aayu|उम्र|आयु|वय)\b"),
    ("age", r"\b(age sex|age gender|sex age)\b"),
    ("sex", r"\b(sex|gender|ling|लिंग)\b"),
    ("pin", r"\b(pin|pincode|pin code|postal|postal code|zip|zipcode|पिन|पिनकोड)\b"),
    ("state", r"\b(state|राज्य)\b"),
    ("district", r"\b(district|distt|dist|zila|zilla|jila|jilla|जिला|जनपद)\b"),
    ("village", r"\b(village|vill|gaon|gram|mohalla|gram mohalla|गांव|गाँव|ग्राम|मोहल्ला)\b"),
    ("tehsil", r"\b(tehsil|taluka|taluk|block|mandal|तहसील)\b"),
    ("city", r"\b(city|town|शहर|कस्बा)\b"),
    ("address", r"\b(address|addr|add|pata|street|locality|area|house|colony|landmark|residence|resident|r o|line|पता|निवास|निवासी)\b"),
    ("first_name", r"\b(first name|firstname|given name|given|fname|f name|forename)\b"),
    ("last_name", r"\b(last name|lastname|surname|family name|family|lname|l name)\b"),
    ("name", r"\b(name|naam|nam|patient|pt name|full name|fullname|middle name|नाम|मरीज|रोगी|मरीज़)\b"),
    ("contact", r"\b(contact|emergency|संपर्क)\b"),
    ("diagnosis", r"\b(diagnosis|dx|disease|condition|icd|problem|निदान|बीमारी|रोग)\b"),
    ("hospital", r"\b(hospital|facility|centre|center|clinic|अस्पताल)\b"),
    ("clinical", r"\b(drug|medicine|medication|meds|dose|dosage|rx|prescription|lab|test|result|value|unit|units|bp|pulse|temp|temperature|spo2|weight|height|ward|bed|department|dept|frequency|duration|route|vitals?|procedure)\b"),
]
_LB = r"(?<![0-9a-z\u0900-\u097F])"
_RB = r"(?![0-9a-z\u0900-\u097F])"
_COMPILED = [(t, re.compile(p.replace(r"\b(", _LB + "(", 1).replace(r")\b", ")" + _RB))) for t, p in _RULES]


def norm_label(label):
    s = str(label)
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)  # camelCase
    s = s.lower()
    s = re.sub(r"[^a-z0-9\u0900-\u097F]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def classify_label(label, parent=None):
    n = norm_label(label)
    if not n:
        return None
    if parent in ("name", "relative"):
        if re.search(r"\b(first|given|fname|forename)\b", n):
            return "first_name" if parent == "name" else "relative"
        if re.search(r"\b(last|surname|family|lname|middle|prefix|suffix|text|full)\b", n):
            return "last_name" if parent == "name" else "relative"
    if parent == "address" and re.search(r"\b(line|street|village|house|landmark|locality)\b", n):
        return "address"
    if re.search(r"\b(address|addr|pata|पता)\b", n) and not re.search(r"\b(email|e mail|ip|web)\b", n):
        return "address"
    for t, rx in _COMPILED:
        if rx.search(n):
            if t == "relative" and re.search(r"\b(relation|relationship)\b", n) and not re.search(r"\bname\b", n):
                return None
            if t == "date" and re.search(r"\b(birth|dob)\b", n):
                return "dob"
            if t in ("mrn", "record_id") and re.search(r"\b(date|dt|on|time)\b", n):
                return "date"
            if t == "name" and re.search(r"\b(hospital|drug|medicine|test|doctor|ward|file)\b", n):
                continue
            return t
    return None


# ---------------------------------------------------------------- value profiling
_PHONE_V = re.compile(r"^\s*(?:(?:\+|00)?91[\s.-]?|0)?[6-9]\d{2}[\s.-]?\d{3}[\s.-]?\d{4}\s*$|^\s*(?:(?:\+|00)?91[\s.-]?|0)?[6-9]\d{4}[\s.-]?\d{5}\s*$")
_EMAIL_V = re.compile(r"^\s*[\w.+-]+@[\w-]+(\.[\w-]+)+\s*$")
_AADHAAR_V = re.compile(r"^\s*[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\s*$|^\s*[xX*]{4}[\s-]?[xX*]{4}[\s-]?\d{4}\s*$")
_PAN_V = re.compile(r"^\s*[A-Za-z]{5}\d{4}[A-Za-z]\s*$")
_ABHA_V = re.compile(r"^\s*\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\s*$|^\s*[\w.]+@(abdm|sbx|ndhm)\s*$")
_PIN_V = re.compile(r"^\s*[1-9]\d{2}\s?\d{3}\s*$")
_AGE_V = re.compile(r"^\s*\d{1,3}\s*(y|yr|yrs|years?|m|months?|वर्ष|साल)?\s*$", re.I)
_SEX_V = re.compile(r"^\s*(m|f|male|female|o|other|t|tg|पुरुष|महिला|स्त्री|अन्य)\s*$", re.I)
_DATE_V = re.compile(r"^\s*(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{1,2}[\s-][A-Za-z]{3,9}[\s-]\d{2,4})([T ]\d{1,2}:\d{2}.*)?\s*$")
_ID_V = re.compile(r"^\s*(?=[A-Za-z0-9/_-]*\d)(?=[A-Za-z0-9/_-]*[A-Za-z])[A-Za-z0-9/_-]{5,24}\s*$")
_WORD = re.compile(r"[A-Za-z][A-Za-z.']*|[\u0900-\u0963\u0970-\u097F]+")


def looks_like_name(v, dyn=None):
    from .translit import fold, devanagari_to_latin, has_devanagari
    lex = get_lexicon()
    v = str(v).strip()
    if not v or re.search(r"\d|@", v) or len(v) > 60:
        return False
    toks = _WORD.findall(v)
    if not 1 <= len(toks) <= 5:
        return False
    hits = 0
    for t in toks:
        tl = t.lower().strip(".")
        if lex.is_medical(tl) and tl not in lex.names:
            return False
        lat = devanagari_to_latin(t) if has_devanagari(t) else t
        f = fold(lat)
        if tl in lex.names or f in lex.names_f or (dyn is not None and f in dyn):
            hits += 1
    return hits >= 1


def infer_from_values(values, dyn=None):
    vals = [str(v) for v in values if v is not None and str(v).strip() != ""][:300]
    if len(vals) < 2:
        return None
    n = float(len(vals))
    checks = [
        ("email", _EMAIL_V), ("abha", _ABHA_V), ("aadhaar", _AADHAAR_V), ("phone", _PHONE_V), ("pan", _PAN_V),
        ("date", _DATE_V), ("pin", _PIN_V), ("sex", _SEX_V),
    ]
    for t, rx in checks:
        if sum(1 for v in vals if rx.match(v)) / n >= 0.7:
            return t
    if sum(1 for v in vals if re.match(r"(?i)\s*(?:dr\.?|prof\.?|डॉ\.?|डॉक्टर)\s", v)) / n >= 0.6:
        return "doctor"   # a column of "Dr. ..." values is the treating clinician, not the patient
    if sum(1 for v in vals if looks_like_name(v, dyn)) / n >= 0.6:
        return "name"
    if sum(1 for v in vals if _ID_V.match(v)) / n >= 0.8:
        return "mrn"
    return None


def value_type(v):
    """Type of a single scalar value (used for shifted-column realignment scoring)."""
    s = str(v)
    if not s.strip():
        return "empty"
    for t, rx in (("email", _EMAIL_V), ("phone", _PHONE_V), ("aadhaar", _AADHAAR_V), ("pan", _PAN_V),
                  ("date", _DATE_V), ("pin", _PIN_V), ("sex", _SEX_V), ("age", _AGE_V)):
        if rx.match(s):
            return t
    if _ID_V.match(s):
        return "mrn"
    if re.fullmatch(r"\s*-?\d+(\.\d+)?\s*", s):
        return "number"
    return "text"


def date_order_hint(label):
    n = str(label).lower()
    if re.search(r"mm\W?dd\W?yy", n):
        return "mdy"
    if re.search(r"dd\W?mm\W?yy", n):
        return "dmy"
    return None
