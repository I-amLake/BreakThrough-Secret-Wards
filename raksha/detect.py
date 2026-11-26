"""Multilingual PII detection for free text (English / Devanagari Hindi / Hinglish).

Stages (all deterministic, rule + gazetteer based):
  A. clinical shielding   - doses, regimens, vitals, labs, eponyms are locked first
  B. high-precision regex - phones, Aadhaar (+Verhoeff boost), ABHA, PAN, email, labelled IDs,
                            dates, ages, PIN codes, addresses (Devanagari digits normalised)
  C. label:value parsing  - "Name: ..", "पिता का नाम: ..", "Mob- .." reuse the header classifier
  D. name finding         - honorific / relation / patient cues, Hinglish postpositions,
                            gazetteer + dataset-learnt lexicon (cross-script), doctor protection
Overlaps are arbitrated by a fixed priority table.
"""
import re

from .lexicon import get_lexicon
from .schema import classify_label
from .translit import devanagari_to_latin, fold, has_devanagari

DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

PRIORITY = {"MED": 100, "DOCTOR": 95, "EMAIL": 90, "ABHA": 89, "AADHAAR": 88, "PAN": 88, "PHONE": 87,
            "MRN": 85, "INSURANCE": 85, "ID": 84, "DATE": 70, "DOB": 71, "AGE": 65, "PIN": 62, "ADDRESS": 60,
            "NAME": 50}
PII_KINDS = {"EMAIL", "ABHA", "AADHAAR", "PAN", "PHONE", "MRN", "INSURANCE", "ID", "PIN", "ADDRESS", "NAME", "DOB"}


class Span:
    __slots__ = ("start", "end", "kind", "text", "role", "meta")

    def __init__(self, start, end, kind, text, role=None, meta=None):
        self.start, self.end, self.kind, self.text, self.role = start, end, kind, text, role
        self.meta = meta or {}

    def __repr__(self):
        return "Span(%d,%d,%s,%s)" % (self.start, self.end, self.kind, self.role)


# ------------------------------------------------------------------ Stage A: shielding
_UNITS = r"(?:mg|mcg|µg|ug|gm|g|kg|ml|mL|l|L|iu|IU|units?|U|meq|mEq|%|mmhg|mmHg|bpm|/min|mg/dl|mg/dL|g/dl|g/dL|mmol/l|mmol/L|/ul|/uL|/cumm|lakh|cells|°F|°C|F|C|cm|mm|puffs?|tabs?|caps?|drops?)"
SHIELD_RX = [
    re.compile(r"(?i)(?<![0-9a-f-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f-])"),   # UUIDs (FHIR ids)
    # organisation names: "Shanti Nagar Charitable Hospital", "Seva Sadan", "City Labs"
    re.compile(r"(?:\b[A-Z][A-Za-z.&'-]+[ \t]+){1,4}(?:(?i:Hospitals?|Sadan|Clinic|Nursing Home|Medical College|Labs?|Laboratory|Diagnostics|Trust|Charitable|Foundation|Pharmacy|Chikitsalaya|Aushadhalaya)|CHC|PHC)\b"),
    re.compile(r"\b(?i:District|Civil|General|Community|Primary|Sub[- ]?District|Women'?s?|Base|Railway|ESI|Government|Govt\.?|Zila)[ \t]+(?i:Hospital|Chikitsalaya|Health Centre|Health Center)(?:[ \t]+[A-Z][a-z]+)?"),
    re.compile(r"\b[0-5]\s?-\s?[0-5]\s?-\s?[0-5](?:\s?-\s?[0-5])?\b"),                     # 1-0-1
    re.compile(r"\b\d+(?:\.\d+)?[ \t]?" + _UNITS + r"(?![A-Za-z])"),                          # 5 mg
    re.compile(r"\b(?:BP|B\.P\.?)\s*[:=-]?\s*\d{2,3}\s*/\s*\d{2,3}(?:\s*mm\s?hg)?", re.I),    # BP 150/90
    re.compile(r"\b(?:HR|PR|RR|SpO2|SPO2|Temp|T|Pulse|RBS|FBS|PPBS|HbA1c|Hb|TLC|Plt|Platelets?|Cr|Creat|eGFR|TSH|Na|K|INR|ESR|CRP|Wt|Ht|BMI|GCS)\s*[:=-]?\s*\d+(?:[.,]\d+)*", re.I),
    re.compile(r"\b[xX×]\s?\d+\s?(?:days?|d|wks?|weeks?|months?|mths?|yrs?|years?|दिन)\b"),  # x 5 days
    re.compile(r"\b\d+(?:,\d{2})*,\d{3}\b"),                                                # 1,50,000
]


# ------------------------------------------------------------------ Stage B: regex PII
_NB = r"(?<![\w])(?<!\d[-/.])"
RX_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RX_ABHA_ADDR = re.compile(r"[A-Za-z0-9._]+@(?:abdm|sbx|ndhm)\b", re.I)
RX_ABHA = re.compile(_NB + r"\d{2}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}(?![\w])|" + _NB + r"\d{14}(?![\w])")
RX_AADHAAR = re.compile(_NB + r"[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![\w])|(?:[xX*]{4}[\s-]?){2}\d{4}(?![\w])")
RX_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{3}[PCHFATBLJGpchfatbljg][A-Za-z]\d{4}[A-Za-z](?![A-Za-z0-9])")
RX_PHONE = re.compile(
    _NB + r"(?:(?:\+|00)\s?91[\s.-]?|91[\s.-]|0)?\(?[6-9]\d{4}\)?[\s.-]?\d{5}(?![\w])|"
    + _NB + r"(?:(?:\+|00)\s?91[\s.-]?|91[\s.-]|0)?[6-9]\d{2}[\s.-]\d{3}[\s.-]\d{4}(?![\w])|"
    + _NB + r"(?:(?:\+|00)\s?91[\s.-]?|91)?[6-9]\d{9}(?![\w])|"
    + _NB + r"\(?0\d{2,4}\)?[\s-]\d{6,8}(?![\w])|"
    + r"(?<![\w])[6-9]\d[xX*]{6}\d{2}(?![\w])")
_ID_LABEL = (r"(?:uhid|u\.h\.i\.d|mrn|m\.?r\.?\s?no|mr\s?number|ip\.?\s?no|op\.?\s?no|ipd\s?no|opd\s?no|reg(?:istration|n)?\.?\s?no|"
             r"cr\.?\s?no|patient\s?id|pt\.?\s?id|pid|hosp(?:ital)?\.?\s?no|case\s?no|file\s?no|lab\s?no|sample\s?id|"
             r"यूएचआईडी|पंजीकरण\s?(?:संख्या|नं)?)")
_INS_LABEL = (r"(?:policy\s?(?:no|number|id)?|insurance\s?(?:id|no|number)?|member\s?id|card\s?no|pmjay\s?(?:id)?|ayushman\s?(?:card|id)?|"
              r"tpa\s?id|cghs\s?(?:no|id)?|esic\s?(?:no|id)?|echs\s?(?:no|id)?|claim\s?no|बीमा\s?(?:संख्या|नं)?)")
_GOV_LABEL = r"(?:aadhaa?r|adhaa?r|uid|आधार|abha|health\s?id|pan(?:\s?no| card)?)"
RX_LABELED_ID = re.compile(r"(?i)\b(" + _ID_LABEL + r"|" + _INS_LABEL + r")\s*(?:no\.?|number|#)?\s*[:#.=\-–]?\s*([A-Za-z0-9][A-Za-z0-9/_.\-]{2,30})")
RX_UNLABELED_ID = re.compile(r"(?<![\w/-])(?=[A-Z0-9/-]*\d)[A-Z]{1,6}(?:-[A-Z]{2,6})?[-/]?(?:\d{2,4}[-/])?\d{3,10}(?:[-/][A-Z0-9]{1,6})?(?![\w/-])")
RX_LONGNUM = re.compile(r"(?<![\w.,])\d{7,}(?![\w.,])")
RX_PIN_CTX = re.compile(r"(?i)(?:pin\s?code|pincode|pin|postal\s?code|zip|पिन\s?(?:कोड)?)\s*[:#.\-–]?\s*([1-9]\d{2}\s?\d{3})(?!\d)")
RX_PIN_TAIL = re.compile(r"(?<![\d])([1-9]\d{2}\s?\d{3})(?!\d)")
_ADDR_TRIG = (r"(?:address|addr\.?|add\.|r/o|resident\s+of|residing\s+at|res\.|permanent\s+address|present\s+address|"
              r"पता|निवासी|निवास|vill(?:age)?\.?|gram|gaon|gaanv|gaw|mauza|ग्राम|गांव|गाँव|मौजा|mohalla|मोहल्ला|h\.?\s?no\.?|house\s+no\.?|flat\s+no\.?|gali|गली)")
_VILL = r"(?:vill(?:age)?|gram|gaon|gaanv|gaw|mauza|ग्राम|गांव|गाँव|मौजा)"
_RX_VILL_WORD = re.compile(r"(?i)" + _VILL)
_RX_VILL_END = re.compile(r"(?i)\s*(?:[,\n;|(]|-\s|\s(?:tehsil|teh\.?|tahsil|post|p\.\s?o\.?|distt?\.?|district|thana|block|near|pin|तहसील|पोस्ट|जिला|जनपद|ब्लॉक|थाना|के\s+पास))")
RX_VILLAGE = re.compile(r"(?i)(?<![\w\u0900-\u097F])" + _VILL + r"\.?\s*[:\-]?\s*([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F ]{1,40}?)(?=\s*(?:[,\n;|(]|$|\s(?:tehsil|teh\.?|tahsil|post|distt?\.?|district|thana|block|pin|तहसील|पोस्ट|जिला|जनपद|ब्लॉक|थाना)))")
RX_ADDR = re.compile(r"(?i)(?<![\w])(" + _ADDR_TRIG + r")(?:\s*\([^)\n]{1,25}\))?[ \t]*[:\-–]?[ \t]*")
RX_ADDR_STOP = re.compile(r"(?i)[\n|;]|\s(?:mob(?:ile)?|ph(?:one)?|contact|tel|age|sex|gender|aadhaa?r|uhid|mrn|dob|diagnosis|dx|c/o|complaint|उम्र|मोबाइल|फोन|आधार)(?![\w\u0900-\u097F])|(?<=[A-Za-z0-9\u0900-\u097F])\.\s+(?=[A-Z][a-z]+\s+[a-z])|।")
_ADDR_ABBR = {"vill", "distt", "dist", "teh", "h.no", "no", "p.o", "po", "ps", "near", "opp", "st", "rd", "gram", "mohalla", "sec", "nr"}
RX_DISTRICT = re.compile(r"(?i)(?:distt?\.?|district|zila|zilla|जिला|जनपद)\s*[:\-]?\s*([A-Za-z\u0900-\u0963\u0970-\u097F]+(?:\s(?!pin|state|up\b)[A-Za-z\u0900-\u0963\u0970-\u097F]+)?)")
STATES = ["andhra pradesh", "arunachal pradesh", "assam", "bihar", "chhattisgarh", "goa", "gujarat", "haryana",
          "himachal pradesh", "jharkhand", "karnataka", "kerala", "madhya pradesh", "maharashtra", "manipur",
          "meghalaya", "mizoram", "nagaland", "odisha", "orissa", "punjab", "rajasthan", "sikkim", "tamil nadu",
          "telangana", "tripura", "uttar pradesh", "uttarakhand", "west bengal", "delhi", "jammu and kashmir",
          "ladakh", "puducherry", "chandigarh", "उत्तर प्रदेश", "बिहार", "मध्य प्रदेश", "राजस्थान", "दिल्ली"]
RX_STATE = re.compile(r"(?i)\b(" + "|".join(re.escape(s) for s in STATES) + r"|[A-Z][a-z]+\s+Pradesh|[\u0900-\u097F]+\s+प्रदेश)\b")

_AGE_UNIT = r"(?:years?|yrs?\.?|yr\.?|y\.?o\.?|yo|y|Y|yr\s+old|years?\s+old|वर्ष(?:ीय)?|साल|saal|sal|baras)"
RX_AGE = [
    re.compile(r"(?i)\b(?:age[d]?|aged|umar|umr|उम्र|आयु)(?:\s*/\s*(?:sex|gender|ling|लिंग))?\s*[:\-=]?\s*(\d{1,3})(?!\d)"),
    re.compile(r"(?<![\w/])(\d{1,3})\s?(?:-?\s?years?-?\s?old|-year-old|yrs?\s?old|y/o|yo\b|y\.o\.)", re.I),
    re.compile(r"(?<![\w/.])(\d{1,3})\s?(?i:y|yr|yrs|years?)\.?\s?[/,]?\s?(?:M|F|Male|Female|male|female)\b"),
    re.compile(r"(?<![\w/.])(\d{1,3})\s?/\s?(?:M|F|Male|Female)\b"),
    re.compile(r"\b(?:M|F)\s?/\s?(\d{1,3})(?![\d/])"),
    re.compile(r"(?<![\d])(\d{1,3})\s?(?:वर्ष|वर्षीय|साल)\s?(?:का|की|के|वर्षीय|पुरुष|महिला)"),
    re.compile(r"(?<![\w/.])(\d{1,3})\s?(?:M|F)\b(?![/\-])"),
]
RX_AGE_NEG = re.compile(r"(?i)\b(?:age[d]?|umar|umr|उम्र|आयु)(?:\s*/\s*(?:sex|gender|ling|लिंग))?\s*[:=(]\s*(-\s?\d{1,3})(?![\d.])")
RX_SEX = re.compile(r"(?<![\w\u0900-\u097F])((?i:male|female|man|woman|boy|girl|aurat|aadmi)|पुरुष|महिला|स्त्री|लड़का|लड़की)(?![\w\u0900-\u097F])"
                    r"|(?<![\d.])\d{1,3}\s?(?:(?i:y|yr|yrs|years?|वर्ष|साल)\.?)?\s?/\s?([MFmf])\b|(?<![\d.])\d{1,3}\s?([MF])\b(?![\d.])"
                    r"|\b([MF])\s?/\s?\d|(?i:sex|gender|ling|लिंग)\s*[:\-]?\s*([MF])\b")

_AMBIG_CTX = re.compile(r"\s+(?:ji|jee|devi|bai|ben|kumari)\b|\s*,?\s*[SWDCH]\s?/\s?[oO]\b|\s+[A-Z][a-z]+\s*,\s*[SWDCH]/[oO]\b|\s*\(\s*\d{1,3}\s*(?:y|yrs?|years?)?\s*/?\s*[MF]\b")
_SENT_LAT = re.compile(r"[A-Za-z]+(?:'(?![sS]\b)[A-Za-z]+)*\.?|[\u0900-\u0963\u0970-\u097F]+\.?")

# relation marker -> (canonical role of the RELATIVE, sex hint for the PATIENT)
#   P = parent/father, PM = mother, SP = spouse, CH = child, C = care-of, G = other
REL_LETTER = {"S": ("P", "M"), "D": ("P", "F"), "W": ("SP", "F"), "H": ("SP", "M"), "F": ("CH", "M"),
              "M": ("CH", "F"), "C": ("C", None), "B": ("PM", None)}
REL_WORD = {"son of": ("P", "M"), "daughter of": ("P", "F"), "wife of": ("SP", "F"), "husband of": ("SP", "M"),
            "father of": ("CH", "M"), "mother of": ("CH", "F"), "care of": ("C", None),
            "पुत्र": ("P", "M"), "सुपुत्र": ("P", "M"), "पुत्री": ("P", "F"), "सुपुत्री": ("P", "F"),
            "पत्नी": ("SP", "F"), "धर्मपत्नी": ("SP", "F"), "पति": ("SP", "F"), "पिता": ("P", None), "माता": ("PM", None)}
REL_NOUN = {"wife": ("SP", "M"), "patni": ("SP", "M"), "biwi": ("SP", "M"), "husband": ("SP", "F"), "pati": ("SP", "F"),
            "son": ("CH", None), "daughter": ("CH", None), "beta": ("CH", None), "beti": ("CH", None), "bahu": ("G", None),
            "father": ("P", None), "mother": ("PM", None)}
REL_POST = {"wife": ("SP", "F"), "patni": ("SP", "F"), "biwi": ("SP", "F"), "पत्नी": ("SP", "F"), "pati": ("SP", "M"),
            "husband": ("SP", "M"), "पति": ("SP", "M"), "beta": ("P", "M"), "bete": ("P", "M"), "son": ("P", "M"),
            "बेटा": ("P", "M"), "बेटे": ("P", "M"), "beti": ("P", "F"), "daughter": ("P", "F"), "बेटी": ("P", "F"),
            "maa": ("CH", "F"), "mother": ("CH", "F"), "माँ": ("CH", "F"), "माता": ("CH", "F"), "papa": ("CH", "M"),
            "father": ("CH", "M"), "पिता": ("CH", "M"), "bahu": ("G", "F"), "बहू": ("G", "F")}


def label_relation(label):
    l = label.lower()
    if re.search(r"husband|pati|पति|w o|w/o", l):
        return ("SP", "F")
    if re.search(r"wife|patni|पत्नी", l):
        return ("SP", "M")
    if re.search(r"spouse", l):
        return ("SP", None)
    if re.search(r"mother|mata|माता|माँ", l):
        return ("PM", None)
    if re.search(r"father|pita|पिता|s o|d o|s/o|d/o", l):
        return ("P", None)
    if re.search(r"care of|c o|c/o", l):
        return ("C", None)
    return ("G", None)


RX_REL = re.compile(r"(?<![\w])(?:([SDWHFMCB])\s?[/.\\]\s?[oO]\.?|son of|daughter of|wife of|husband of|father of|mother of|care of|पुत्र|सुपुत्र|पुत्री|सुपुत्री|धर्मपत्नी|पत्नी|पति|पिता|माता)(?![\w\u0900-\u097F])", re.I)
RX_REL_NOUN = re.compile(r"(?i)\b(wife|husband|son|daughter|father|mother|beta|beti|patni|pati|biwi|bahu|attendant|guardian|relative|bhai|brother|sister|bahan|behen"
                         r"|neighbou?r|caretaker|informant|companion|escort|attender|bystander)\b(?:'s)?\s*(?:name)?\s*(?:(?:was|is|hai|tha|thi|named|called)\s+)?[:\-]?\s*(?=[A-Z\u0900-\u097F])")
_NON_KIN = {"neighbour", "neighbor", "caretaker", "informant", "companion", "escort", "attender", "bystander", "attendant", "guardian", "relative"}
_PLACE_WORDS = {"hospital", "district", "tehsil", "village", "nagar", "pur", "ganj", "road", "colony", "mohalla", "ward", "block",
                "lucknow", "delhi", "india", "pradesh", "uttar", "bihar", "chc", "phc", "medical", "college", "clinic", "centre", "center"}
# Hinglish subject/object markers after a capitalised word: "Subodh ne bataya", "Subodh aur uski wife"
RX_HINGLISH_ARG = re.compile(r"(?<![\w.'])([A-Z][a-z]{2,})(?=\s+(?:ne|ko|ka|ki|ke|se|aur|bhi|ji|bole|boli|bola)\s+[a-z])")
RX_REL_POST = re.compile(r"(?i)\s+(?:ki|ke|ka|की|के|का)\s+(wife|patni|biwi|pati|husband|beta|beti|bete|son|daughter|father|mother|maa|papa|bahu|पत्नी|पति|बेटा|बेटी|बेटे|पिता|माता|माँ|बहू)(?![\w\u0900-\u097F])")
RX_DOCTOR = re.compile(r"(?<![\w])(?:Dr|DR|dr|Doctor|Prof)\.?\s*(?=[A-Z\u0900-\u097F])|(?:डॉ|डा|डॉक्टर)\.?\s*")
RX_BY_CUE = re.compile(r"(?i)(?<![\w])(?:called|witnessed|raised|brought|accompanied|informed|signed|reported|requested|visited|escorted|consented|filled|registered|attended|countersigned)\s+by\s*:?\s*(?=[A-Z\u0900-\u097F])")
RX_ROLE_AFTER = re.compile(r"(?<![\w.])((?:[A-Z][a-z]+ ){1,2}[A-Z][a-z]+)(?=\s*\(\s*(?:attendant|visitor|relative|guardian|caretaker|bystander|wife|husband|son|daughter|mother|father|brother|sister|patient|pt|informant|witness)\b|\s*,?\s*(?:mob(?:ile)?|ph(?:one)?|contact|tel|cell)\.?\s*(?:no\.?)?\s*[:\-]?\s*(?:\+?91[\s-]?)?[6-9]\d)")
RX_BEFORE_REL = re.compile(r"(?<![\w.])((?:[A-Z][a-z]+ ){0,2}[A-Z][a-z]+),?\s+[SWD]\s?/\s?[oO]\.?\s+(?=[A-Z])")
RX_PATIENT_CUE = re.compile(r"(?i)(?<![\w])(?:report\s+(?:of|for)|pt\.?|patient(?:\s+name)?|name|naam|mareez|marij|मरीज़?|रोगी|नाम)\s*(?:is|:|-|–|=)?\s*(?=[A-Za-z\u0900-\u097F])")
_COMPLAINT_HINT = re.compile(r"(?i)^\s*[:\-]?\s*(?:\d|fever|pain|cough|cold|vomit|loose|burning|breath|headache|abd|chest|weakness|giddiness|swelling|bleeding|itching|rash|sob|bukhar|dard|khansi|ulti|chakkar|बुखार|दर्द|खांसी|उल्टी|सांस|चक्कर|pet|sir|severe|mild|high|low|h/o|known|k/c/o)")


def verhoeff_ok(num):
    d = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
         [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
         [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
         [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
    p = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
         [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
         [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = d[c][p[i % 8][int(ch)]]
    return c == 0


def digits_only(s):
    return re.sub(r"\D", "", s.translate(DIGITS))


def norm_phone(s):
    d = digits_only(s)
    if len(d) >= 10 and d[-10] in "6789":
        return d[-10:]
    return d.lstrip("0") or d


class Detector:
    def __init__(self, dyn_names=None):
        self.lex = get_lexicon()
        self.dyn = dyn_names if dyn_names is not None else set()   # folded tokens learnt from structured data

    # ---------------------------------------------------------------- token helpers
    def _tok_ok_latin(self, tok, lenient):
        t = tok.rstrip(".")
        tl = t.lower()
        if len(t) == 1:
            return t.isupper()  # initial
        if re.fullmatch(r"(?:[A-Z]\.){2,3}[A-Z]?", tok):
            return True
        if tl in self.lex.stop_latin or tl in self.lex.honor_pre or tl in self.lex.honor_suf:
            return False
        if self.lex.is_medical(tl) and tl not in self.lex.names and tl not in self.lex.ambiguous:
            return False
        if tl in self.lex.ambiguous and not lenient:
            return False
        f = fold(tl)
        known = tl in self.lex.names or f in self.lex.names_f or f in self.dyn
        if lenient:
            return known or t[0].isupper()
        return known and t[0].isupper()

    def _tok_ok_deva(self, tok, lenient):
        t = tok.rstrip(".")
        if t in self.lex.stop_hindi or t in self.lex.honor_pre or t in self.lex.honor_suf or len(t) < 2:
            return False
        lat = devanagari_to_latin(t)
        f = fold(lat)
        if not f or lat in self.lex.medical or f in self.lex.medical:
            return False
        known = f in self.lex.names_f or f in self.dyn
        return known or lenient

    def plausible_name_tok(self, tok):
        """An unknown word that can still be a given name: Titlecase Latin, 3+ letters, and not a
        stop/common/medical word, honorific, unit or place word. Used only next to a name cue."""
        t = tok.rstrip(".")
        if not re.fullmatch(r"[A-Z][a-z]{2,}", t):
            return False
        tl = t.lower()
        lex = self.lex
        if lex.is_common(t) or lex.is_medical(t) or tl in lex.honor_pre or tl in lex.honor_suf:
            return False
        if tl in _PLACE_WORDS or tl in lex.surnames:
            return tl in lex.surnames and not lex.is_surname_only(t)
        return True

    def tok_ok(self, tok, lenient):
        if has_devanagari(tok):
            return self._tok_ok_deva(tok, lenient)
        return self._tok_ok_latin(tok, lenient)

    @staticmethod
    def _joinable(text, prev, nxt):
        """prev/nxt are token tuples. Only spaces join, or '.'/'. ' after an initial."""
        between = text[prev[1]:nxt[0]]
        if re.fullmatch(r" {1,2}", between) or (between == "" and prev[2].endswith(".")):
            ok = True
        elif re.fullmatch(r"\. ?", between):
            ok = bool(re.fullmatch(r"[A-Z]|(?:[A-Z]\.){1,3}[A-Z]?", prev[2].rstrip(".")))
        else:
            ok = False
        if ok and re.fullmatch(r"[A-Za-z]\.?", nxt[2]) and text[nxt[1]:nxt[1] + 1] in ("/", "\\"):
            ok = False  # "S/o"
        if ok and prev[2].endswith(".") and len(prev[2].rstrip(".")) > 1 and not re.fullmatch(r"(?:[A-Z]\.)+", prev[2]):
            ok = False  # sentence end "Rajan. Rajan"
        return ok

    def _tokens(self, text):
        return [(m.start(), m.end(), m.group(0)) for m in _SENT_LAT.finditer(text)]

    def _collect_forward(self, text, toks, pos, maxn=3, lenient=True):
        """Name tokens starting at char pos. Skips honorifics. Returns (start,end) or None."""
        idx = next((i for i, t in enumerate(toks) if t[0] >= pos), None)
        if idx is None:
            return None
        gap = text[pos:toks[idx][0]]
        if len(gap) > 3 or re.search(r"[,;\n|()]", gap):
            return None
        # skip honorifics / "late"
        while idx < len(toks) and toks[idx][2].rstrip(".").lower() in self.lex.honor_pre:
            idx += 1
        start = end = None
        n = 0
        while idx < len(toks) and n < maxn:
            s, e, w = toks[idx]
            if end is not None and not self._joinable(text, toks[idx - 1], toks[idx]):
                break
            if re.fullmatch(r"[A-Za-z]\.?", w) and text[e:e + 1] in ("/", "\\"):
                break
            if not self.tok_ok(w, lenient):
                break
            if w.endswith(".") and len(w.rstrip(".")) > 1 and not re.fullmatch(r"(?:[A-Z]\.)+", w):
                e -= 1
                start = s if start is None else start
                end = e
                n += 1
                break
            start = s if start is None else start
            end = e
            n += 1
            idx += 1
        if start is None:
            return None
        # do not end on a bare initial
        seg = text[start:end]
        if re.fullmatch(r"(?:[A-Z](?:\.\s?|\s+|$))+", seg):
            return None
        return start, end

    def _collect_backward(self, text, toks, pos, maxn=2):
        idx = None
        for i in range(len(toks) - 1, -1, -1):
            if toks[i][1] <= pos:
                idx = i
                break
        if idx is None:
            return None
        if len(text[toks[idx][1]:pos]) > 2 or re.search(r"[,;\n]", text[toks[idx][1]:pos]):
            return None
        start = end = None
        n = 0
        while idx >= 0 and n < maxn:
            s, e, w = toks[idx]
            if start is not None and not self._joinable(text, toks[idx], toks[idx + 1]):
                break
            if not self.tok_ok(w.rstrip("."), True):
                break
            if not has_devanagari(w) and not w[0].isupper() and fold(w) not in self.lex.names_f and fold(w) not in self.dyn:
                break
            end = e if end is None else end
            start = s
            n += 1
            idx -= 1
        return (start, end) if start is not None else None

    # ---------------------------------------------------------------- main entry
    def detect(self, text, field_hint=None, order=None, year=None):
        """Return resolved list of Spans for text."""
        if not text or not text.strip():
            return []
        norm = text.translate(DIGITS)
        spans = []
        # A. shielding
        for rx in SHIELD_RX:
            for m in rx.finditer(norm):
                spans.append(Span(m.start(), m.end(), "MED", m.group(0)))
        # B. regex identifiers
        for m in RX_ABHA_ADDR.finditer(norm):
            spans.append(Span(m.start(), m.end(), "ABHA", m.group(0)))
        for m in RX_EMAIL.finditer(norm):
            spans.append(Span(m.start(), m.end(), "EMAIL", m.group(0)))
        for m in RX_ABHA.finditer(norm):
            spans.append(Span(m.start(), m.end(), "ABHA", digits_only(m.group(0))))
        for m in RX_AADHAAR.finditer(norm):
            raw = m.group(0)
            d = digits_only(raw)
            ctx = norm[max(0, m.start() - 30):m.start()].lower()
            labelled = bool(re.search(r"aadhaa?r|adhaa?r|uid|आधार", ctx))
            if not labelled and d.startswith("91") and d[2] in "6789" and len(d) == 12 and not verhoeff_ok(d):
                continue  # +91 phone without separators: handled by phone regex
            spans.append(Span(m.start(), m.end(), "AADHAAR", d, meta={"verhoeff": len(d) == 12 and verhoeff_ok(d)}))
        for m in RX_PAN.finditer(norm):
            w = m.group(0)
            if w.isupper() or re.search(r"(?i)pan", norm[max(0, m.start() - 15):m.start()]):
                spans.append(Span(m.start(), m.end(), "PAN", w.upper()))
        for m in RX_PHONE.finditer(norm):
            spans.append(Span(m.start(), m.end(), "PHONE", norm_phone(m.group(0))))
        for m in RX_LABELED_ID.finditer(norm):
            val = m.group(2).rstrip(".-")
            if not re.search(r"\d", val):
                continue
            label = m.group(1).lower()
            kind = "INSURANCE" if re.match(_INS_LABEL, label, re.I) else "MRN"
            spans.append(Span(m.start(2), m.start(2) + len(val), kind, val.upper()))
        for m in RX_UNLABELED_ID.finditer(norm):
            w = m.group(0)
            if sum(c.isdigit() for c in w) >= 5 and sum(c.isalpha() for c in w) >= 1:
                spans.append(Span(m.start(), m.end(), "ID", w.upper()))
        for m in RX_LONGNUM.finditer(norm):
            spans.append(Span(m.start(), m.end(), "ID", m.group(0)))
        # dates
        from .dates import find_dates
        for a, b, d, f in find_dates(norm, order, year):
            ctx = norm[max(0, a - 25):a].lower()
            kind = "DOB" if re.search(r"dob|d\.o\.b|birth|जन्म", ctx) else "DATE"
            spans.append(Span(a, b, kind, norm[a:b], meta={"date": d, "fmt": f}))
        # ages
        for rx in RX_AGE:
            for m in rx.finditer(norm):
                age = int(m.group(1))
                st = m.start(1)
                if 0 <= age <= 120:
                    spans.append(Span(st, m.end(1), "AGE", str(age), meta={"age": age}))
                elif rx is RX_AGE[0]:   # "Age: 150": implausible -> masked, never a fake band
                    spans.append(Span(st, m.end(1), "AGE", str(age), meta={"age": None}))
        for m in RX_AGE_NEG.finditer(norm):   # "Age: -2": a data error; mask sign and digits together
            spans.append(Span(m.start(1), m.end(1), "AGE", m.group(1), meta={"age": None}))
        # PIN with context
        for m in RX_PIN_CTX.finditer(norm):
            spans.append(Span(m.start(1), m.end(1), "PIN", digits_only(m.group(1))))
        # addresses
        for m in RX_ADDR.finditer(text):
            st = m.end()
            en = min(len(text), st + 160)
            for stop in RX_ADDR_STOP.finditer(text, st):
                if stop.group(0).startswith("."):
                    prevw = re.findall(r"[\w.]+$", text[st:stop.start()])
                    if prevw and prevw[0].lower().strip(".") in _ADDR_ABBR:
                        continue
                en = min(en, stop.start())
                break
            seg = text[st:en].rstrip(" ,.-")
            if len(seg.strip()) < 2:
                continue
            en = st + len(seg)
            spans.append(Span(st, en, "ADDRESS", seg, meta=self.parse_address(seg, m.group(1))))
        # C. label:value lines
        spans.extend(self._label_values(text, norm))
        # D. names
        spans.extend(self._names(text))
        return self.resolve(spans)

    # ---------------------------------------------------------------- address parsing
    def parse_address(self, seg, trigger=None):
        norm = seg.translate(DIGITS)
        meta = {}
        v = None
        if trigger and _RX_VILL_WORD.fullmatch(trigger.strip().rstrip(".")):
            v = _RX_VILL_END.split(norm, 1)[0]
        else:
            m = RX_VILLAGE.search(norm)
            if m:
                v = m.group(1)
        if v:
            v = re.sub(r"[^A-Za-z\u0900-\u097F ]", " ", v).strip()
            if 2 <= len(v) <= 40:
                meta["village"] = v
        m = RX_DISTRICT.search(norm)
        if m:
            meta["district"] = m.group(1).strip().title() if not has_devanagari(m.group(1)) else m.group(1).strip()
        m = RX_STATE.search(norm)
        if m:
            meta["state"] = m.group(1).strip().title() if not has_devanagari(m.group(1)) else m.group(1).strip()
        pins = RX_PIN_TAIL.findall(norm)
        if pins:
            meta["pin"] = re.sub(r"\s", "", pins[-1])
        return meta

    # ---------------------------------------------------------------- label:value
    _SEG_SPLIT = re.compile(r"\s*(?:\||;|\t|\s{3,})\s*")
    _LV = re.compile(r"^\s*([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F /.'()&_-]{0,38}?)\s*[:：=]\s*(.+?)\s*$")

    def _chunks(self, line):
        """Split a line into (offset, label, value_offset, value) label:value chunks."""
        parts = []
        for m in re.finditer(r"[^|;\t,]+|[|;\t,]", line):
            parts.append((m.start(), m.group(0)))
        chunks = []
        for off, p in parts:
            if p in "|;\t,":
                if chunks and p == ",":
                    chunks[-1][1] += p
                elif chunks:
                    chunks[-1][2] = True  # hard separator closes the chunk
                continue
            m = self._LV.match(p)
            if m and classify_label(m.group(1)) is not None and len(m.group(1).split()) <= 5:
                chunks.append([off, p, False])
            elif chunks and not chunks[-1][2]:
                chunks[-1][1] += p
            else:
                chunks.append([off, p, True])
        out = []
        for off, p, _ in chunks:
            m = self._LV.match(p)
            if not m:
                continue
            value = m.group(2).rstrip(" ,")
            out.append((off, m.group(1), off + m.start(2), value))
        return out

    def _label_values(self, text, norm):
        out = []
        pos = 0
        for line in text.split("\n"):
            lstart = pos
            pos += len(line) + 1
            if ":" not in line and "：" not in line and "=" not in line:
                continue
            for off, label, voff, value in self._chunks(line):
                vstart = lstart + voff
                vend = vstart + len(value)
                t = classify_label(label)
                if t is None or not value.strip():
                    continue
                if t in ("name", "first_name", "last_name"):
                    v0 = value.split()[0].lower()
                    if re.search(r"\d|@", value) or (self.lex.is_medical(v0) and v0 not in self.lex.ambiguous
                                                     and v0 not in self.lex.names):
                        continue
                    nm = self._trim_name_value(text, vstart, vend)
                    if nm:
                        out.append(Span(nm[0], nm[1], "NAME", text[nm[0]:nm[1]], role="patient", meta={"label": True}))
                elif t == "relative":
                    nm = self._trim_name_value(text, vstart, vend)
                    if nm:
                        rel, psex = label_relation(label)
                        out.append(Span(nm[0], nm[1], "NAME", text[nm[0]:nm[1]], role="relative", meta={"rel": rel, "psex": psex, "label": True}))
                elif t == "doctor":
                    out.append(Span(vstart, vend, "DOCTOR", value))
                elif t == "address":
                    out.append(Span(vstart, vend, "ADDRESS", value, meta=self.parse_address(value)))
                elif t in ("aadhaar", "abha", "pan", "mrn", "insurance") and re.search(r"\d", norm[vstart:vend]):
                    val = norm[vstart:vend].split()[0] if t in ("mrn", "insurance") else norm[vstart:vend]
                    kind = {"aadhaar": "AADHAAR", "abha": "ABHA", "pan": "PAN", "mrn": "MRN", "insurance": "INSURANCE"}[t]
                    v = digits_only(val) if kind in ("AADHAAR", "ABHA") else val.upper()
                    out.append(Span(vstart, vstart + len(val), kind, v))
                elif t == "phone" and len(digits_only(value)) >= 8:
                    out.append(Span(vstart, vend, "PHONE", norm_phone(value)))
                elif t == "email" and "@" in value:
                    out.append(Span(vstart, vend, "EMAIL", value))
                elif t == "pin" and re.fullmatch(r"[1-9]\d{2}\s?\d{3}", norm[vstart:vend].strip()):
                    out.append(Span(vstart, vend, "PIN", digits_only(value)))
                elif t == "contact":
                    if len(digits_only(value)) >= 10:
                        out.append(Span(vstart, vend, "PHONE", norm_phone(value)))
        return out

    def _trim_name_value(self, text, vs, ve):
        toks = [t for t in self._tokens(text[vs:ve])]
        if not toks:
            return None
        start = end = None
        n = 0
        for s, e, w in toks:
            w2 = w.rstrip(".")
            if w2.lower() in self.lex.honor_pre:
                continue
            if w2.lower() in ("s/o", "d/o", "w/o") or self.lex.is_stop(w2) and w2.lower() not in self.lex.names:
                break
            if self.lex.is_medical(w2) and w2.lower() not in self.lex.names and w2.lower() not in self.lex.ambiguous:
                break
            if start is not None and re.search(r"[,;(/]", text[vs + end:vs + s]):
                break
            start = s if start is None else start
            end = e if not w.endswith(".") or len(w2) == 1 else e - 1
            n += 1
            if n >= 5:
                break
        if start is None:
            return None
        return vs + start, vs + end

    # ---------------------------------------------------------------- names
    def _names(self, text):
        lex = self.lex
        toks = self._tokens(text)
        out = []
        # doctors
        for m in RX_DOCTOR.finditer(text):
            r = self._collect_forward(text, toks, m.end(), 3, True)
            if r:
                out.append(Span(m.start(), r[1], "DOCTOR", text[m.start():r[1]]))
        # relation markers  S/o, W/o, पत्नी ...
        for m in RX_REL.finditer(text):
            letter = (m.group(1) or "").upper()
            word = m.group(0).lower()
            rel, psex = REL_LETTER[letter] if letter else REL_WORD.get(word, REL_WORD.get(m.group(0), ("G", None)))
            after = text[m.end():m.end() + 40]
            hindi_post = None
            if has_devanagari(m.group(0)):
                hindi_post = re.search(r"([\u0900-\u097F]+(?:\s[\u0900-\u097F]+)?)\s+(?:की|के|का)\s+$", text[max(0, m.start() - 40):m.start()])
            if rel == "C":
                nxt = re.match(r"\s*[:\-]?\s*([A-Za-z\u0900-\u097F.]+)", after)
                if not nxt or _COMPLAINT_HINT.match(after):
                    continue
                w = nxt.group(1).rstrip(".")
                is_person = (w.lower() in lex.honor_pre or (w[:1].isupper() and not lex.is_medical(w))
                             or (has_devanagari(w) and self.tok_ok(w, False)))
                if not is_person or lex.is_medical(w):
                    continue
            if letter == "H":
                # "H/O" is far more often "history of" than "husband of": demand a real name
                nxt = re.match(r"\s*[:\-]?\s*([A-Za-z\u0900-\u097F.]+)('?)", after)
                if not nxt or _COMPLAINT_HINT.match(after) or nxt.group(2):
                    continue
                w = nxt.group(1).rstrip(".")
                if not (w.lower() in lex.honor_pre or (w[:1].isupper() and not w.isupper() and self.tok_ok(w, False))
                        or (has_devanagari(w) and self.tok_ok(w, False))) or lex.is_medical(w.lower()):
                    continue
            r = self._collect_forward(text, toks, m.end() + len(re.match(r"\s*[:\-]?\s*", after).group(0)), 3, True)
            if r and not hindi_post:
                out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="relative", meta={"rel": rel, "psex": psex}))
            elif r:
                out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="cued", meta={}))
            if hindi_post:
                # Hindi order "राजन की पत्नी सीता": राजन is the relative (spouse/parent) of the subject
                pre = hindi_post
                b = self._collect_backward(text, toks, m.start() - len(pre.group(0)) + len(pre.group(1)), 2)
                if b:
                    prel = REL_POST.get(m.group(0), ("G", None))
                    out.append(Span(b[0], b[1], "NAME", text[b[0]:b[1]], role="relative", meta={"rel": prel[0], "psex": prel[1]}))
        # relation nouns  "wife Salma", "husband: Rajan"
        for m in RX_REL_NOUN.finditer(text):
            r = self._collect_forward(text, toks, m.end(), 3, True)
            if r and (text[r[0]].isupper() or has_devanagari(text[r[0]])):
                noun = m.group(1).lower()
                if not any(self.plausible_name_tok(t) or self.tok_ok(t, False) for t in text[r[0]:r[1]].split()):
                    continue
                if noun in _NON_KIN:   # neighbour, caretaker ...: a person, but not family evidence
                    out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="cued"))
                    continue
                rel, psex = REL_NOUN.get(noun, ("G", None))
                out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="relative", meta={"rel": rel, "psex": psex}))
        # Hinglish postposition "Rajan ki wife"
        for m in RX_REL_POST.finditer(text):
            b = self._collect_backward(text, toks, m.start(), 2)
            if b:
                rel, psex = REL_POST.get(m.group(1).lower(), REL_POST.get(m.group(1), ("G", None)))
                out.append(Span(b[0], b[1], "NAME", text[b[0]:b[1]], role="relative", meta={"rel": rel, "psex": psex}))
            # "Bitto ki maa Ramrati": a capitalised word right after the kin noun names the subject
            fw = re.match(r"\s*[:\-]?\s*", text[m.end():])
            r = self._collect_forward(text, toks, m.end() + fw.end(), 2, True)
            if r and all(self.plausible_name_tok(t) or self.tok_ok(t, False) for t in text[r[0]:r[1]].split()):
                out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="cued"))
        for m in RX_HINGLISH_ARG.finditer(text):
            w = m.group(1)
            if self.plausible_name_tok(w) or (self.tok_ok(w, False) and not lex.is_common(w)):
                st = m.start(1)
                # "Rukmini Devi ne", "Ram Prakash ko": take one more capitalised token on the left
                pv = re.search(r"([A-Z][a-z]{2,}) $", text[max(0, st - 30):st])
                if pv and (self.plausible_name_tok(pv.group(1)) or self.tok_ok(pv.group(1), False)):
                    st -= len(pv.group(0))
                out.append(Span(st, m.end(1), "NAME", text[st:m.end(1)], role="cued"))
        # honorific prefixes
        for s, e, w in toks:
            wl = w.rstrip(".").lower()
            if wl in lex.honor_pre or w.rstrip(".") in lex.honor_pre:
                if wl in ("late", "स्व", "स्वर्गीय", "baby", "बेबी", "master"):
                    pass
                r = self._collect_forward(text, toks, e, 3, True)
                if r:
                    sx = lex.honor_pre.get(wl, lex.honor_pre.get(w.rstrip("."), "U"))
                    out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="cued", meta={"sex": sx}))
        # honorific suffixes  "Arif sahab", "Sunita didi", "रमेश जी"
        for i, (s, e, w) in enumerate(toks):
            wl = w.lower().rstrip(".")
            if (wl in lex.honor_suf or w in lex.honor_suf) and i > 0:
                prev = toks[i - 1][2]
                if prev.lower() in ("dr", "doctor", "sister", "nurse", "madam", "sir", "mata", "pita", "guru", "baba") or lex.is_medical(prev):
                    continue
                b = self._collect_backward(text, toks, s, 2)
                if b is None:
                    pw = toks[i - 1]
                    if re.fullmatch(r" ", text[pw[1]:s]) and self.tok_ok(pw[2], True) and not self.lex.is_stop(pw[2]):
                        b = (pw[0], pw[1])
                if b:
                    sx = lex.honor_suf.get(wl, lex.honor_suf.get(w, "U"))
                    out.append(Span(b[0], b[1], "NAME", text[b[0]:b[1]], role="cued", meta={"sex": sx}))
        # patient cues
        for m in RX_PATIENT_CUE.finditer(text):
            r = self._collect_forward(text, toks, m.end(), 3, True)
            before = text[max(0, m.start() - 15):m.start()].lower()
            if r and re.search(r"father|husband|mother|guardian|spouse|wife|pita|pati|पिता|पति|माता|पत्नी|अभिभावक", before):
                continue
            if r:
                w = text[r[0]:r[1]]
                if has_devanagari(w) or w[0].isupper() or fold(w.split()[0]) in self.dyn or fold(w.split()[0]) in lex.names_f:
                    out.append(Span(r[0], r[1], "NAME", w, role="patient"))
        # context cues that need no gazetteer: "witnessed by X Y", "X Y (attendant, ...)", "X Y, mob 98..."
        for m in RX_BY_CUE.finditer(text):
            r = self._collect_forward(text, toks, m.end(), 3, True)
            if r:
                w = text[r[0]:r[1]]
                if all(t[:1].isupper() or has_devanagari(t) for t in w.split()):
                    out.append(Span(r[0], r[1], "NAME", w, role="cued"))
        for m in RX_BEFORE_REL.finditer(text):  # "Asha, W/o Kamal": the subject of a relation marker is a person
            w = m.group(1)
            if all(self._tok_ok_latin(t, True) and not lex.is_stop(t) and (not lex.is_medical(t.lower()) or t.lower() in lex.ambiguous)
                   and t.lower() not in lex.honor_pre for t in w.split()):
                out.append(Span(m.start(1), m.end(1), "NAME", w, role="cued"))
        for m in RX_ROLE_AFTER.finditer(text):
            w = m.group(1)
            parts = w.split()
            if all(self._tok_ok_latin(t, True) and not lex.is_stop(t) and not lex.is_medical(t.lower()) for t in parts):
                out.append(Span(m.start(1), m.end(1), "NAME", w, role="cued"))
        # gazetteer / learnt lexicon seeds (+ extension over adjacent name-ish tokens)
        allcaps = sum(1 for _, _, w in toks if w.isupper() and len(w) > 2) > 0.6 * max(1, len(toks))
        i = 0
        while i < len(toks):
            s, e, w = toks[i]
            seed = False
            wc = w.rstrip(".")
            if has_devanagari(wc):
                seed = self._tok_ok_deva(wc, False)
            else:
                f = fold(wc)
                if (wc.lower() in lex.names or f in self.dyn) and len(wc) >= 3:
                    if (wc[0].isupper() or allcaps) and self._tok_ok_latin(wc, False):
                        seed = True
                    elif wc.lower() in lex.ambiguous and wc[0].isupper() and _AMBIG_CTX.match(text, toks[i][1]):
                        seed = True  # "Asha ji", "Asha, W/o ..." (a name only with person context)
                    elif f in self.dyn and not lex.is_stop(wc) and not lex.is_medical(wc) and len(wc) >= 4:
                        seed = True
            if not seed:
                i += 1
                continue
            # extend backward over initials / capitalised tokens
            j = i
            # a family name / gendered suffix ("... Devi", "... Yadav", "... Bano") is preceded by the
            # given name even when that given name is in no gazetteer: accept up to two plausible tokens
            lead = 2 if (not has_devanagari(wc) and lex.is_surname_only(wc)) else 0
            while j - 1 >= 0 and self._joinable(text, toks[j - 1], toks[j]):
                pw = toks[j - 1][2]
                if re.fullmatch(r"[A-Z]\.?|(?:[A-Z]\.){2,3}", pw) or (self.tok_ok(pw, False)):
                    j -= 1
                elif lead and self.plausible_name_tok(pw):
                    j -= 1
                    lead -= 1
                else:
                    break
            k = i
            while k + 1 < len(toks) and self._joinable(text, toks[k], toks[k + 1]) and k - j < 3:
                nw = toks[k + 1][2].rstrip(".")
                if has_devanagari(nw):
                    ok = self._tok_ok_deva(nw, True) and has_devanagari(w)
                else:
                    ok = self._tok_ok_latin(nw, False) or (nw[:1].isupper() and self._tok_ok_latin(nw, True) and not self.lex.is_stop(nw) and len(nw) > 1) \
                        or (nw[:1].isupper() and lex.is_surname_only(nw))   # "Sarita Kumari", "Fatima Begum"
                if not ok:
                    break
                k += 1
            st, en = toks[j][0], toks[k][1]
            if text[st:en].endswith(".") and not re.search(r"\b[A-Z]\.$", text[st:en]):
                en -= 1
            out.append(Span(st, en, "NAME", text[st:en], role="gaz"))
            i = k + 1
        # eponym guard: "Parkinson's disease", "Bell's palsy"
        res = []
        for sp in out:
            if sp.kind == "NAME":
                tail = text[sp.end:sp.end + 25].lower()
                if re.match(r"'s?\s+(?:disease|syndrome|palsy|sign|test|law|tube|catheter|score|lactate|solution|phenomenon|fracture|ulcer)", tail):
                    continue
                if re.match(r"\s+(?:disease|syndrome|palsy|sign|lactate|catheter|tube|score)\b", tail):
                    continue
            res.append(sp)
        return res

    # ---------------------------------------------------------------- arbitration
    def resolve(self, spans):
        role_rank = {"patient": 5, "relative": 4, "cued": 3, "gaz": 1, None: 0}
        spans = sorted(spans, key=lambda s: (-PRIORITY.get(s.kind, 0), -role_rank.get(s.role, 0), -(s.end - s.start), s.start))
        chosen = []
        occupied = []
        for sp in spans:
            if sp.end <= sp.start:
                continue
            clash = False
            for o in occupied:
                if sp.start < o.end and o.start < sp.end:
                    clash = True
                    # NAME role upgrade: a patient/relative label overlapping a gaz name keeps the stronger role
                    if sp.kind == "NAME" and o.kind == "NAME" and role_rank.get(sp.role, 0) > role_rank.get(o.role, 0):
                        o.role = sp.role
                        o.meta.update(sp.meta)
                    break
            if clash:
                continue
            occupied.append(sp)
            chosen.append(sp)
        chosen.sort(key=lambda s: s.start)
        return chosen


def sex_hints(text, spans):
    """Return 'M'/'F'/None for the document's patient from explicit words and cues."""
    norm = text.translate(DIGITS)
    m = RX_SEX.search(norm)
    vals = []
    for m in RX_SEX.finditer(norm):
        w = (m.group(1) or m.group(2) or m.group(3) or m.group(4) or m.group(5) or "").lower()
        if w in ("male", "man", "boy", "पुरुष", "लड़का", "aadmi", "m"):
            vals.append("M")
        elif w in ("female", "woman", "girl", "महिला", "स्त्री", "लड़की", "aurat", "f"):
            vals.append("F")
    for sp in spans:
        if sp.kind == "NAME" and sp.role == "relative" and sp.meta.get("psex") in ("M", "F"):
            vals.append(sp.meta["psex"])
        if sp.kind == "NAME" and sp.meta.get("sex") in ("M", "F") and sp.role != "relative":
            vals.append(sp.meta["sex"])
    if not vals:
        return None
    return max(sorted(set(vals)), key=vals.count)
