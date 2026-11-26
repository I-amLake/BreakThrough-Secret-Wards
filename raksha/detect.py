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
from .translit import devanagari_to_latin, fold, has_devanagari, skeleton

DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

PRIORITY = {"EVENT": 69, "MED": 100, "DOCTOR": 95, "EMAIL": 90, "ABHA": 89, "AADHAAR": 88, "PAN": 88, "PHONE": 87,
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
_UNITS = r"(?:mg|mcg|µg|ug|gm|g|kg|ml|mL|l|L|iu|IU|units?|U|meq|mEq|%|mmhg|mmHg|bpm|/min|mg/dl|mg/dL|g/dl|g/dL|mmol/l|mmol/L|/ul|/uL|/cumm|lakh|cells|°F|°C|cm|mm|puffs?|tabs?|caps?|drops?)"
SHIELD_RX = [
    re.compile(r"(?i)(?<![0-9a-f-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f-])"),   # UUIDs (FHIR ids)
    # organisation names: "Navodaya Charitable Hospital", "Seva Sadan", "City Labs"
    re.compile(r"(?:\b[A-Z][A-Za-z.&'-]+[ \t]+){1,4}(?:(?i:Hospitals?|Sadan|Clinic|Nursing Home|Medical College|Labs?|Laboratory|Diagnostics|Trust|Charitable|Foundation|Pharmacy|Chikitsalaya|Aushadhalaya)|CHC|PHC)\b"),
    re.compile(r"\b(?i:District|Civil|General|Community|Primary|Sub[- ]?District|Women'?s?|Base|Railway|ESI|Government|Govt\.?|Zila)[ \t]+(?i:Hospital|Chikitsalaya|Health Centre|Health Center)(?:[ \t]+[A-Z][a-z]+)?"),
    re.compile(r"\b[0-5]\s?-\s?[0-5]\s?-\s?[0-5](?:\s?-\s?[0-5])?\b"),                     # 1-0-1
    re.compile(r"\b\d+(?:\.\d+)?[ \t]?" + _UNITS + r"(?![A-Za-z])"),                          # 5 mg
    # bare F / C only in body-temperature ranges: "101F", "38.5 C" (but "47F" is an age + sex)
    re.compile(r"\b(?:9\d|1[01]\d)(?:\.\d+)?[ \t]?F(?![A-Za-z])|\b(?:3[4-9]|4[0-4])(?:\.\d+)?[ \t]?C(?![A-Za-z])"),
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
RX_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{3}[PCHFATBLJGpchfatbljg][A-Za-z] ?\d{4} ?[A-Za-z](?![A-Za-z0-9])")
# a labelled PAN-shaped value even when the 4th (entity) letter is not an official one ("PAN XYZQB9876C"),
# and labelled government IDs with no fixed public format (voter ID / EPIC, passport, driving licence, ration card)
RX_PAN_LABELLED = re.compile(r"(?i)(?<![A-Za-z])(?:pan|p\.a\.n\.?|पैन)(?:\s*(?:no\.?|number|card|कार्ड|नं\.?))?\s*[:#.=\-–]?\s*"
                             r"([A-Za-z]{5} ?\d{4} ?[A-Za-z])(?![A-Za-z0-9])")
RX_GOV_LABELLED = re.compile(r"(?i)(?<![A-Za-z])(?:voter\s?id|epic(?:\s?no)?|election\s+card|passport|driving\s+licen[cs]e|"
                             r"\bdl|ration\s+card|मतदाता\s?पहचान|पासपोर्ट)(?:\s*(?:no\.?|number|#))?\s*[:#.=\-–]?\s*"
                             r"((?=[A-Za-z0-9/\-]*\d{3})[A-Za-z0-9][A-Za-z0-9/\-]{5,19})(?![A-Za-z0-9])")
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
_ADDR_TRIG = (r"(?:address|addr\.?|add\.|r/o|resident\s+of|residing\s+at|resides\s+at|stays\s+at|staying\s+at|lives\s+at|living\s+at|"
              r"makan\s+(?:no\.?|number|nambar|sankhya)|मकान\s+(?:नं\.?|नंबर|संख्या)|res\.|permanent\s+address|present\s+address|"
              r"पता|निवासी|निवास|vill(?:age)?\.?|gram|gaon|gaanv|gaw|mauza|ग्राम|गांव|गाँव|मौजा|mohalla|मोहल्ला|h\.?\s?no\.?|house\s+no\.?|flat\s+no\.?|gali|गली)")
_VILL = r"(?:vill(?:age)?|gram|gaon|gaanv|gaw|mauza|ग्राम|गांव|गाँव|मौजा)"
_RX_VILL_WORD = re.compile(r"(?i)" + _VILL)
_RX_HOUSE_NO_BEFORE = re.compile(r"(?:^|(?<=[\n,(]))\s*(\d{1,4}[A-Za-z]?(?:/[A-Za-z0-9]{1,4})?)[,\s]+$")
_RX_WEAK_ADDR_TRIG = re.compile(r"(?i)" + _VILL + r"|gali|गली|mohalla|मोहल्ला")
_RX_ADDR_FUNC_NEXT = re.compile(r"(?i)(?:mein|me|mai|se|ka|ki|ke|ko|wale|waale|wali|par|pe|tak|walon|log|records?|in|of|for|is|was|and|or|the|"
                                r"में|से|का|की|के|को|वाले|वाली|पर|तक|लोग)(?![\w\u0900-\u097F])")
_RX_VILL_END = re.compile(r"(?i)\s*(?:[,\n;|(]|-\s|\s(?:tehsil|teh\.?|tahsil|post|p\.\s?o\.?|distt?\.?|district|thana|block|near|pin|तहसील|पोस्ट|जिला|जनपद|ब्लॉक|थाना|के\s+पास))")
RX_VILLAGE = re.compile(r"(?i)(?<![\w\u0900-\u097F])" + _VILL + r"\.?\s*[:\-]?\s*([A-Za-z\u0900-\u097F][A-Za-z\u0900-\u097F ]{1,40}?)(?=\s*(?:[,\n;|(]|$|\s(?:tehsil|teh\.?|tahsil|post|distt?\.?|district|thana|block|pin|तहसील|पोस्ट|जिला|जनपद|ब्लॉक|थाना)))")
RX_ADDR = re.compile(r"(?i)(?<![\w\u0900-\u097F])(" + _ADDR_TRIG + r")(?:\s*\([^)\n]{1,25}\))?[ \t]*[:\-–]?[ \t]*")
RX_ADDR_STOP = re.compile(r"(?i)[\n|;]|\s(?:mob(?:ile)?|ph(?:one)?|contact|tel|age|sex|gender|aadhaa?r|uhid|mrn|dob|diagnosis|dx|c/o|complaint|उम्र|मोबाइल|फोन|आधार)(?![\w\u0900-\u097F])|(?<=[A-Za-z0-9\u0900-\u097F])\.\s+(?=[A-Z][a-z]+\s+[a-z])|(?<=[A-Za-z0-9\u0900-\u097F])\.\s+(?=[A-Z][A-Za-z/ ]{0,20}\s?:)|।")
_RX_NAME_TAIL_LABEL = re.compile(r"\s+(?:MRN|UHID|UID|ABHA|PAN|DOB|D\.O\.B|IPD|OPD|IP|OP|ID|CR|REG|Regn|Reg\.|Age|Sex|M/F|F/M|PIN|Ph|Mob)\.?\s*[:#\-]?\s*$")
_DEVA_FUNC = {"और", "को", "का", "की", "के", "ने", "से", "में", "पर", "है", "हैं", "था", "थी", "श्री", "श्रीमती", "मरीज", "मरीज़", "रोगी", "नाम"}
_ADDR_NOUNS = {"house", "h.no", "flat", "plot", "row", "sector", "sec", "phase", "block", "nagar", "colony", "road", "rd", "lane", "street",
               "gali", "marg", "chowk", "bagh", "ganj", "pur", "civil", "lines", "apartments", "apartment", "apts", "tower", "towers", "society",
               "enclave", "vihar", "park", "extension", "ext", "market", "bazar", "bazaar", "mohalla", "village", "near", "opp", "no", "green"}
_ADDR_ABBR = {"vill", "distt", "dist", "teh", "h.no", "no", "p.o", "po", "ps", "near", "opp", "st", "rd", "gram", "mohalla", "sec", "nr"}
RX_DISTRICT = re.compile(r"(?i)(?:(?<![a-z])(?:district|distt?\.?|zila|zilla)(?![a-z])|जिला|जनपद)\s*[:\-]?\s*([A-Za-z\u0900-\u0963\u0970-\u097F]+(?:\s(?!pin|state|up\b)[A-Za-z\u0900-\u0963\u0970-\u097F]+)?)")
STATES = ["andhra pradesh", "arunachal pradesh", "assam", "bihar", "chhattisgarh", "goa", "gujarat", "haryana",
          "himachal pradesh", "jharkhand", "karnataka", "kerala", "madhya pradesh", "maharashtra", "manipur",
          "meghalaya", "mizoram", "nagaland", "odisha", "orissa", "punjab", "rajasthan", "sikkim", "tamil nadu",
          "telangana", "tripura", "uttar pradesh", "uttarakhand", "west bengal", "delhi", "jammu and kashmir",
          "ladakh", "puducherry", "chandigarh", "उत्तर प्रदेश", "बिहार", "मध्य प्रदेश", "राजस्थान", "दिल्ली"]
RX_STATE = re.compile(r"(?i)\b(" + "|".join(re.escape(s) for s in STATES) + r"|[A-Z][a-z]+\s+Pradesh|[\u0900-\u097F]+\s+प्रदेश)\b")

_AGE_UNIT = r"(?:years?|yrs?\.?|yr\.?|y\.?o\.?|yo|y|Y|yr\s+old|years?\s+old|वर्ष(?:ीय)?|साल|saal|sal|baras|varsh)"
RX_AGE = [
    re.compile(r"(?i)\b(?:age[d]?|aged|umar|umr|umra|aayu|aayu|ayu|उम्र|उमर|आयु)(?:\s*/\s*(?:sex|gender|ling|लिंग))?\s*[:\-=]?\s*(\d{1,3})(?!\d)"),
    re.compile(r"(?<![\w/])(\d{1,3})\s?(?:-?\s?years?-?\s?old|-year-old|yrs?\s?old|y/o|yo\b|y\.o\.)", re.I),
    re.compile(r"(?<![\w/.])(\d{1,3})\s?(?i:y|yr|yrs|years?)\.?\s?[/,]?\s?(?:M|F|Male|Female|male|female)\b"),
    re.compile(r"(?<![\w/.])(\d{1,3})\s?/\s?(?:M|F|Male|Female)\b"),
    re.compile(r"\b(?:M|F)\s?/\s?(\d{1,3})(?![\d/])"),
    re.compile(r"(?<![\d])(\d{1,3})\s?(?:वर्ष|वर्षीय|साल)\s?(?:का|की|के|वर्षीय|पुरुष|महिला)"),
    re.compile(r"(?<![\w/.])(\d{1,3})\s?(?:M|F)\b(?![/\-])"),
]
_AGE_WORD_UNIT = re.compile(r"(?i)[\s-]*(years?|yrs?\.?|yr\.?|saal|sal|baras|baras|varsh|वर्षीया|वर्षीय|वर्ष|साल|बरस)(?![A-Za-z\u0900-\u097F])")
_AGE_WORD_CUE = re.compile(r"(?i)(?:\bage[d]?|\bumar|\bumr|\bumra|\baayu|उम्र|उमर|आयु|\bturns?|\bturned|\bturning|\bwill\s+turn)\s*(?:of|is|was|hai|:|-|=)?\s*$")
_AGE_WORD_SUFFIX = re.compile(r"(?i)^[\s,]*(?:old\b|ka\b|ki\b|ke\b|ki\s|की|का|के|वाली|वाला|वाले)(?![\s,]*(?:baad|pehle|pahle|andar|tak|बाद|पहले|अंदर|तक)\b)")
_AGE_DIGIT_EXTRA = [
    re.compile(r"(?<=\()\s*(\d{1,3})\s?(?i:yrs?|years?)\.?\s*(?=[,)])"),                       # "(46 yrs)"
    re.compile(r"(?i)(?<![\w/.])(\d{1,3})\s?(?:saal|sal|varsh|baras)\s(?:ka|ki|ke)\b(?!\s+(?:baad|pehle|pahle|andar|tak)\b)"),
    re.compile(r"(?i)\b(?:turns?|turned|turning|will\s+turn)\s+(\d{1,3})(?![\d/.:-])"),
]
_HINGLISH_SMALL = {"ek", "do", "teen", "char", "chaar", "paanch", "panch", "chhe", "chheh", "saat", "aath", "nau", "das", "sau"}
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
from .namefind import CharNgramScorer, NameFinder, NamePropagator, norm_latin  # noqa: E402
_RX_PLACE_CTX = re.compile(r"\s+(?:se\s+(?:aa|aay|aaye|aayi|aaya|aai|aaye\s+the|laaye|laya|refer)|ko\s+refer|(?:mein|me|main)\s+(?:rehte|rehti|rahte|rahti|bhej)|tak\s+(?:gaye|gayi)"
                           r"|से\s+(?:आ|लाए|लाया|रेफर)|को\s+रेफर|में\s+(?:रहत|भेज))", re.I)
# Structural cues that a weakly-detected word is a complaint/drug, not a person.
_RX_THING_RIGHT = re.compile(r"\s+(?:(?:ki|ka|की|का)\s+(?:shikayat|shikaayat|takleef|taklif|dose|शिकायत|तकलीफ़?|डोज़?)"
                             r"|(?:ke|के)\s+(?:baad|bad|pehle|pahle|dauran|samay|बाद|पहले|दौरान|समय)(?![\w\u0900-\u097F])"
                             r"|(?:ne|ने)\s+(?:kaam|asar|fayda|faayda|असर|काम|फ़?ायदा)\s+(?:kiya|kar|diya|किया|कर|दिया))", re.I)
_RX_DRUG_LEFT = re.compile(r"(?:\b(?:tab|tabs|tablet|cap|caps|capsule|syp|syrup|inj|injection|oint|ointment|drops?|started|start|continue|stop|stopped)\.?|टैबलेट|गोली|सिरप|इंजेक्शन)\s+$", re.I)
_RX_KO_LEFT = re.compile(r"(?:\bko|को)\s+$", re.I)
_RX_COPULA_RIGHT = re.compile(r"\s+(?:hai|tha|thi|ho\s+gay[ai]|है|था|थी|हो\s+गय[ाी])(?![\w\u0900-\u097F])", re.I)
# ---- cue-less person frames (no postposition, honorific or label next to the name)
_CL_TEMPORAL = {"aaj", "kal", "abhi", "subah", "shaam", "sham", "raat", "dopahar", "phir", "ab", "parson", "ko", "aaj", "today",
                "आज", "कल", "अभी", "सुबह", "शाम", "रात", "दोपहर", "फिर", "अब", "परसों", "को"}
# Only verbs whose subject is a person: honorific/plural "came/went" forms (a symptom "aaya/aayi/आई" is
# excluded on purpose: "bukhar aaya", "हिचकी आई") and speech/admission verbs.
_CL_PERSON_VERB = {"aaye", "aayin", "aaeen", "gaye", "chale", "bharti", "bhartee", "bataya", "batayi", "batai", "kaha", "boli",
                   "bole", "bola", "ro", "rone", "chilla",
                   "आए", "आये", "आईं", "गए", "गये", "गईं", "चले", "भर्ती", "बताया", "बताई", "कहा", "बोली", "बोले", "बोला", "रो"}
_CL_HONOR_STATE = re.compile(r"(?:\s+(?:ab|अब|abhi|अभी))?\s+(?:theek|thik|stable|behtar|better|ठीक|स्थिर|बेहतर)\s+(?:hain|हैं)(?![\w\u0900-\u097F])", re.I)
_CL_EN_LEFT = re.compile(r"(?i)\b(?:(?:spoke|talked|discussed|explained|counsell?ed)(?:\s+[a-z]+){0,4}?\s+(?:to|with)|called(?:\s+back)?|informed|told|"
                         r"counsell?ed|reassured|phoned|met|consoled)\s+(?=[A-Z])")
_CL_EN_SUBJ = re.compile(r"\s+(?:was|is|has\s+been|got|had\s+been)\s+(?:admitted|discharged|brought|counsell?ed|examined|operated|shifted|seen)\b", re.I)
_CL_DEMO = re.compile(r"(?m)^[ \t]*((?:[A-Z][a-z]{2,}|[\u0900-\u097F]{2,})(?:[ \t]+(?:[A-Z][a-z]{2,}|[\u0900-\u097F]{2,})){0,2})"
                      r"[ \t]*\([ \t]*\d{1,3}[ \t]*(?:y|yr|yrs|Y|वर्ष|साल)?[ \t]*/[ \t]*(?:M|F|m|f|पु|म|स्त्री)[ \t]*\)")
_CL_MIN_P = 0.3   # name-scorer floor inside a person frame (the lexicon guards do most of the work)
_CL_COND = {"haalat", "halat", "haalaat", "tabiyat", "tabiyet", "tabeeyat", "tabiyat", "sehat", "condition", "हालत", "तबीयत", "तबियत", "सेहत"}
_CL_EXPERIENCER = re.compile(r"(?:\s+[A-Za-z\u0900-\u097F]+){1,3}?\s+(?:ho\s+rah[aie]|hai|hain|aaya|aayi|aaye|lag\s+rah[aie]|lagi|hua|hui|"
                             r"है|हैं|हो\s+रह[ाीे]|आया|आई|आए|लग\s+रह[ाीे]|हुआ|हुई)(?![\w\u0900-\u097F])", re.I)
# generic person-role / group nouns: subjects of person verbs that are not names
_ROLE_NOUNS = {"relative", "relatives", "rishtedar", "rishtedaar", "gharwale", "gharwaale", "parivar", "family", "saathi", "sathi", "dost",
               "friend", "friends", "padosi", "neighbour", "neighbor", "attendant", "attendants", "attender", "nurse", "sister", "doctor",
               "doctors", "staff", "ward", "boy", "aaya", "ayah", "bhai", "behen", "beta", "beti", "bachche", "bachcha", "baccha", "log",
               "sab", "mareez", "marij", "patient", "patients", "mother", "father", "husband", "wife", "son", "daughter", "pati", "patni",
               "रिश्तेदार", "घरवाले", "परिवार", "साथी", "दोस्त", "पड़ोसी", "पडोसी", "नर्स", "सिस्टर", "डॉक्टर", "डाक्टर", "स्टाफ",
               "भाई", "बहन", "बेटा", "बेटी", "बच्चे", "बच्चा", "लोग", "सब", "मरीज़", "मरीज", "पति", "पत्नी", "माँ", "मां", "पिता"}
# a following department/organisation head makes the capitalised object a unit, not a person ("Blood Bank")
_RX_ORG_NEXT = re.compile(r"\s+(?:Bank|Team|Department|Dept\.?|Unit|Ward|OPD|Clinic|Lab|Laboratory|Desk|Counter|Office|Services|Staff|Room|Theatre|Section|Store)\b")
_CL_TOK = re.compile(r"[A-Za-z]+|[\u0900-\u0963\u0970-\u097F]+")
_CL_CLAUSE = re.compile(r"[^.!?।\n;:,()\[\]]+")
# ---- addresses without a trigger word: structure, not labels
_LOC_HEAD_L = (r"(?:Nagar|Colony|Tola|Marg|Vihar|Puram|Basti|Purwa|Chowk|Bazaa?r|Road|Rd\.?|Street|Lane|Gali|Mohalla|Enclave|Market|"
               r"Mandi|Nagla|Khurd|Kalan|Ganj|Para|Patti|Kheda|Khera|Extension|Layout|Society|Apartments?|Complex|Sector\s?\d{1,3}|Phase\s?\d{1,2})")
_LOC_HEAD_D = r"(?:नगर|कॉलोनी|कालोनी|टोला|मार्ग|रोड|विहार|बस्ती|पुरवा|चौक|बाज़ार|बाजार|गंज|मंडी|नगला|खुर्द|कलां|कला|मोहल्ला|गली|पुरम|सेक्टर\s?\d{1,3})"
_LMK_HEAD_L = (r"(?:Mandir|Masjid|School|Vidyalaya|Chauraha|Tiraha|(?:Pani\s)?Tanki|Post\s?Office|Petrol\s?Pump|Gurudwara|Church|Thana|"
               r"Chowki|Railway\s(?:Crossing|Station|Phatak)|Bus\s?(?:Stand|Adda)|Talab|Pul|Park|Mazar|Dharamshala|Tower|Water\sTank)")
_LMK_HEAD_D = r"(?:मंदिर|मस्जिद|स्कूल|विद्यालय|चौराहा|तिराहा|(?:पानी\s)?टंकी|डाकघर|पेट्रोल\sपंप|गुरुद्वारा|थाना|चौकी|स्टेशन|बस\sअड्डा|तालाब|पुल|पार्क|मज़ार|मजार)"
_ROOT_L = r"(?:[A-Z][a-z]+(?:\s(?!(?:Pani|Post|Petrol|Railway|Bus|Water)\b)[A-Z][a-z]+)?)"
_ROOT_D = r"(?:[\u0900-\u0963\u0970-\u097F]+(?:\s(?!(?:पानी|पेट्रोल|बस)\s)[\u0900-\u0963\u0970-\u097F]+)?)"
_HOUSE = r"(?:\d{1,4}(?:\s?[/-]\s?\d{1,4})?[A-Za-z]?)"
RX_HOUSE_CUE = re.compile(r"(?i)(?<![\w\u0900-\u097F])(?:(?:ghar|makaa?n|house|flat|मकान|घर)\s*(?:no\.?|number|nambar|नं\.?|नंबर|संख्या)|h\.?\s?no\.?)"
                          r"\s*[:\-.]?\s*(\d{1,4}(?:\s?[/-]\s?\d{1,4})?[A-Za-z]?)(?![\d/])")
RX_HEAD_FIRST = re.compile(r"(?<![\w\u0900-\u097F])(?:Tola|Mohalla|Purwa|Basti|टोला|मोहल्ला|पुरवा|बस्ती)[ \t]+([A-Z][a-z]{2,}|[\u0900-\u097F]{2,})(?![\w\u0900-\u097F])")
RX_ADDR_TAIL = re.compile(r"[ \t]*,[ \t]*([A-Z][a-z]{3,}|[\u0900-\u097F]{3,})(?=\s*(?:[.,;।\n]|$))")
RX_LOC_L = re.compile(r"(?<![\w/])(?:(" + _HOUSE + r")\s*[,\-]?\s*)?(" + _ROOT_L + r")\s+" + _LOC_HEAD_L + r"(?![A-Za-z])")
RX_LOC_D = re.compile(r"(?<![\w\u0900-\u097F/])(?:(" + _HOUSE + r")\s*[,\-/]?\s*)?(" + _ROOT_D + r")\s+" + _LOC_HEAD_D + r"(?![\u0900-\u097F])")
RX_LMK_L = re.compile(r"(?i:\b(?:near|nr\.?|opp\.?|opposite|behind|beside|next\s+to|in\s+front\s+of)\s+)(?:the\s+)?(" + _ROOT_L + r"\s+)?" + _LMK_HEAD_L + r"\b"
                      r"|(" + _ROOT_L + r"\s+)?" + _LMK_HEAD_L + r"(?=\s+ke\s+(?:paas|pass|saamne|samne|peeche|piche)\b)")
RX_LMK_D = re.compile(r"(" + _ROOT_D + r"\s+)?" + _LMK_HEAD_D + r"(?=\s+के\s+(?:पास|सामने|पीछे|बगल))")
RX_PIN_AFTER_PLACE = re.compile(r"([A-Za-z\u0900-\u097F]+)[,\s]\s?([1-9]\d{2}\s?\d{3})(?![\d])")
_WEAK_CUE_MIN_P = 0.3  # min name-classifier probability for an unknown word after a weak Hinglish cue
_SCORER = []


def _shared_scorer():
    if not _SCORER:
        _SCORER.append(CharNgramScorer())
    return _SCORER[0]

_NF_MODE = 2  # 1 = NameFinder, 2 = NameFinder + in-document name propagation
_NON_KIN = {"neighbour", "neighbor", "caretaker", "informant", "companion", "escort", "attender", "bystander", "attendant", "guardian", "relative"}
_PLACE_WORDS = {"hospital", "district", "tehsil", "village", "nagar", "pur", "ganj", "road", "colony", "mohalla", "ward", "block",
                "lucknow", "delhi", "india", "pradesh", "uttar", "bihar", "chc", "phc", "medical", "college", "clinic", "centre", "center"}
# Hinglish subject/object markers after a capitalised word: "Thivaresh ne bataya", "Thivaresh aur uski wife"
RX_HINGLISH_ARG = re.compile(r"(?<![\w.'])([A-Z][a-z]{2,})(?=\s+(?:ne|ko|ka|ki|ke|se|aur|bhi|ji|bole|boli|bola)\s+[a-z])")
RX_ALIAS_PRE = re.compile(r"(?i)(?<![\w])(?:also\s+known\s+as|a\.?k\.?a\.?|alias|urf|उर्फ|nick\s?name(?:\s+is)?|pet\s+name(?:\s+is)?|"
                          r"ghar\s+(?:ka|ki|ke)\s+naam|घर\s+का\s+नाम|called\s+(?:as\s+)?|known\s+as|goes\s+by)(?![\w\u0900-\u097F])")
RX_ALIAS_POST = re.compile(r"(?i)\s+(?:(?:naam|name)\s+se\s+)?(?:bulate|bulaate|bulati|bulaati|pukarte|pukaarte|kehte|kahte|bolte)\s+(?:hain|hai|the|thi)"
                           r"|\s+(?:ke|ki)\s+naam\s+se(?:\s+jaan|\s+bul|\s+mash)|\s+(?:नाम\s+से\s+)?(?:बुलाते|पुकारते|कहते)\s+(?:हैं|है|थे)")
RX_REL_POST = re.compile(r"(?i)\s+(?:ki|ke|ka|की|के|का)\s+(wife|patni|biwi|pati|husband|beta|beti|bete|son|daughter|father|mother|maa|papa|bahu|पत्नी|पति|बेटा|बेटी|बेटे|पिता|माता|माँ|बहू)(?![\w\u0900-\u097F])")
RX_DOCTOR = re.compile(r"(?<![\w])(?:Dr|DR|dr|Doctor|Prof)\.?\s*(?=[A-Z\u0900-\u097F])|(?<![\w\u0900-\u097F])(?:डॉक्टर|डॉ|डा)(?![\u0900-\u097F])\.?\s*")
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
        self.scorer = _shared_scorer()
        self.name_finder = NameFinder(lex=self.lex, scorer=self.scorer) if _NF_MODE else None
        self.strict = 0
        self.cl_min_p = _CL_MIN_P

    def set_strict(self, level, drop=0.35):
        """Stigma Shield: 0 = normal, 1 = stricter unseen-name threshold, 2 = strictest (self-check retry)."""
        self.strict = level
        self.cl_min_p = _CL_MIN_P - (0.0, 0.1, 0.2)[level]
        if self.name_finder is not None:
            self.name_finder.thr_drop = (0.0, drop, 2.5 * drop)[level]

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

    @staticmethod
    def _weak_negative_context(text, sp):
        """A weakly-detected single word followed by 'se aaye' / 'ko refer' / 'mein rehte' is a place."""
        if sp.kind != "NAME" or sp.role not in ("ctx", "morph", "prop") and not sp.meta.get("weak"):
            return False
        if _RX_PLACE_CTX.match(text, sp.end) or _RX_THING_RIGHT.match(text, sp.end):
            return True
        left = text[max(0, sp.start - 24):sp.start]
        if _RX_DRUG_LEFT.search(left):
            return True
        return bool(_RX_KO_LEFT.search(left) and _RX_COPULA_RIGHT.match(text, sp.end))

    def _root_ok(self, root):
        """Every word of a locality/landmark root must be an unknown or name-like word, never a clinical,
        stop or common word ("Pain near ...", "Road traffic ...", "Medicine Market" stay)."""
        lex = self.lex
        for w in root.split():
            if has_devanagari(w):
                if w in lex.stop_hindi:
                    return False
                lat = devanagari_to_latin(w)
                if lat in lex.medical or lat in lex.common or lat in lex.stop_latin:
                    return False
            elif lex.is_medical(w) or lex.is_stop(w) or (lex.is_common(w) and w.lower() not in lex.names):
                return False
        return True

    def _structural_addresses(self, text, spans):
        """House number + locality ("45 Kalvo Nagar", "45 कलवो टोला"), a locality phrase on its own, and
        landmarks ("near X Mandir", "X मंदिर के पास"), found without any Address/Vill./पता trigger."""
        taken = [(sp.start, sp.end) for sp in spans if sp.kind in ("ADDRESS", "MED", "DOCTOR")]
        out = []

        def add(st, en, has_house):
            if en - st < 4 or any(st < b and a < en for a, b in taken):
                return
            seg = text[st:en]
            out.append(Span(st, en, "ADDRESS", seg, meta=dict(self.parse_address(seg), structural=True, house=has_house)))
            taken.append((st, en))

        for rx in (RX_LOC_L, RX_LOC_D):
            for m in rx.finditer(text):
                if self._root_ok(m.group(2)) and not self.lex.is_place(m.group(2).split()[0]):
                    add(m.start(1) if m.group(1) else m.start(2), m.end(), bool(m.group(1)))
        for m in RX_LMK_L.finditer(text):
            root = m.group(1) or m.group(2)
            if root and not self._root_ok(root):
                continue
            g = 1 if m.group(1) else (2 if m.group(2) else 0)
            add(m.start(g) if g else m.start(), m.end(), False)
        for m in RX_LMK_D.finditer(text):
            if m.group(1) and not self._root_ok(m.group(1)):
                continue
            add(m.start(), m.end(), False)
        # Hinglish/Hindi house-number cue ("Ghar no 56", "मकान नं. 12") and head-first localities ("Tola Pashchim")
        for m in RX_HOUSE_CUE.finditer(text):
            add(m.start(), m.end(), True)
        for m in RX_HEAD_FIRST.finditer(text):
            if self._root_ok(m.group(1)):
                add(m.start(), m.end(), False)
        # a structural chain "<house>, <locality>, <Village>." also takes the final village word (a known
        # district / city stays: it is released at district level anyway)
        for sp in list(out):
            t = RX_ADDR_TAIL.match(text, sp.end)
            if t and sp.meta.get("structural") and self._root_ok(t.group(1)) and not self.lex.is_place(t.group(1)) and not any(
                    t.start(1) < b and a < t.end(1) for a, b in taken):
                out.append(Span(t.start(1), t.end(1), "ADDRESS", t.group(1),
                                meta=dict(self.parse_address(t.group(1)), structural=True, house=False)))
                taken.append((t.start(1), t.end(1)))
        # a PIN right after a place word or after a structural address on the same line
        for m in RX_PIN_AFTER_PLACE.finditer(text.translate(DIGITS)):
            line_start = text.rfind("\n", 0, m.start()) + 1
            near_addr = any(line_start <= a and b <= m.start(2) and m.start(2) - b < 60 for a, b in taken)
            if self.lex.is_place(m.group(1)) or near_addr:
                out.append(Span(m.start(2), m.end(2), "PIN", digits_only(m.group(2))))
        return out

    def _cueless_names(self, text):
        """Names with no adjacent cue, found from the clause frame: the first word of a clause whose
        predicate is a person verb (aaye/गए/भर्ती/बताया ...), or an honorific state (`ab theek hain`),
        an English object of a speech verb (`spoke to X`, `informed X`) or subject of `was admitted`.
        Only unknown, name-shaped words (not stop/common/medical/place/surname) qualify."""
        out = []
        lex = self.lex

        def latin_ok(w, p):
            return self.plausible_name_tok(w) and not lex.is_surname_only(w) and w.lower() not in _ROLE_NOUNS and self.name_score(w) >= p

        def lower_ok(w, p):
            return (len(w) >= 4 and w.islower() and not lex.is_common(w) and not lex.is_medical(w) and not lex.is_stop(w)
                    and not lex.is_place(w) and fold(w) not in lex.names_f and self.name_score(w) >= p)

        # "<Name> (47/M), <address>": the age/sex bracket right after a line-initial name-shaped phrase
        for m in _CL_DEMO.finditer(text):
            toks = list(re.finditer(r"\S+", m.group(1)))
            good = []
            for t in toks:
                w = t.group(0)
                if has_devanagari(w):
                    good.append(self._tok_ok_deva(w, True) and not lex.is_place(w))
                else:
                    good.append(self.plausible_name_tok(w) and w.lower() not in _ROLE_NOUNS and self.name_score(w) >= 0.15
                                or (len(toks) > 1 and lex.is_surname_only(w)))
            if toks and all(good):
                out.append(Span(m.start(1), m.end(1), "NAME", m.group(1), role="ctx"))
        for m in _CL_EN_LEFT.finditer(text):
            t = _CL_TOK.match(text, m.end())
            if t and latin_ok(t.group(0), self.cl_min_p) and not _RX_ORG_NEXT.match(text, t.end()):
                out.append(Span(t.start(), t.end(), "NAME", t.group(0), role="ctx", meta={"weak": True}))
        for cm in _CL_CLAUSE.finditer(text):
            toks = [(cm.start() + t.start(), cm.start() + t.end(), t.group(0)) for t in _CL_TOK.finditer(cm.group(0))]
            k = 0
            while k < len(toks) and toks[k][2].lower() in _CL_TEMPORAL:
                k += 1
            if k >= len(toks) - 1:
                continue
            st, en, w = toks[k]
            if w.lower() in _ROLE_NOUNS or w in _ROLE_NOUNS:
                continue
            rest = [t[2].lower() for t in toks[k + 1:k + 9]]
            verb = any(r in _CL_PERSON_VERB for r in rest)
            state = bool(_CL_HONOR_STATE.match(text, en))
            subj = bool(_CL_EN_SUBJ.match(text, en))
            nxt = toks[k + 1][2].lower()
            post = None
            if nxt in ("ne", "ने"):
                post = "erg"
            elif nxt in ("ko", "को") and k + 2 < len(toks) and (lex.is_medical(toks[k + 2][2]) or toks[k + 2][2] in lex.stop_hindi
                                                                 or lex.is_common(toks[k + 2][2])) and _CL_EXPERIENCER.match(text, toks[k + 1][1]):
                post = "dat"
            elif nxt in ("ki", "की", "ka", "का") and k + 2 < len(toks) and toks[k + 2][2].lower() in _CL_COND:
                post = "gen"
            if post:
                if has_devanagari(w):
                    ok = self.plausible_name_tok_deva(w, self.cl_min_p)
                elif w[:1].isupper():
                    ok = latin_ok(w, self.cl_min_p)
                else:
                    ok = lower_ok(w, 0.3)
                if ok:
                    out.append(Span(st, en, "NAME", w, role="ctx", meta={"weak": True}))
                continue
            if nxt in ("ko", "को", "se", "से", "ka", "ki", "ke", "का", "की", "के", "mein", "में"):
                continue   # other postposition frames belong to the other rules
            if not (verb or state or subj):
                continue
            if verb and not state and (w.endswith("े") or re.search(r"[^e]e$", w)):
                continue   # masculine plural nouns ("झटके आए", "jhatke aaye") take the plural verb too
            if has_devanagari(w):
                ok = self.plausible_name_tok_deva(w, self.cl_min_p if verb or state else 1.1)
            elif w[:1].isupper():
                ok = latin_ok(w, self.cl_min_p)
            else:
                ok = (verb or state) and lower_ok(w, 0.6)
            if ok:
                out.append(Span(st, en, "NAME", w, role="ctx", meta={"weak": True}))
        return out

    def name_score(self, tok):
        """Probability that an unknown word is a person name (synthetic-trained char n-gram scorer)."""
        if has_devanagari(tok):
            tok = devanagari_to_latin(tok)
            if re.search(r"[bcdfghjklmnpqrstvwxyz]{2}$", tok) and not re.search(r"(?:sh|ch|th|dh|bh|kh|gh|ph|jh|nt|nd|nk|ng|nj|mb|mp|rk|st)$", tok):
                tok += "a"   # restore the final schwa of a conjunct ("-endr" -> "-endra")
        return self.scorer.prob(norm_latin(tok))

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
        if lex.is_place(t):
            return False
        if tl in _PLACE_WORDS or tl in lex.surnames:
            return tl in lex.surnames and not lex.is_surname_only(t)
        return True

    def plausible_name_tok_deva(self, tok, min_p=0.5):
        """An unknown Devanagari word that can still be a given name (used only next to a name cue)."""
        t = tok.rstrip(".।")
        if len(t) < 2 or not has_devanagari(t) or t in self.lex.stop_hindi or t in self.lex.honor_pre or t in self.lex.honor_suf:
            return False
        lat = devanagari_to_latin(t)
        f = fold(lat)
        lex = self.lex
        if not f or lat in lex.medical or f in lex.medical or lat in lex.common or lat in lex.stop_latin or lex.is_place(t):
            return False
        if self.is_surname_only_any(t) or t in _ROLE_NOUNS:
            return False
        sk = skeleton(lat)
        if len(sk) >= 4 and sk in lex.loan_sk:
            return False   # English loanword in Devanagari ("सैंपल" ~ sample, "रिपोर्ट" ~ report)
        return min_p <= 0.0 or self.name_score(lat) >= min_p

    def is_surname_only_any(self, tok):
        """Family name / gendered suffix in either script (Devanagari via transliteration)."""
        if has_devanagari(tok):
            return self.lex.is_surname_only(devanagari_to_latin(tok.rstrip(".।")))
        return self.lex.is_surname_only(tok)

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
            ok = False  # sentence end "Kelvansh. Kelvansh"
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

    def _extend_given_left(self, text, chosen):
        """"शोभा [रावत]", "Shobha [Rawat]": a known given name standing right before a detected name joins it,
        even when on its own it is an ordinary word (e.g. a given name that is also a dictionary word) that the detector would not take."""
        for sp in chosen:   # "T Rawat MRN": an all-caps record label is never part of a name
            if sp.kind == "NAME":
                m = _RX_NAME_TAIL_LABEL.search(sp.text)
                if m and m.start() > 0:
                    sp.end = sp.start + m.start()
                    sp.text = text[sp.start:sp.end]
        occ = sorted((sp.start, sp.end) for sp in chosen)
        for sp in chosen:
            if sp.kind != "NAME" or sp.start < 2:
                continue
            m = re.search(r"(?<![\w\u0900-\u097F.])([A-Z][a-z]{2,}|[\u0900-\u097F]{2,}) $", text[max(0, sp.start - 25):sp.start])
            if not m:
                continue
            w = m.group(1)
            st = sp.start - len(m.group(0))
            if any(a < sp.start and st < b for a, b in occ if (a, b) != (sp.start, sp.end)):
                continue
            f = fold(devanagari_to_latin(w)) if has_devanagari(w) else fold(w)
            if f not in self.lex.names_f or (self.lex.is_stop(w) and not has_devanagari(w)) or w.lower() in self.lex.honor_pre or (not has_devanagari(w) and self.lex.is_place(w)):
                continue
            if has_devanagari(w) and w in _DEVA_FUNC:
                continue
            sp.start, sp.text = st, text[st:sp.end]
        return chosen

    def _pre_pin_places(self, text, spans, pins):
        """A short run of capitalised place segments right before a PIN with no address cue
        ("... . Kalyanpur, Jhansi 284001", "near bus stand Sector 9 Ajmer 305001")."""
        out = []
        lex = self.lex
        for p in pins:
            if any(sp.kind == "ADDRESS" and sp.start < p.start and p.start - sp.end <= 6 for sp in spans):
                continue
            left = text[max(0, p.start - 90):p.start]
            cut = max(left.rfind("\n"), left.rfind(". "), left.rfind("; "), left.rfind("("), left.rfind(":"), left.rfind("|"))
            seg0 = left[cut + 1:] if cut >= 0 else left
            seg = re.sub(r"(?i)[\s,:\-–]*(?:pin\s?code|pincode|pin|पिन)?[\s,:\-–]*$", "", seg0)
            lead = len(seg) - len(seg.lstrip())
            seg = seg.strip()
            if not seg:
                continue
            toks = re.findall(r"[^\s,]+", seg)
            if not 1 <= len(toks) <= 7:
                continue
            # a lower-case locative lead-in ("near metro station", "stays at") stays outside the span
            k = len(toks)
            while k > 0 and (toks[k - 1][0].isupper() or re.fullmatch(r"[\d/\-]+[A-Za-z]?\.?", toks[k - 1]) or has_devanagari(toks[k - 1])) and \
                    not (lex.is_stop(toks[k - 1].strip(".")) and toks[k - 1].lower() not in _ADDR_NOUNS):
                k -= 1
            body = toks[k:]
            if not body or len(body) > 6 or all(t[0].isdigit() for t in body):
                continue
            if any(lex.is_common(t.strip(".")) and not lex.is_place(t.strip(".")) and t.lower().strip(".") not in _ADDR_NOUNS
                   for t in body if not t[0].isdigit() and not has_devanagari(t)):
                continue
            if not (any(lex.is_place(t.strip(".")) for t in body) or "," in seg):
                continue
            st = p.start - len(seg0) + lead + seg.find(body[0])
            en = st + len(seg) - seg.find(body[0])
            sub = text[st:en]
            out.append(Span(st, en, "ADDRESS", sub, meta=self.parse_address(sub, None)))
        return out

    _RX_WRAP = re.compile(r"(?<=\d)-[ \t]*\r?\n[ \t]*(?=\d)|(?<=@)[ \t]*\r?\n[ \t]*(?=[A-Za-z0-9])|(?<=[A-Za-z0-9._%+-])[ \t]*\r?\n[ \t]*(?=@)")

    def _wrapped_ids(self, norm):
        """Identifiers broken across a line end ("99112-" / "33445", "name@" / "mail.org"): found on a
        joined shadow copy and mapped back to the original offsets."""
        if "\n" not in norm or not self._RX_WRAP.search(norm):
            return []
        keep, pos, parts = [], 0, []
        for m in self._RX_WRAP.finditer(norm):
            parts.append(norm[pos:m.start()])
            keep.extend(range(pos, m.start()))
            if m.group(0).startswith("-"):
                parts.append("-")
                keep.append(m.start())
            pos = m.end()
        parts.append(norm[pos:])
        keep.extend(range(pos, len(norm)))
        sh = "".join(parts)
        out = []

        def back(a, b):
            return keep[a], keep[b - 1] + 1
        for rx, kind, f in ((RX_PHONE, "PHONE", norm_phone), (RX_EMAIL, "EMAIL", str.lower), (RX_AADHAAR, "AADHAAR", digits_only),
                            (RX_ABHA, "ABHA", digits_only)):
            for m in rx.finditer(sh):
                a, b = back(m.start(), m.end())
                if "\n" in norm[a:b]:
                    out.append(Span(a, b, kind, f(m.group(0))))
        return out

    def _spelled_ages(self, norm, field_hint=None):
        """Ages written in words ("seventy two years", "pachpan saal ke", "पचपन साल की", "छियासठ वर्षीया",
        "turns forty") and bare "(46 yrs)" / "41 saal ka". A number word is an age only in an age frame:
        an age cue before it, an adjectival unit (वर्षीय), unit + ka/ki/ke/old, a bracket, or the whole
        value; "do saal se", "five years back" stay (durations)."""
        from . import numwords
        out = []
        for rx in _AGE_DIGIT_EXTRA:
            for m in rx.finditer(norm):
                v = int(m.group(1))
                if 0 <= v <= 120:
                    out.append(Span(m.start(1), m.end(1), "AGE", str(v), meta={"age": v}))
        whole_age = field_hint is not None and re.search(r"(?i)age|umar|उम्र|आयु", str(field_hint))
        for a, b, v in numwords.find(norm):
            w = norm[a:b]
            if w.isascii() and w.lower() not in _HINGLISH_SMALL and " " not in w and "-" not in w and \
                    re.fullmatch(r"[A-Za-z]+", w) and (self.lex.is_stop(w) or self.lex.is_common(w)) and \
                    w.lower() not in numwords._EN_UNITS and w.lower() not in numwords._EN_TENS:
                continue
            if not 0 < v <= 120:
                continue
            before = norm[max(0, a - 30):a]
            um = _AGE_WORD_UNIT.match(norm, b)
            ok = bool(_AGE_WORD_CUE.search(before))
            if not ok and um:
                rest = norm[um.end():um.end() + 30]
                unit = um.group(1)
                ok = (unit in ("वर्षीय", "वर्षीया") or bool(_AGE_WORD_SUFFIX.match(rest))
                      or (before.rstrip().endswith("(") and rest.lstrip()[:1] in (")", ",", "/"))
                      or (not norm[:a].strip() and not rest.strip()) or bool(whole_age))
            if ok:
                out.append(Span(a, b, "AGE", w, meta={"age": v}))
        return out

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
            if (w.isupper() and " " not in w) or re.search(r"(?i)pan|पैन", norm[max(0, m.start() - 15):m.start()]):
                spans.append(Span(m.start(), m.end(), "PAN", re.sub(r"\s", "", w).upper()))
        for m in RX_PAN_LABELLED.finditer(norm):
            spans.append(Span(m.start(1), m.end(1), "PAN", re.sub(r"\s", "", m.group(1)).upper(), meta={"labelled": True}))
        for m in RX_GOV_LABELLED.finditer(norm):
            spans.append(Span(m.start(1), m.end(1), "ID", m.group(1).upper(), meta={"labelled": True}))
        for m in RX_PHONE.finditer(norm):
            spans.append(Span(m.start(), m.end(), "PHONE", norm_phone(m.group(0))))
        spans.extend(self._wrapped_ids(norm))
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
            kind = "DOB" if re.search(r"dob|d\.o\.b|birth|\bborn\b|janm|janam|paida|जन्म|पैदा", ctx) else "DATE"
            spans.append(Span(a, b, kind, norm[a:b], meta={"date": d, "fmt": f}))
        from . import events
        for a, b, kind, d in events.find(norm):
            ctx = norm[max(0, a - 25):a].lower()
            if kind == "DATE" and re.search(r"dob|d\.o\.b|birth|\bborn\b|janm|janam|paida|जन्म|पैदा", ctx):
                kind = "DOB"
            fmt = (lambda nd: "%02d %s %04d" % (nd.day, nd.strftime("%b"), nd.year)) if d else None
            spans.append(Span(a, b, kind, norm[a:b], meta={"date": d, "fmt": fmt, "event": True}))
        # ages
        for rx in RX_AGE:
            for m in rx.finditer(norm):
                age = int(m.group(1))
                st = m.start(1)
                if 0 <= age <= 120:
                    spans.append(Span(st, m.end(1), "AGE", str(age), meta={"age": age}))
                elif rx is RX_AGE[0]:   # "Age: 150": implausible -> masked, never a fake band
                    spans.append(Span(st, m.end(1), "AGE", str(age), meta={"age": None}))
        spans.extend(self._spelled_ages(norm, field_hint))
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
            if _RX_WEAK_ADDR_TRIG.fullmatch(m.group(1).strip().rstrip(".")) and not m.group(0)[len(m.group(1)):].strip(" \t") and \
                    _RX_ADDR_FUNC_NEXT.match(seg):
                continue   # "gaon mein sab ...", "village records", "गांव में": the word, not an address label
            en = st + len(seg)
            hn = _RX_HOUSE_NO_BEFORE.search(text[max(0, m.start() - 14):m.start()]) if _RX_WEAK_ADDR_TRIG.fullmatch(m.group(1).strip().rstrip(".")) else None
            if hn:   # "12 Gali 7 ...": the house number written before the lane / village word
                st = m.start() - (len(text[max(0, m.start() - 14):m.start()]) - hn.start(1))
                seg = text[st:en]
            spans.append(Span(st, en, "ADDRESS", seg, meta=self.parse_address(seg, m.group(1))))
        spans.extend(self._structural_addresses(text, spans))
        # an address that runs into its PIN keeps everything before the PIN (PIN outranks ADDRESS in resolve)
        pins = [p for p in spans if p.kind == "PIN"]
        spans.extend(self._pre_pin_places(text, spans, pins))
        for sp in spans:
            if sp.kind != "ADDRESS":
                continue
            for p in pins:
                if sp.start < p.start < sp.end:
                    seg = re.sub(r"(?i)[\s,:\-–]*(?:pin\s?code|pincode|pin|postal\s?code|पिन(?:\s?कोड)?)?[\s,:\-–]*$", "", text[sp.start:p.start])
                    if len(seg.strip()) >= 2:
                        sp.end = sp.start + len(seg)
                        sp.text = seg
                        sp.meta = self.parse_address(seg, sp.meta.get("trigger") if isinstance(sp.meta, dict) else None)
                    break
        # C. label:value lines
        spans.extend(self._label_values(text, norm))
        # D. names
        spans.extend(self._names(text))
        spans.extend(self._cueless_names(text))
        if _NF_MODE:
            spans = [sp for sp in spans if not self._weak_negative_context(text, sp)]
            base = self.resolve(spans)
            spans.extend(self.name_finder.find(text, existing_spans=base, dyn_names=self.dyn, span_cls=Span))
            if _NF_MODE >= 2:
                mid = self.resolve(spans)
                prop = NamePropagator(lex=self.lex)
                prop.register_spans(text, mid)
                spans.extend(prop.propagate(text, existing_spans=mid, span_cls=Span))
            spans.extend(self._coordinated_names(text, self.resolve(spans)))
            spans = [sp for sp in spans if not self._weak_negative_context(text, sp)]
        return self._extend_given_left(text, self.resolve(spans))

    _RX_COORD = re.compile(r"[ \t]*(?:,[ \t]*)?(?:and|aur|और|&)[ \t]+([A-Z][a-z]{2,}|[\u0900-\u097F]{2,})(?![\w\u0900-\u097F])")

    def _coordinated_names(self, text, spans):
        """`... to <NAME> and Y` / `<NAME> aur Y`: a name-shaped word coordinated with a detected person
        name is a person too (found by the honey-PII self-check: the second conjunct otherwise depends
        on how name-like the word happens to look)."""
        out = []
        taken = [(s.start, s.end) for s in spans]
        for s in spans:
            if s.kind not in ("NAME", "RELATIVE"):
                continue
            m = self._RX_COORD.match(text, s.end)
            if not m:
                continue
            w, st, en = m.group(1), m.start(1), m.end(1)
            if any(a < en and st < b for a, b in taken):
                continue
            if has_devanagari(w):
                ok = self._tok_ok_deva(w, True) and not self.lex.is_place(w) and self.plausible_name_tok_deva(w, 0.15)
            else:
                ok = (self.plausible_name_tok(w) and not self.lex.is_surname_only(w) and w.lower() not in _ROLE_NOUNS
                      and self.name_score(w) >= 0.15 and not _RX_ORG_NEXT.match(text, en))
            if ok:
                out.append(Span(st, en, "NAME", w, role="ctx", meta={"weak": True}))
        return out

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
        # relation nouns  "wife Gonavati", "husband: Kelvansh"
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
        # Hinglish postposition "Kelvansh ki wife"
        for m in RX_REL_POST.finditer(text):
            b = self._collect_backward(text, toks, m.start(), 2)
            if b:
                rel, psex = REL_POST.get(m.group(1).lower(), REL_POST.get(m.group(1), ("G", None)))
                out.append(Span(b[0], b[1], "NAME", text[b[0]:b[1]], role="relative", meta={"rel": rel, "psex": psex}))
            # "Pimmo ki maa Gonavati": a capitalised word right after the kin noun names the subject
            fw = re.match(r"\s*[:\-]?\s*", text[m.end():])
            r = self._collect_forward(text, toks, m.end() + fw.end(), 2, True)
            if r and all(self.plausible_name_tok(t) or self.tok_ok(t, False) for t in text[r[0]:r[1]].split()):
                out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="cued"))
        # aliases / nicknames: "also known as Bittu", "urf Pappu", "pet name Gudiya", "log Tinku bulate hain"
        for m in RX_ALIAS_PRE.finditer(text):
            fw = re.match(r"\s*(?:is|was|hai|:|-|=)?\s*[\"'‘“]?", text[m.end():])
            r = self._collect_forward(text, toks, m.end() + fw.end(), 2, True)
            if r and (text[r[0]].isupper() or has_devanagari(text[r[0]])) and \
                    all(self.plausible_name_tok(t) or self.tok_ok(t, False) for t in text[r[0]:r[1]].split()):
                out.append(Span(r[0], r[1], "NAME", text[r[0]:r[1]], role="cued", meta={"alias": True}))
        for m in RX_ALIAS_POST.finditer(text):
            b = self._collect_backward(text, toks, m.start(), 1)
            if b and (text[b[0]].isupper() or has_devanagari(text[b[0]])) and \
                    all(self.plausible_name_tok(t) or self.tok_ok(t, False) for t in text[b[0]:b[1]].split()):
                out.append(Span(b[0], b[1], "NAME", text[b[0]:b[1]], role="cued", meta={"alias": True}))
        for m in RX_HINGLISH_ARG.finditer(text):
            w = m.group(1)
            known = self.tok_ok(w, False) and not lex.is_common(w)
            if not known and (lex.is_place(w) or self.name_score(w) < _WEAK_CUE_MIN_P):
                continue   # "Limcee ki dose", "Gonda ko refer": a weak cue needs a name-shaped word
            if self.plausible_name_tok(w) or known:
                st = m.start(1)
                # "Gonavati Devi ne", "Kelvansh Durovan ko": take one more capitalised token on the left
                pv = re.search(r"([A-Z][a-z]{2,}) $", text[max(0, st - 30):st])
                if pv and (self.plausible_name_tok(pv.group(1)) or self.tok_ok(pv.group(1), False)):
                    st -= len(pv.group(0))
                out.append(Span(st, m.end(1), "NAME", text[st:m.end(1)], role="cued", meta={"weak": True}))
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
        # honorific suffixes  "Thivaresh sahab", "Gonavati didi", "थिवरेश जी"
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
            if r and re.search(r"relative|attendant|care\s?giver|caretaker|informant|bystander|emergency\s+contact|next\s+of\s+kin|kin|rishtedar|"
                               r"रिश्तेदार|परिजन|तीमारदार", before):
                w = text[r[0]:r[1]]
                if has_devanagari(w) or w[0].isupper():
                    out.append(Span(r[0], r[1], "NAME", w, role="relative", meta={"rel": "G", "psex": None}))
                continue
            if r:
                w = text[r[0]:r[1]]
                if not has_devanagari(w) and w[0].islower() and re.match(r"\s+(?:hua|hue|hui|hai|hain|tha|the|thi|kiya|kiye|gaya|gayi|gaye|hoga|hogi)\b", text[r[1]:r[1] + 8]):
                    continue   # "Mareez bharti hua": a lower-case predicate word, not a name
                w0 = w.split()[0]
                lower_ok = (fold(w0) in self.dyn or fold(w0) in lex.names_f) and not (
                    lex.is_common(w0) or lex.is_stop(w0) or lex.is_medical(w0.lower()))  # "Patient seen": "seen" folds like "Sen"
                if has_devanagari(w) or w[0].isupper() or lower_ok:
                    out.append(Span(r[0], r[1], "NAME", w, role="patient"))
        # context cues that need no gazetteer: "witnessed by X Y", "X Y (attendant, ...)", "X Y, mob 98..."
        for m in RX_BY_CUE.finditer(text):
            r = self._collect_forward(text, toks, m.end(), 3, True)
            if r:
                w = text[r[0]:r[1]]
                if all(t[:1].isupper() or has_devanagari(t) for t in w.split()):
                    out.append(Span(r[0], r[1], "NAME", w, role="cued"))
        for m in RX_BEFORE_REL.finditer(text):  # "Gonavati, W/o Kelvansh": the subject of a relation marker is a person
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
            sur_seed = False
            if i > 0 and self._joinable(text, toks[i - 1], toks[i]) and self.is_surname_only_any(wc) \
                    and (has_devanagari(wc) or wc[:1].isupper()):
                pw0 = toks[i - 1][2]
                sur_seed = self.plausible_name_tok_deva(pw0, 0.0) if has_devanagari(wc) else self.plausible_name_tok(pw0)
            if sur_seed:
                seed = True
            elif has_devanagari(wc):
                seed = self._tok_ok_deva(wc, False)
            else:
                f = fold(wc)
                if (wc.lower() in lex.names or f in self.dyn) and len(wc) >= 3:
                    if (wc[0].isupper() or allcaps) and self._tok_ok_latin(wc, False):
                        seed = True
                    elif wc.lower() in lex.ambiguous and wc[0].isupper() and _AMBIG_CTX.match(text, toks[i][1]):
                        seed = True  # "Gonavati ji", "Gonavati, W/o ..." (ambiguous words count only with person context)
                    elif f in self.dyn and not lex.is_stop(wc) and not lex.is_medical(wc) and len(wc) >= 4:
                        seed = True
            if not seed:
                i += 1
                continue
            # extend backward over initials / capitalised tokens
            j = i
            # a family name / gendered suffix ("... Devi", "... Yadav", "... Bano") is preceded by the
            # given name even when that given name is in no gazetteer: accept up to two plausible tokens
            # a known given name also pulls in ONE adjacent unknown word that strongly looks like a name
            # ("<unknown> Prasad"); Devanagari works the same way through transliteration
            if self.is_surname_only_any(wc):
                lead, lead_p = 2, 0.0
            else:
                lead, lead_p = 1, 0.8
            while j - 1 >= 0 and self._joinable(text, toks[j - 1], toks[j]):
                pw = toks[j - 1][2]
                if re.fullmatch(r"[A-Z]\.?|(?:[A-Z]\.){2,3}", pw) or (self.tok_ok(pw, False)):
                    j -= 1
                elif lead and has_devanagari(pw) and has_devanagari(wc) and self.plausible_name_tok_deva(pw, lead_p):
                    j -= 1
                    lead -= 1
                elif lead and not has_devanagari(pw) and self.plausible_name_tok(pw) and (lead_p == 0.0 or self.name_score(pw) >= lead_p):
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
                        or (nw[:1].isupper() and lex.is_surname_only(nw))   # "Pramithika Kumari", "Zevrina Begum"
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
        role_rank = {"patient": 5, "relative": 4, "cued": 3, "ctx": 2, "morph": 2, "prop": 1, "gaz": 1, None: 0}
        lab = [s for s in spans if s.meta.get("labelled")]
        if lab:   # an explicitly labelled identifier ("PAN ...", "Passport no. ...") outranks the code-shaped MED guard
            spans = [s for s in spans if not (s.kind == "MED" and any(s.start < l.end and l.start < s.end for l in lab))]
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
