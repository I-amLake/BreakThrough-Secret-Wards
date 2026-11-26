"""Spelled-out numbers 1-120 in English, Devanagari Hindi and Hinglish (for ages such as
"forty one years", "baasath saal ke", "बासठ साल की", "अड़सठ वर्षीया")."""
import re
import unicodedata

from .translit import devanagari_to_latin, fold

_HI = ("एक दो तीन चार पांच|पाँच छह|छः|छे सात आठ नौ दस ग्यारह बारह तेरह चौदह पंद्रह|पन्द्रह सोलह सत्रह अठारह उन्नीस बीस "
       "इक्कीस बाईस तेईस चौबीस पच्चीस छब्बीस सत्ताईस अट्ठाईस|अठ्ठाईस उनतीस तीस इकतीस बत्तीस तैंतीस चौंतीस पैंतीस छत्तीस "
       "सैंतीस अड़तीस उनतालीस चालीस इकतालीस बयालीस तैंतालीस चवालीस|चौवालीस पैंतालीस छियालीस सैंतालीस अड़तालीस उनचास पचास "
       "इक्यावन बावन तिरपन चौवन पचपन छप्पन सत्तावन अट्ठावन उनसठ साठ इकसठ बासठ तिरसठ चौंसठ पैंसठ छियासठ सड़सठ|सरसठ "
       "अड़सठ उनहत्तर सत्तर इकहत्तर बहत्तर तिहत्तर चौहत्तर पचहत्तर छिहत्तर सतहत्तर अठहत्तर उन्यासी|उनासी अस्सी इक्यासी "
       "बयासी तिरासी चौरासी पचासी छियासी सत्तासी अट्ठासी नवासी नब्बे इक्यानवे बानवे तिरानवे चौरानवे पंचानवे छियानवे "
       "सत्तानवे अट्ठानवे निन्यानवे सौ").split()
_EN_UNITS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve",
             "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"]
_EN_TENS = {"twenty": 20, "thirty": 30, "forty": 40, "fourty": 40, "fifty": 50, "sixty": 60, "seventy": 70,
            "eighty": 80, "ninety": 90}

DEVA = {}
for _i, _w in enumerate(_HI):
    for _v in _w.split("|"):
        DEVA[unicodedata.normalize("NFC", _v)] = _i + 1
LATIN_FOLD = {}
for _w, _n in DEVA.items():
    f = fold(devanagari_to_latin(_w))
    if len(f) >= 3:
        LATIN_FOLD.setdefault(f, _n)
        if "ड़" in _w or "\u095c" in _w:
            LATIN_FOLD.setdefault(f.replace("r", "d"), _n)   # "adsath" for अड़सठ
for _w, _n in (("ek", 1), ("do", 2), ("teen", 3), ("char", 4), ("chaar", 4), ("paanch", 5), ("panch", 5), ("chhe", 6),
               ("chheh", 6), ("saat", 7), ("aath", 8), ("nau", 9), ("das", 10), ("sau", 100)):
    LATIN_FOLD.setdefault(fold(_w), _n)

_EN_RX = re.compile(r"(?i)(?<![A-Za-z])(?:(" + "|".join(_EN_TENS) + r")(?:[\s-]+(" + "|".join(_EN_UNITS[1:10]) + r"))?"
                    r"|(" + "|".join(sorted(_EN_UNITS[1:], key=len, reverse=True)) + r")|(hundred))(?![A-Za-z])")
_DEVA_RX = re.compile(r"(?<![\u0900-\u097F])(" + "|".join(sorted(map(re.escape, DEVA), key=len, reverse=True)) + r")(?![\u0900-\u097F])")
_LAT_TOK = re.compile(r"(?<![A-Za-z])[A-Za-z]{2,12}(?![A-Za-z])")


def find(text):
    """[(start, end, value)] for spelled numbers. text should be NFC-normalised."""
    out = []
    for m in _EN_RX.finditer(text):
        if m.group(1):
            v = _EN_TENS[m.group(1).lower()] + (_EN_UNITS.index(m.group(2).lower()) if m.group(2) else 0)
        elif m.group(3):
            v = _EN_UNITS.index(m.group(3).lower())
        else:
            v = 100
        out.append((m.start(), m.end(), v))
    for m in _DEVA_RX.finditer(text):
        out.append((m.start(), m.end(), DEVA[m.group(1)]))
    taken = [(a, b) for a, b, _ in out]
    for m in _LAT_TOK.finditer(text):
        if any(a < m.end() and m.start() < b for a, b in taken):
            continue
        v = LATIN_FOLD.get(fold(m.group(0).lower()))
        if v:
            out.append((m.start(), m.end(), v))
    return sorted(out)
