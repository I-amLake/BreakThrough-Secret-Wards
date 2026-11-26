"""Holiday / national-day date anchors ("Republic Day 2025", "born on Independence Day 1962",
"Holi ke baad", "दिवाली से"). A fixed-date day with a year is a real date: it is shifted like any other
date. A movable festival with a year, or any holiday in a temporal frame next to a visit, still dates
the event (season + year): it becomes [DATE] / [EVENT]. A closed public list, no NLP."""
import datetime as dt
import re

FIXED = {  # (month, day)
    "republic day": (1, 26), "gantantra diwas": (1, 26), "ganatantra diwas": (1, 26), "गणतंत्र दिवस": (1, 26),
    "independence day": (8, 15), "swatantrata diwas": (8, 15), "swatantra diwas": (8, 15), "स्वतंत्रता दिवस": (8, 15),
    "pandrah august": (8, 15), "पंद्रह अगस्त": (8, 15), "chhabbis january": (1, 26), "छब्बीस जनवरी": (1, 26),
    "gandhi jayanti": (10, 2), "गांधी जयंती": (10, 2), "christmas": (12, 25), "christmas day": (12, 25), "क्रिसमस": (12, 25),
    "new year's day": (1, 1), "new years day": (1, 1), "new year day": (1, 1), "children's day": (11, 14),
    "childrens day": (11, 14), "bal diwas": (11, 14), "बाल दिवस": (11, 14), "ambedkar jayanti": (4, 14),
    "teachers' day": (9, 5), "teachers day": (9, 5), "shikshak diwas": (9, 5), "valentine's day": (2, 14),
    "women's day": (3, 8), "womens day": (3, 8), "labour day": (5, 1), "may day": (5, 1),
}
MOVABLE = [
    "holi", "होली", "diwali", "deepawali", "dipawali", "deepavali", "दिवाली", "दीवाली", "दीपावली", "dussehra", "dussera",
    "dasara", "dashahra", "vijayadashami", "दशहरा", "eid", "id ul fitr", "eid ul fitr", "eid-ul-fitr", "eid al fitr", "eid ul adha",
    "eid-ul-adha", "bakrid", "bakri eid", "ईद", "बकरीद", "navratri", "navaratri", "नवरात्रि", "नवरात्र", "raksha bandhan",
    "rakshabandhan", "rakhi", "रक्षाबंधन", "राखी", "janmashtami", "जन्माष्टमी", "makar sankranti", "sankranti", "मकर संक्रांति",
    "lohri", "लोहड़ी", "pongal", "पोंगल", "onam", "ओणम", "chhath", "chhath puja", "छठ", "ganesh chaturthi", "गणेश चतुर्थी",
    "durga puja", "दुर्गा पूजा", "guru nanak jayanti", "gurpurab", "karva chauth", "karwa chauth", "करवा चौथ", "ram navami",
    "राम नवमी", "mahashivratri", "shivratri", "शिवरात्रि", "muharram", "मुहर्रम", "good friday", "easter", "baisakhi",
    "vaisakhi", "बैसाखी", "bihu", "teej", "तीज", "dhanteras", "धनतेरस", "bhai dooj", "भाई दूज", "ugadi", "gudi padwa",
    "kumbh", "कुंभ",
]
_ALL = sorted(set(FIXED) | set(MOVABLE), key=len, reverse=True)


def _alt(w):
    e = re.escape(w).replace(r"\ ", r"[\s\-]+").replace("'", "'?")
    return e


_NAME = r"(?:" + "|".join(_alt(w) for w in _ALL) + r")"
_B, _E = r"(?<![\w\u0900-\u097F])", r"(?![\w\u0900-\u097F])"
# holiday + year ("Holi 2024", "Republic Day, 2025", "Diwali of 2023", "होली 2024")
RX_WITH_YEAR = re.compile(r"(?i)" + _B + r"(" + _NAME + r")" + _E + r"(?:[\s,]+(?:of\s+|in\s+|सन\s+)?|\s*')((?:19|20)\d{2}|\d{2})(?!\d)")
# holiday in a temporal frame, no year: "since Holi", "after Diwali", "Holi ke baad", "दिवाली से"
_PRE = r"(?:on|since|after|before|around|during|till|until|from|post|pre|near|over|ahead\s+of|day\s+after|day\s+before)"
_POST = (r"(?:ke\s+baad|ke\s+pehle|ke\s+pahle|se\s+pehle|se|par|pe|tak|ke\s+aas\s*paas|ke\s+din|wale\s+din|ke\s+time|ke\s+samay|"
         r"के\s+बाद|से\s+पहले|के\s+पहले|से|पर|तक|को|के\s+आसपास|के\s+दिन|वाले\s+दिन)")
RX_FRAME_PRE = re.compile(r"(?i)" + _B + _PRE + r"\s+(?:the\s+)?(" + _NAME + r")" + _E)
RX_FRAME_POST = re.compile(r"(?i)" + _B + r"(" + _NAME + r")\s+" + _POST + _E)


def _key(s):
    return re.sub(r"[\s\-]+", " ", s.lower()).replace("'", "'")


def find(text):
    """[(start, end, kind, date)] kind: 'DATE' (date may be None for movable) or 'EVENT'."""
    out, taken = [], []
    for m in RX_WITH_YEAR.finditer(text):
        name = m.group(1)
        if name[:1].isascii() and not name[:1].isupper():
            continue   # "holi" / "id 2024" in lower case is not a holiday mention
        ys = m.group(2)
        y = int(ys) + (0 if len(ys) == 4 else (2000 if int(ys) <= 40 else 1900))
        k = _key(name)
        md = next((v for kk, v in FIXED.items() if _key(kk) == k), None)
        d = None
        if md:
            try:
                d = dt.date(y, *md)
            except ValueError:
                d = None
        out.append((m.start(), m.end(), "DATE", d))
        taken.append((m.start(), m.end()))
    for rx in (RX_FRAME_PRE, RX_FRAME_POST):
        for m in rx.finditer(text):
            a, b = m.start(1), m.end(1)
            name = m.group(1)
            if name[:1].isascii() and not name[:1].isupper():
                continue
            if _key(name) in ("eid", "id") and not name[:1].isupper():
                continue
            if any(x < b and a < y for x, y in taken):
                continue
            out.append((a, b, "EVENT", None))
            taken.append((a, b))
    return sorted(out)
