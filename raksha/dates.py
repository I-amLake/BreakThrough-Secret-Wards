"""Find, parse and shift dates while preserving their original textual format."""
import datetime as dt
import re

MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
          "november", "december"]
_MON_ABBR = {m[:3]: i + 1 for i, m in enumerate(MONTHS)}
_MON_ABBR["sept"] = 9
HINDI_MONTHS = {"जनवरी": 1, "फ़रवरी": 2, "फरवरी": 2, "मार्च": 3, "अप्रैल": 4, "अप्रेल": 4, "मई": 5, "जून": 6,
                "जुलाई": 7, "अगस्त": 8, "सितंबर": 9, "सितम्बर": 9, "अक्टूबर": 10, "अक्तूबर": 10, "नवंबर": 11,
                "नवम्बर": 11, "दिसंबर": 12, "दिसम्बर": 12}
_HM_REV = {}
for _k, _v in HINDI_MONTHS.items():
    _HM_REV.setdefault(_v, _k)

_MON_RX = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_HMON_RX = "(?:" + "|".join(sorted(HINDI_MONTHS, key=len, reverse=True)) + ")"
_TIME = r"(?:[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:\s?[AaPp][Mm])?(?:Z|[+-]\d{2}:?\d{2})?)?"

RX_ISO = re.compile(r"(?<![\d/.-])(\d{4})([-/.])(\d{1,2})\2(\d{1,2})" + _TIME + r"(?![\d])")
RX_DMY = re.compile(r"(?<![\d/.-])(?<!\d:)(\d{1,2})([-/.])(\d{1,2})\2(\d{4}|\d{2})" + _TIME + r"(?![\d/.-]\d)(?!\d)")
RX_DMONY = re.compile(r"(?<![\w])(\d{1,2})(st|nd|rd|th)?([\s\-/.,]+)(" + _MON_RX + r")\.?([\s\-/.,]+)(\d{4}|'?\d{2})(?![\w])", re.I)
RX_MONDY = re.compile(r"(?<![\w])(" + _MON_RX + r")\.?(\s+)(\d{1,2})(st|nd|rd|th)?(,?\s+)(\d{4})(?![\w])", re.I)
RX_DMON_NOYEAR = re.compile(r"(?<![\w])(\d{1,2})(st|nd|rd|th)?(\s+)(" + _MON_RX + r")(?![\w])(?!\.?[\s\-/.,]+'?\d{2,4})", re.I)
RX_HINDI = re.compile(r"(?<![\d])(\d{1,2})(\s+)(" + _HMON_RX + r")(\s+)(\d{4})(?![\d])")
RX_FHIR_FULL = re.compile(r"^(\d{4})(-(\d{2})(-(\d{2})(T[\d:.]+(Z|[+-]\d{2}:\d{2})?)?)?)?$")


_RX_DATE_LABEL = re.compile(r"(?i)(?:\b(?:date|dated|dt|doa|dod|dob|dos|d\.o\.[abds]\.?|admi(?:tted|ssion)|discharged?|visit(?:ed)?|"
                            r"seen|on|born|birth|reported|collected|sampled?)|दिनांक|तारीख|तिथि|जन्म)\W{0,4}$")


def _valid(y, m, d):
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def _year(ys):
    ys = ys.lstrip("'")
    y = int(ys)
    if len(ys) == 2:
        y += 2000 if y <= 40 else 1900
    return y


def find_dates(text, order=None, year=None):
    """Return [(start, end, date, formatter)] where formatter(newdate) -> string.

    order: "dmy" or "mdy" for ambiguous numeric dates (default day-first, Indian convention).
    year: assumed year for year-less dates such as "5 September".
    """
    out = []
    taken = []

    def free(a, b):
        return all(b <= s or a >= e for s, e in taken)

    for m in RX_ISO.finditer(text):
        y, sep, mo, d = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        date = _valid(y, int(mo), int(d))
        if not date or not (1900 <= y <= 2100):
            continue
        tail = m.group(0)[len(m.group(1)) + len(mo) + len(d) + 2:]
        wm, wd = len(mo), len(d)
        fmt = (lambda nd, sep=sep, wm=wm, wd=wd, tail=tail: "%04d%s%0*d%s%0*d%s" % (nd.year, sep, wm, nd.month, sep, wd, nd.day, tail))
        out.append((m.start(), m.end(), date, fmt))
        taken.append((m.start(), m.end()))
    for m in RX_DMY.finditer(text):
        if not free(m.start(), m.end()):
            continue
        a, sep, b, ys = m.group(1), m.group(2), m.group(3), m.group(4)
        if sep == "." and len(ys) == 2 and not _RX_DATE_LABEL.search(text[max(0, m.start() - 24):m.start()]):
            continue  # too ambiguous with decimals / versions, unless a date label stands right before it
        y = _year(ys)
        ia, ib = int(a), int(b)
        order_used = "dmy"
        if ia <= 12 and ib <= 12 and order == "mdy":
            date = _valid(y, ia, ib)
            order_used = "mdy"
        elif ia <= 31 and ib <= 12:
            date = _valid(y, ib, ia)
        elif ia <= 12 and ib <= 31:
            date = _valid(y, ia, ib)
            order_used = "mdy"
        else:
            date = None
        if not date or not (1900 <= y <= 2100):
            continue
        tail = m.group(0)[len(a) + len(b) + len(ys) + 2:]
        wa, wb, wy = len(a), len(b), len(ys)

        def fmt(nd, sep=sep, wa=wa, wb=wb, wy=wy, order=order_used, tail=tail):
            first, second = (nd.day, nd.month) if order == "dmy" else (nd.month, nd.day)
            yy = "%04d" % nd.year if wy == 4 else "%02d" % (nd.year % 100)
            return "%0*d%s%0*d%s%s%s" % (wa, first, sep, wb, second, sep, yy, tail)
        out.append((m.start(), m.end(), date, fmt))
        taken.append((m.start(), m.end()))
    for m in RX_DMONY.finditer(text):
        if not free(m.start(), m.end()):
            continue
        d, suf, s1, mon, s2, ys = m.groups()
        mi = _MON_ABBR.get(mon.lower()[:4] if mon.lower().startswith("sept") else mon.lower()[:3])
        y = _year(ys)
        date = _valid(y, mi, int(d)) if mi else None
        if not date:
            continue
        full = len(mon) > 4 or mon.lower() in ("may", "june", "july")
        dot = m.group(0)[m.group(0).find(mon) + len(mon):].startswith(".")

        def fmt(nd, d=d, suf=suf, s1=s1, mon=mon, s2=s2, ys=ys, full=full, dot=dot):
            name = MONTHS[nd.month - 1] if full else MONTHS[nd.month - 1][:3]
            name = name.upper() if mon.isupper() else (name.capitalize() if mon[0].isupper() else name)
            ns = _suffix(nd.day) if suf else ""
            yy = ("'" if ys.startswith("'") else "") + ("%04d" % nd.year if len(ys.lstrip("'")) == 4 else "%02d" % (nd.year % 100))
            return "%0*d%s%s%s%s%s%s" % (len(d), nd.day, ns, s1, name, "." if dot else "", s2, yy)
        out.append((m.start(), m.end(), date, fmt))
        taken.append((m.start(), m.end()))
    for m in RX_MONDY.finditer(text):
        if not free(m.start(), m.end()):
            continue
        mon, s1, d, suf, s2, ys = m.groups()
        mi = _MON_ABBR.get(mon.lower()[:3])
        date = _valid(int(ys), mi, int(d)) if mi else None
        if not date:
            continue
        full = len(mon) > 4 or mon.lower() in ("may", "june", "july")

        def fmt(nd, mon=mon, s1=s1, d=d, suf=suf, s2=s2, full=full):
            name = MONTHS[nd.month - 1] if full else MONTHS[nd.month - 1][:3]
            name = name.upper() if mon.isupper() else (name.capitalize() if mon[0].isupper() else name)
            return "%s%s%d%s%s%04d" % (name, s1, nd.day, _suffix(nd.day) if suf else "", s2, nd.year)
        out.append((m.start(), m.end(), date, fmt))
        taken.append((m.start(), m.end()))
    for m in RX_HINDI.finditer(text):
        if not free(m.start(), m.end()):
            continue
        d, s1, mon, s2, ys = m.groups()
        date = _valid(int(ys), HINDI_MONTHS[mon], int(d))
        if not date:
            continue
        out.append((m.start(), m.end(), date,
                    lambda nd, s1=s1, s2=s2: "%d%s%s%s%04d" % (nd.day, s1, _HM_REV[nd.month], s2, nd.year)))
        taken.append((m.start(), m.end()))
    if year:
        for m in RX_DMON_NOYEAR.finditer(text):
            if not free(m.start(), m.end()):
                continue
            d, suf, s1, mon = m.groups()
            mi = _MON_ABBR.get(mon.lower()[:3])
            date = _valid(year, mi, int(d)) if mi else None
            if not date:
                continue
            full = len(mon) > 4 or mon.lower() in ("may", "june", "july")

            def fmt(nd, d=d, suf=suf, s1=s1, mon=mon, full=full):
                name = MONTHS[nd.month - 1] if full else MONTHS[nd.month - 1][:3]
                name = name.upper() if mon.isupper() else (name.capitalize() if mon[0].isupper() else name)
                return "%d%s%s%s" % (nd.day, _suffix(nd.day) if suf else "", s1, name)
            out.append((m.start(), m.end(), date, fmt))
            taken.append((m.start(), m.end()))
    out.sort(key=lambda x: x[0])
    return out


def numeric_order_votes(text):
    """(+1 per unambiguous day-first date, -1 per month-first) for order inference."""
    dmy = mdy = 0
    for m in RX_DMY.finditer(text):
        a, b = int(m.group(1)), int(m.group(3))
        if a > 12 and b <= 12:
            dmy += 1
        elif b > 12 and a <= 12:
            mdy += 1
    return dmy, mdy


def _suffix(n):
    if 10 <= n % 100 <= 20:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


def parse_full(value, order=None):
    """If the whole string is a single date, return (date, formatter)."""
    s = str(value)
    st = s.strip()
    if not st:
        return None
    m = RX_FHIR_FULL.match(st)
    if m and (m.group(3) is None):  # bare year "1979" or "1979-" -> treat as year only
        if m.group(2) is None and len(st) == 4:
            return None
    found = find_dates(s, order)
    if len(found) == 1:
        a, b, d, f = found[0]
        if s[:a].strip() == "" and s[b:].strip() == "":
            pre, post = s[:a], s[b:]
            return d, (lambda nd, f=f, pre=pre, post=post: pre + f(nd) + post)
    # FHIR partial dates YYYY-MM
    m2 = re.match(r"^(\s*)(\d{4})-(\d{2})(\s*)$", s)
    if m2:
        d = _valid(int(m2.group(2)), int(m2.group(3)), 15)
        if d:
            return d, (lambda nd, a=m2.group(1), b=m2.group(4): "%s%04d-%02d%s" % (a, nd.year, nd.month, b))
    return None


def shift_text_dates(text, days, order=None, year=None):
    found = find_dates(text, order, year)
    if not found:
        return text, 0
    out, last = [], 0
    for a, b, d, f in found:
        out.append(text[last:a])
        try:
            out.append(f(d + dt.timedelta(days=days)))
        except (OverflowError, ValueError):
            out.append("[DATE]")
        last = b
    out.append(text[last:])
    return "".join(out), len(found)
