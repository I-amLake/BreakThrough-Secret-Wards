"""Shared record model, evidence extraction and rendering used by every format handler."""
import base64
import datetime as dt
import re

from .dates import find_dates, parse_full
from .detect import DIGITS, PII_KINDS, Detector, Span, digits_only, norm_phone, sex_hints
from .translit import has_devanagari
from .linkage import Profile
from .privacy import age_band, pin3
from .translit import fold, name_tokens

ID_KINDS = {"AADHAAR", "ABHA", "PAN", "MRN", "INSURANCE", "ID", "EMAIL"}
PLACEHOLDER = {"PHONE": "[PHONE]", "AADHAAR": "[AADHAAR]", "ABHA": "[ABHA]", "PAN": "[PAN]", "EMAIL": "[EMAIL]",
               "MRN": "[ID]", "INSURANCE": "[INSURANCE-ID]", "ID": "[ID]"}
STRUCT_PII = {"name", "first_name", "last_name", "relative", "phone", "email", "aadhaar", "abha", "pan", "mrn",
              "insurance", "address", "village", "tehsil", "dob", "contact"}
ICD_RX = re.compile(r"\b([A-TV-Z]\d{2}(?:\.\d{1,2})?)\b")


class Unit:
    """One patient-bearing record (CSV row, JSON record, FHIR bundle, text document)."""
    __slots__ = ("loc", "out", "prof", "qi", "dates", "names_raw", "psn", "shift", "level", "rid", "key",
                 "patient_keys", "age", "ref_date", "dx", "los", "band", "arange",
                 "_name_parts", "_sex_hint", "_adm", "_dis")

    def __init__(self, loc, hospital):
        self.loc = loc
        self.out = None
        self.prof = Profile(-1, hospital)
        self.qi = {}
        self.dates = []
        self.names_raw = []
        self.psn = None
        self.shift = 0
        self.level = 0
        self.rid = -1
        self.key = None
        self.patient_keys = set()
        self.age = None
        self.ref_date = None
        self.dx = set()
        self.los = None
        self.band = None      # patient-level released age band (same string for every visit)
        self.arange = None    # (min, max) true age of the patient across visits


class Ctx:
    """Rendering context for one unit (or for file-level metadata)."""

    def __init__(self, eng, unit=None, shift=0, order=None, year=None):
        self.eng = eng
        self.unit = unit
        self.psn = unit.psn if unit else None
        self.shift = unit.shift if unit else shift
        self.level = unit.level if unit else 0
        self.order = order
        self.year = year
        self.patient_keys = unit.patient_keys if unit else set()
        self.age = unit.age if unit else None
        self.band = unit.band if unit else None
        self.arange = unit.arange if unit else None
        self.qi = unit.qi if unit else {}
        self.psn_used = False


# ------------------------------------------------------------------ helpers
def norm_id(v):
    return re.sub(r"[^A-Z0-9@._]", "", str(v).upper().translate(DIGITS))


def parse_age(v):
    """Age in years from a cell/phrase, or None when absent or implausible (negative, > 120, 4+ digits)."""
    t = str(v).translate(DIGITS)
    m = re.search(r"(?<![\d.])(-\s*)?(\d{1,3})(?![\d.])", t)
    if m and m.group(1) and not re.search(r"\d\s*$", t[:m.start()]):
        return None          # "-2": a negative age is a data error, never a real age
    if m and int(m.group(2)) <= 120:
        txt = str(v).lower()
        if re.search(r"\d\s*(m|mo|mon|months?|महीने|माह)\b", txt) and not re.search(r"/\s*m\b", txt):
            return 0
        return int(m.group(2))
    return None


def has_digits(v):
    return bool(re.search(r"\d", str(v).translate(DIGITS)))


def parse_sex(v):
    t = str(v).strip().lower()
    if re.search(r"(^|[^a-z])(f|female|woman|girl)([^a-z]|$)|महिला|स्त्री|लड़की", t):
        return "F"
    if re.search(r"(^|[^a-z])(m|male|man|boy)([^a-z]|$)|पुरुष|लड़का", t):
        return "M"
    return None


def name_keys(name):
    """Folded name tokens without honorifics/kinship suffixes ("Gonavati ji" -> ['gonavati'])."""
    from .lexicon import get_lexicon
    from .translit import _TOKEN_RE
    lex = get_lexicon()
    out = []
    for raw in _TOKEN_RE.findall(name or ""):
        r = raw.rstrip(".").lower()
        if r in lex.honor_suf or r in lex.honor_pre:
            continue
        out.extend(t for t in name_tokens(raw) if t)
    return out


def rel_from_value(value, header_rel=("G", None)):
    """'S/O TEVAN ORLIKAR' -> (('P','M'), 'TEVAN ORLIKAR')."""
    from .detect import REL_LETTER, REL_WORD
    v = str(value).strip()
    m = re.match(r"^\s*([SDWHFMCB])\s?[/.\\]\s?[oO]\.?\s*[:\-]?\s*(.*)$", v)
    if m:
        return REL_LETTER[m.group(1).upper()], m.group(2)
    for w, r in REL_WORD.items():
        if v.lower().startswith(w + " "):
            return r, v[len(w):].strip()
    return header_rel, v


def add_name(unit, name, eng):
    toks = name_keys(name)
    toks = [t for t in toks if t not in ("kumar", "devi", "ji", "md", "bai", "begum", "bano", "kumari", "singh", "kaur")
            or len(toks) <= 2]
    if toks:
        unit.prof.names.append(tuple(toks))
        unit.patient_keys.update(t for t in toks if len(t) > 1)
        unit.names_raw.append(name)


def apply_dob(unit, d):
    if d:
        unit.prof.dobs.add(d.isoformat())
        unit.prof.byears.append(d.year)


def set_age(unit, age):
    if age is not None and unit.age is None:
        unit.age = age


def finalize_unit(unit, default_year=None):
    """Derive birth-year estimates, LOS and QI after all fields were seen."""
    ref = unit.ref_date or (min(unit.dates) if unit.dates else None)
    if ref is None and unit.age is not None and default_year and not unit.prof.byears:
        # undated record (e.g. a register without dates): the input's dominant year, with a wider window
        unit.prof.byears.extend([default_year - unit.age + k for k in (1, 0, -1, -2)])
    if unit.age is None and unit.prof.dobs and ref:
        b = dt.date.fromisoformat(sorted(unit.prof.dobs)[0])
        unit.age = ref.year - b.year - ((ref.month, ref.day) < (b.month, b.day))
    if unit.age is not None and ref and not unit.prof.byears:
        unit.prof.byears.extend([ref.year - unit.age, ref.year - unit.age - 1])
    unit.qi["age"] = unit.age
    unit.qi["sex"] = unit.prof.sex
    unit.qi["dx"] = sorted(unit.dx)
    unit.qi["los"] = unit.los


# ------------------------------------------------------------------ evidence from detected spans
def spans_evidence(unit, text, spans, patient_mode=False):
    """Add identifiers / relatives / dates from free-text spans to the unit."""
    for sp in spans:
        k = sp.kind
        if k == "PHONE" and len(sp.text) == 10:
            unit.prof.phones.add(sp.text)
        elif k in ("AADHAAR",) and len(sp.text) == 12:
            unit.prof.ids["AADHAAR"].add(sp.text)
        elif k == "ABHA":
            unit.prof.ids["ABHA"].add(norm_id(sp.text))
        elif k == "PAN":
            unit.prof.ids["PAN"].add(sp.text)
        elif k == "EMAIL":
            unit.prof.ids["EMAIL"].add(sp.text.lower())
        elif k in ("MRN", "ID", "INSURANCE"):
            v = norm_id(sp.text)
            if sum(c.isdigit() for c in v) >= 4:
                unit.prof.ids["INSURANCE" if k == "INSURANCE" else "MRN"].add(v)
        elif k == "DOB" and sp.meta.get("date"):
            apply_dob(unit, sp.meta["date"])
        elif k == "DATE" and sp.meta.get("date"):
            unit.dates.append(sp.meta["date"])
        elif k == "AGE" and patient_mode:
            set_age(unit, sp.meta.get("age"))
        elif k == "PIN":
            unit.prof.pins.add(sp.text)
            unit.qi.setdefault("pin", sp.text)
        elif k == "ADDRESS":
            m = sp.meta
            if m.get("pin"):
                unit.prof.pins.add(m["pin"])
                unit.qi.setdefault("pin", m["pin"])
            if m.get("district"):
                unit.prof.districts.add(fold(m["district"]))
                unit.qi.setdefault("district", m["district"])
            if m.get("state"):
                unit.qi.setdefault("state", m["state"])
            if m.get("village"):
                unit.prof.villages.add(" ".join(name_tokens(m["village"])))
        elif k == "NAME" and sp.role == "relative":
            toks = tuple(name_keys(sp.text))
            if toks:
                unit.prof.rels.append((sp.meta.get("rel", "G"), toks))
    for d in ICD_RX.findall(text):
        unit.dx.add(d)


# ------------------------------------------------------------------ rendering
def address_repl(meta, ctx, eng):
    pol = eng.policy
    parts = []
    if meta.get("district") and ctx.level <= pol["district_level"]:
        parts.append("Distt. " + meta["district"])
    if meta.get("state"):
        parts.append(meta["state"])
    if meta.get("pin") and ctx.level <= pol["pin3_level"]:
        parts.append(pin3(meta["pin"]))
    return "[ADDRESS]" + ((", " + ", ".join(parts)) if parts else "")


def band_for(ctx, age):
    """Ages of this unit's patient share ONE band across all visits (so pooled visits cannot be
    intersected into a narrow range); any other age (a relative's) gets its own band."""
    if age is None:
        return None
    if ctx.band and ctx.arange and ctx.arange[0] <= age <= ctx.arange[1]:
        return ctx.band
    return age_band(age, ctx.level, ctx.eng.policy)


def is_patient_span(sp, ctx):
    if sp.role == "relative":
        return False
    if sp.meta.get("is_patient") is not None:
        return sp.meta["is_patient"]
    toks = [t for t in name_keys(sp.text) if len(t) > 1]
    return bool(toks) and any(t in ctx.patient_keys for t in toks)


_WD_FULL = (r"monday|tuesday|wednesday|thursday|friday|saturday|sunday"
            r"|somv[aw]a?r|mangalv[aw]a?r|budhv[aw]a?r|guruv[aw]a?r|brihaspativ[aw]a?r|shukrav[aw]a?r|shaniv[aw]a?r|raviv[aw]a?r"
            r"|सोमवार|मंगलवार|बुधवार|गुरुवार|बृहस्पतिवार|शुक्रवार|शनिवार|रविवार|इतवार")
_RX_WD_FULL = re.compile(r"(?i)(?<![\w\u0900-\u097F])(?:%s)(?![\w\u0900-\u097F])" % _WD_FULL)
_RX_DATEISH = re.compile(r"\d{1,4}[-/.]\d{1,2}[-/.]\d{2,4}|(?i:\b\d{1,2}\s*(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b)")
_RX_WD_ABBR_NEAR = re.compile(r"(?i)\b(?:mon|tue|tues|wed|thu|thur|thurs|fri|sat|sun)\b\.?,?(?=\s{0,2}\d{1,4}[-/.])")


def weekday_scrub(text):
    """A weekday next to a shifted date tells an attacker the TRUE weekday (shift mod 7) and narrows
    "admitted on a Tuesday" candidates. On lines that carry a date, weekday names become [DAY]."""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if _RX_DATEISH.search(ln):
            ln = _RX_WD_FULL.sub("[DAY]", ln)
            lines[i] = _RX_WD_ABBR_NEAR.sub("[DAY] ", ln).replace("[DAY]  ", "[DAY] ")
    return "\n".join(lines)


def render(text, spans, ctx):
    """Apply replacements. Returns (new_text, n_identifiers, entity_counter_dict)."""
    eng = ctx.eng
    repl = eng.policy["repl"]
    out, last, n = [], 0, 0
    ents = {}
    for sp in spans:
        k = sp.kind
        rep = None
        if k in ("MED", "DOCTOR"):
            continue
        if k == "NAME":
            if is_patient_span(sp, ctx):
                rep = ctx.psn if ctx.psn else repl["unlinked_patient"]
                if ctx.psn:
                    ctx.psn_used = True
                ents["PATIENT_NAME"] = ents.get("PATIENT_NAME", 0) + 1
            elif sp.role == "relative":
                rep = repl["relative"]
                ents["RELATIVE_NAME"] = ents.get("RELATIVE_NAME", 0) + 1
            else:
                rep = repl["other_name"]
                ents["PERSON_NAME"] = ents.get("PERSON_NAME", 0) + 1
        elif k in PLACEHOLDER:
            rep = PLACEHOLDER[k]
            ents[k] = ents.get(k, 0) + 1
        elif k == "DATE":
            d = sp.meta.get("date")
            try:
                rep = sp.meta["fmt"](d + dt.timedelta(days=ctx.shift))
            except Exception:
                rep = "[DATE]"
        elif k == "DOB":
            age = ctx.age
            rep = ("[DOB: age %s]" % band_for(ctx, age)) if age is not None else "[DOB]"
            ents["DOB"] = ents.get("DOB", 0) + 1
        elif k == "AGE":
            rep = band_for(ctx, sp.meta.get("age")) or "[AGE]"
        elif k == "PIN":
            rep = pin3(sp.text) if ctx.level <= eng.policy["pin3_level"] else "[PIN]"
            ents["PIN"] = ents.get("PIN", 0) + 1
        elif k == "ADDRESS":
            rep = address_repl(sp.meta, ctx, eng)
            ents["ADDRESS"] = ents.get("ADDRESS", 0) + 1
        if rep is None:
            continue
        out.append(text[last:sp.start])
        out.append(rep)
        last = sp.end
        if k in PII_KINDS:
            n += 1
    out.append(text[last:])
    new = "".join(out)
    if ctx.shift and any(sp.kind in ("DATE", "DOB") for sp in spans):
        new = weekday_scrub(new)
    return new, n, ents


_RX_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_RX_LOCAL_TOK = re.compile(r"[A-Z][a-z]{2,}|[A-Z]{3,}|[\u0900-\u097F]{2,}")


_RX_OPAQUE = re.compile(r"(?=(?:[^0-9]*[0-9]){3})(?=(?:[^A-Za-z]*[A-Za-z]){3})[A-Za-z0-9]{10,}")


def opaque_id(tok):
    """A random-looking code of letters and digits (SYNTH013421f8d057, a1b2c3d4e5): >= 10 chars,
    >= 3 digits and >= 3 letters, letters and digits interleaved (not a word with a number tail)."""
    if not _RX_OPAQUE.fullmatch(tok):
        return False
    return len(re.findall(r"[A-Za-z]+|[0-9]+", tok)) >= 4


_RX_B64_SHORT = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{11,}={0,2}(?![A-Za-z0-9+/=])")


def _decode_b64_any(t):
    if len(t) % 4:
        return None
    try:
        dec = base64.b64decode(t, validate=True).decode("utf-8")
    except Exception:
        return None
    if len(dec) < 4 or not re.search(r"[A-Za-z0-9\u0900-\u097F]", dec):
        return None
    if sum(1 for ch in dec if ch.isprintable() or ch in "\n\r\t") < len(dec):
        return None
    return dec


def b64_tokens_sub(text, ctx, field_hint=None):
    """Short base64 tokens inside a value or note ("OTg3NjUwMTIzNA==" is a phone number): decode,
    sanitise the decoded text, re-wrap only if something was removed. Returns (text, n)."""
    if not re.search(r"[A-Za-z0-9+/]{11,}", text):
        return text, 0
    nb = [0]

    def sub(m):
        dec = _decode_b64_any(m.group(0))
        if dec is None:
            return m.group(0)
        new, n, _ = render_value(dec, ctx, field_hint)
        if new == dec:
            return m.group(0)
        nb[0] += max(n, 1)
        return base64.b64encode(new.encode("utf-8")).decode("ascii")
    return _RX_B64_SHORT.sub(sub, text), nb[0]


def _decode_b64_text(text):
    t = text.strip()
    if len(t) % 4 or not _RX_B64.fullmatch(t):
        return None
    try:
        raw = base64.b64decode(t, validate=True)
        dec = raw.decode("utf-8")
    except Exception:
        return None
    if not dec or sum(1 for ch in dec if ch.isprintable() or ch in "\n\r\t") < 0.95 * len(dec):
        return None
    return dec


def local_name_spans(text, ctx, spans):
    """Tokens of THIS record's own patient name inside its free text ("Gonavati ka BP ..."): the record
    context makes even ambiguous tokens personal. Only names learnt from the same record are used."""
    keys = ctx.patient_keys
    if not keys:
        return []
    lex = ctx.eng.detector.lex
    taken = [(sp.start, sp.end) for sp in spans]
    out = []
    for m in _RX_LOCAL_TOK.finditer(text):
        w = m.group(0)
        if any(a < m.end() and m.start() < b for a, b in taken):
            continue
        if not has_devanagari(w) and (lex.is_stop(w) or (lex.is_medical(w.lower()) and w.lower() not in lex.ambiguous)):
            continue
        k = name_keys(w)
        if k and all(x in keys for x in k) and len(k[0]) >= 3:
            out.append(Span(m.start(), m.end(), "NAME", w, role="patient", meta={"is_patient": True}))
    return out


def render_value(value, ctx, field_hint=None):
    text = str(value)
    if not text.strip():
        return text, 0, {}
    if len(text) >= 40:
        dec = _decode_b64_text(text)
        if dec is not None:  # base64-wrapped text (scanned forms, attachments): sanitise inside, re-wrap
            new, n, ents = render_value(dec, ctx, field_hint)
            return base64.b64encode(new.encode("utf-8")).decode("ascii"), n, ents
    whole_b64 = bool(_RX_B64_SHORT.fullmatch(text.strip()))
    t2, nb = b64_tokens_sub(text, ctx, field_hint)
    if t2 != text:
        if whole_b64:
            return t2, nb, {}
        text = t2
    spans = ctx.eng.detector.detect(text, field_hint, ctx.order, ctx.year)
    if ctx.unit is not None:
        extra = local_name_spans(text, ctx, spans)
        if extra:
            spans = sorted(spans + extra, key=lambda sp: (sp.start, sp.end))
    if not spans:
        return text, 0, {}
    return render(text, spans, ctx)


# ------------------------------------------------------------------ path / filename sanitising
_SEG = re.compile(r"[A-Za-z\u0900-\u097F]+|\d+|[^A-Za-z\u0900-\u097F\d]+")


_RX_GLUED_ID = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]{2,6}(?:-[A-Z]{2,6})*-?\d{2,}(?:-\d{2,})*(?![0-9])")


def sanitize_token_string(s, eng, psn=None):
    """Sanitise identifiers glued with _ - . / \\ (file names, export paths). Returns (new, changed)."""
    det = eng.detector
    changed = False
    spaced = re.sub(r"[_\-]+", " ", s)
    spans = [sp for sp in det.detect(spaced) if sp.kind in PII_KINDS
             and not re.fullmatch(r"\d{1,5}", spaced[sp.start:sp.end].strip())]  # short sequence numbers stay
    pieces = list(s)
    # alphanumeric record ids glued with '-' (e.g. IPD-2025-01234, ADM001234, ABC-IPD-01234)
    for m in _RX_GLUED_ID.finditer(s):
        if len(re.sub(r"\D", "", m.group(0))) >= 5:
            for i in range(m.start(), m.end()):
                pieces[i] = "\x00"
            changed = True
    for m in re.finditer(r"[A-Za-z0-9]{8,}", s):
        if opaque_id(m.group(0)):
            for i in range(m.start(), m.end()):
                pieces[i] = "\x00"
            changed = True
    for sp in spans:
        for i in range(sp.start, sp.end):
            if spaced[i] not in " ":
                pieces[i] = "\x00"
        changed = True
    out = "".join(pieces)
    # long digit runs (IDs / phones) and learnt name tokens even in lowercase
    def digit_sub(m):
        return "\x00" if len(m.group(0)) >= 6 else m.group(0)
    out2 = re.sub(r"\d{6,}", digit_sub, out)
    changed = changed or out2 != out
    out = out2
    toks = re.findall(r"[A-Za-z]+|[\u0900-\u097F]+", out)
    for t in toks:
        f = fold(t)
        if len(t) >= 3 and (f in eng.dyn or t.lower() in eng.detector.lex.names) and not eng.detector.lex.is_medical(t) \
                and not eng.detector.lex.is_stop(t) and t.lower() not in eng.safe_file_tokens:
            out = re.sub(r"(?<![A-Za-z])" + re.escape(t) + r"(?![A-Za-z])", "\x00", out)
            changed = True
    out = re.sub("\x00+", psn if psn else "redacted", out)
    return out, changed
