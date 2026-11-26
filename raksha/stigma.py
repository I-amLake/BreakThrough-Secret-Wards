"""Stigma Shield: extra protection for patients with stigmatised conditions.

Indian law singles out HIV status (HIV/AIDS Act 2017), mental illness (Mental Healthcare Act 2017),
termination of pregnancy (MTP Act), child sexual abuse (POCSO) and sex determination (PCPNDT) for
confidentiality; TB and leprosy carry heavy social stigma. For a record that mentions such a condition
(English, Devanagari or Hinglish, from raksha/data/stigma_terms.txt), the pipeline:
  * releases a wider age band and, if the patient is still in a class smaller than k, only the state;
  * removes the name/place of the specific condition-revealing facility ("ART Centre, <hospital>")
    while keeping the diagnosis text and codes;
  * detects names with a lower threshold (residual names are the worst leak for these patients);
  * runs a honey-PII self-check on the patient's free-text files: every detected identifier is swapped
    for an invented one (checksum-valid fake Aadhaar, same-format phone, synthesised name), the file is
    sanitised again in memory, and if any planted value survives the file is re-sanitised in the
    strictest mode, or quarantined if it still leaks.
Only counts leave this module (report.json "stigma_shield").
"""
import hmac
import hashlib
import os
import re

from .translit import has_devanagari

_HERE = os.path.dirname(os.path.abspath(__file__))
_CACHE = {}


def _load():
    if "rx" in _CACHE:
        return _CACHE["rx"]
    pats = []
    with open(os.path.join(_HERE, "data", "stigma_terms.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            cat, terms = parts[0], [t for t in parts[1:] if t]
            ci, cs = [], []
            for t in terms:
                esc = re.escape(t).replace(r"\ ", r"[\s\-]+")
                (cs if (t.isupper() and t.isascii()) else ci).append(esc)
            b, e = r"(?<![\w\u0900-\u097F])", r"(?![\w\u0900-\u097F])"
            alts = []
            if ci:
                alts.append("(?i:" + "|".join(sorted(ci, key=len, reverse=True)) + ")")
            if cs:
                alts.append("(?:" + "|".join(sorted(cs, key=len, reverse=True)) + ")")
            # "HIV+" ends in a non-word char: allow it to end at whitespace/punctuation too
            pats.append((cat, re.compile(b + "(?:" + "|".join(alts) + ")" + r"(?:(?<=\+)|" + e + ")")))
    _CACHE["rx"] = pats
    return pats


_NEG = re.compile(r"(?i)(?:\b(?:no|not|non|negative|neg|ruled\s+out|r/o|denies|nahi|nahin)\b[\s:\-]*(?:[\w/.]+[\s:\-]+){0,2}$)")
_NEG_AFTER = re.compile(r"(?i)^[\s:\-]*(?:(?:1\s*(?:&|and|/|,)\s*2|I\s*/\s*II|test|status|screening|serology|antibod(?:y|ies)|elisa|rapid|card)[\s:\-]*){0,3}(?:NR\b|negative|neg\b|non[\s\-]?reactive|ruled\s+out|nahi|nahin|नहीं|नेगेटिव)")


def categories(text):
    """Sorted stigma categories mentioned (and not negated: "HIV negative", "no h/o TB") in text."""
    if not text:
        return ()
    found = set()
    for cat, rx in _load():
        if cat in found:
            continue
        for m in rx.finditer(text):
            before = text[max(0, m.start() - 30):m.start()]
            after = text[m.end():m.end() + 20]
            if _NEG.search(before) or _NEG_AFTER.match(after):
                continue
            found.add(cat)
            break
    return tuple(sorted(found))


# "ART Centre, Govt Medical College Rampur" / "ICTC at City Hospital": the facility's own name reveals
# where the patient receives stigmatised care; the service type stays (it is clinical context)
RX_FACILITY = re.compile(
    r"(?i:\b(?:ART|ICTC|PPTCT|DOTS|DMC|OST|Nasha[\s\-]?Mukti|De-?addiction|Psychiatr\w*|Mental\s+Health|MTP|Leprosy|Suraksha)"
    r"\s+(?:Centre|Center|Clinic|Kendra|Unit|Ward|OPD|Hospital)s?\b)"
    r"(\s*(?:,|-|–|at|of|in|,\s*at)\s*)((?:[A-Z][A-Za-z.&']+[ \t]*){1,6})")


def mask_structured_facility(ctx):
    """Apply the linked patient's shield to this cell, including unlinked flagged records."""
    return bool(ctx.unit and ctx.unit.stigma_pat and ctx.eng.policy["stigma"]["enabled"])


def strip_facilities(text):
    """Returns (text, n) with condition-revealing facility names replaced by [FACILITY]."""
    n = [0]

    def sub(m):
        n[0] += 1
        tail = m.group(2)
        trail = tail[len(tail.rstrip()):]
        return m.group(0)[:m.start(2) - m.start(0)] + "[FACILITY]" + trail
    return RX_FACILITY.sub(sub, text), n[0]


# ------------------------------------------------------------------ honey PII
_C, _V = "bdfghjklmnprstvz", ("a", "e", "i", "o", "u", "aa", "ee", "ai")
_DC, _DV = "कगजडतदनपबमरलवसह", ("ा", "ि", "ी", "ु", "े", "ो", "")
_VD = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
       (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
       (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
       (9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
_VP = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
       (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
       (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8))
_VINV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_digit(num):
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VD[c][_VP[(i + 1) % 8][int(ch)]]
    return str(_VINV[c])


class Honey:
    """Deterministic invented identifiers, keyed by HMAC(key, file hash): never real, never logged."""

    def __init__(self, key, salt):
        self.key, self.salt, self.i = key, salt, 0

    def _bytes(self, n=32):
        self.i += 1
        return hmac.new(self.key, ("%s|%d" % (self.salt, self.i)).encode(), hashlib.sha256).digest()[:n]

    _ON = ("k", "kh", "g", "ch", "j", "t", "d", "dh", "n", "p", "b", "bh", "m", "y", "r", "l", "v", "sh", "s",
           "h", "pr", "tr", "shr")
    _VW = ("a", "aa", "i", "ee", "u", "e", "ai", "o")
    _CO = ("", "", "", "n", "m", "r", "sh", "l", "t", "nd", "nt", "j", "v")
    _DON = "कखगचजटडतदधनपबभमयरलवशसह"
    _DVW = ("", "ा", "ि", "ी", "ु", "े", "ै", "ो")
    _DCO = ("", "", "", "न", "म", "र", "ल", "श", "त", "ंद", "ंत", "ज", "व")

    def _word(self, b, deva):
        syl = 2 + b[0] % 2
        out = []
        for j in range(syl):
            x = b[1 + 3 * j:4 + 3 * j]
            if deva:
                out.append(self._DON[x[0] % len(self._DON)] + self._DVW[x[1] % len(self._DVW)])
            else:
                out.append(self._ON[x[0] % len(self._ON)] + self._VW[x[1] % len(self._VW)])
        if deva:
            out.append(self._DCO[b[12] % len(self._DCO)])
        else:
            out.append(self._CO[b[12] % len(self._CO)])
        return "".join(out)

    def name_like(self, orig, score=None):
        """An invented name with the same word count, script and case as orig. With score (a function
        word -> name-likeness, negative for lexicon words) each word is drawn until it is at least as
        name-like as the word it replaces, so the check tests the detector's context, not luck."""
        words = []
        for w in orig.split():
            deva = has_devanagari(w)
            target = score(w) if score else None
            best, best_s = None, -9.0
            for _ in range(24):
                cand = self._word(self._bytes(), deva)
                if not deva:
                    cand = cand.upper() if (w.isupper() and len(w) > 1) else (cand if w.islower() else cand.capitalize())
                if score is None:
                    best = cand
                    break
                sc = score(cand)
                if sc > best_s:
                    best, best_s = cand, sc
                if target is not None and sc >= target - 0.02:
                    break
            words.append(best)
        return " ".join(words) or "Qaveno"

    def digits_like(self, orig, kind):
        b = self._bytes()
        ds = [c for c in orig if c.isdigit()]
        new = [str(b[i] % 10) for i in range(len(ds))]
        if kind == "PHONE" and len(ds) >= 10:
            new[len(ds) - 10] = "6789"[b[20] % 4]
        if kind == "AADHAAR" and len(ds) == 12:
            new[0] = "23456789"[b[21] % 8]
            new[11] = verhoeff_digit("".join(new[:11]))
        it = iter(new)
        return "".join(next(it) if c.isdigit() else c for c in orig)


HONEY_KINDS = ("NAME", "PHONE", "AADHAAR", "MRN", "ID", "ABHA", "INSURANCE")
