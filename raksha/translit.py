"""Devanagari -> Latin transliteration and name normalisation for cross-script matching.

Hand-written (no external model): a grapheme table plus a Hindi schwa-deletion heuristic,
followed by a phonetic folding step so that e.g. "मोहम्मद", "Mohammad", "Muhammed", "Mohd" and
"Md." all land on the same key.
"""
import functools
import re
import unicodedata

_CONS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "n",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh",
    "ष": "sh", "स": "s", "ह": "h", "ळ": "l", "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh",
    "फ़": "f", "य़": "y",
}
_NUKTA_BASE = {"क": "क़", "ख": "ख़", "ग": "ग़", "ज": "ज़", "ड": "ड़", "ढ": "ढ़", "फ": "फ़", "य": "य़"}
_VOWELS = {"अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo", "ऋ": "ri", "ए": "e", "ऐ": "ai",
           "ओ": "o", "औ": "au", "ऑ": "o", "ऍ": "e"}
_MATRAS = {"ा": "aa", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo", "ृ": "ri", "े": "e", "ै": "ai", "ो": "o",
           "ौ": "au", "ॉ": "o", "ॅ": "e"}
_VIRAMA = "्"
_NUKTA = "़"
_ANUSVARA = "ं"
_CHANDRA = "ँ"
_VISARGA = "ः"

DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")


def has_devanagari(s):
    return bool(DEVANAGARI_RE.search(s or ""))


def _syllabify(word):
    """Return list of units: (kind, latin, has_inherent_a)."""
    units = []
    chars = list(unicodedata.normalize("NFC", word))
    i = 0
    while i < len(chars):
        c = chars[i]
        if i + 1 < len(chars) and chars[i + 1] == _NUKTA and c in _NUKTA_BASE:
            c = _NUKTA_BASE[c]
            i += 1
        if c in _CONS:
            nxt = chars[i + 1] if i + 1 < len(chars) else ""
            if nxt == _VIRAMA:
                units.append(["C", _CONS[c], False, ""])
                i += 2
                continue
            if nxt in _MATRAS:
                units.append(["C", _CONS[c], False, _MATRAS[nxt]])
                i += 2
                continue
            units.append(["C", _CONS[c], True, ""])
            i += 1
            continue
        if c in _VOWELS:
            units.append(["V", _VOWELS[c], False, ""])
        elif c in (_ANUSVARA, _CHANDRA):
            units.append(["N", "n", False, ""])
        elif c == _VISARGA:
            units.append(["N", "h", False, ""])
        elif c in _MATRAS:  # stray matra
            units.append(["V", _MATRAS[c], False, ""])
        elif "\u0966" <= c <= "\u096F":
            units.append(["D", str(ord(c) - 0x0966), False, ""])
        i += 1
    return units


def _vowel_after(units, j):
    """Does unit j end in a (non-deleted) vowel sound?"""
    u = units[j]
    return u[0] == "V" or (u[0] == "C" and (u[2] or u[3]))


def devanagari_to_latin(word):
    units = _syllabify(word)
    if not units:
        return ""
    n = len(units)
    # word-final schwa deletion (keep for monosyllables like "न")
    cons_idx = [k for k, u in enumerate(units) if u[0] == "C"]
    if units[-1][0] == "C" and units[-1][2] and len(units) > 1:
        units[-1][2] = False
    # medial schwa deletion, right to left: V C [a] C V  -> delete
    for j in range(n - 2, 0, -1):
        u = units[j]
        if u[0] != "C" or not u[2]:
            continue
        prev_ok = j - 1 >= 0 and _vowel_after(units, j - 1)
        nxt = units[j + 1] if j + 1 < n else None
        next_ok = nxt is not None and nxt[0] == "C" and (nxt[2] or nxt[3])
        if prev_ok and next_ok and j + 1 != n - 1 or (prev_ok and next_ok and nxt[3]):
            u[2] = False
    out = []
    for k, u in enumerate(units):
        if u[0] == "C":
            out.append(u[1] + (u[3] if u[3] else ("a" if u[2] else "")))
        elif u[0] == "N":
            nxt = units[k + 1][1] if k + 1 < n else ""
            if u[1] == "n" and nxt[:1] in ("p", "b", "m"):
                out.append("m")
            elif u[1] == "n" and nxt[:1] == "h" and k + 1 == n - 1:
                out.append("ng")  # सिंह -> singh
            else:
                out.append(u[1])
        else:
            out.append(u[1])
    del cons_idx
    return "".join(out)


def to_latin(text):
    """Transliterate every Devanagari run in text; Latin is passed through."""
    if not has_devanagari(text):
        return text
    return re.sub(r"[\u0900-\u0963\u0970-\u097F]+", lambda m: devanagari_to_latin(m.group(0)), text)


# canonical variants (after lowercasing, before folding)
_VARIANTS = {
    "md": "mohammad", "mohd": "mohammad", "mohammed": "mohammad", "muhammad": "mohammad", "muhammed": "mohammad",
    "mohamad": "mohammad", "mohamed": "mohammad", "mohmmad": "mohammad", "mohammad": "mohammad", "mhd": "mohammad",
    "kr": "kumar", "kumaar": "kumar", "laxmi": "lakshmi", "luxmi": "lakshmi", "shri": "", "sri": "", "shree": "",
    "smt": "", "mr": "", "mrs": "", "ms": "", "km": "", "kumari": "kumari", "devi": "devi", "debi": "devi",
    "syed": "sayed", "sayyed": "sayed", "sayyad": "sayed", "sk": "shaikh", "sheikh": "shaikh", "shaik": "shaikh",
    "chaudhari": "chaudhary", "choudhary": "chaudhary", "chowdhury": "chaudhary", "choudhury": "chaudhary",
    "agrawal": "agarwal", "aggarwal": "agarwal", "srivastav": "srivastava", "shrivastava": "srivastava",
    "verma": "varma", "mishra": "misra",
}


@functools.lru_cache(maxsize=200000)
def fold(token):
    """Phonetic folding of a single Latin token into a comparison form."""
    t = token.lower()
    t = re.sub(r"[^a-z]", "", t)
    if not t:
        return ""
    t = _VARIANTS.get(t, t)
    if not t:
        return ""
    rules = [
        ("ksh", "ks"), ("x", "ks"), ("chh", "c"), ("ch", "c"), ("sh", "s"), ("ph", "f"), ("q", "k"), ("ck", "k"),
        ("kh", "k"), ("gh", "g"), ("jh", "j"), ("th", "t"), ("dh", "d"), ("bh", "b"), ("w", "v"), ("z", "j"),
        ("aa", "a"), ("ee", "i"), ("ii", "i"), ("oo", "u"), ("uu", "u"), ("ou", "u"), ("au", "o"), ("ai", "e"),
        ("ey", "e"), ("ay", "e"), ("y", "i"),
    ]
    for a, b in rules:
        t = t.replace(a, b)
    t = re.sub(r"(.)\1+", r"\1", t)  # collapse doubles
    if len(t) > 3 and t.endswith("a"):
        t = t[:-1]
    if len(t) > 3 and t.endswith("h"):
        t = t[:-1]
    return t


@functools.lru_cache(maxsize=200000)
def skeleton(token):
    """Consonant skeleton (first letter kept) - a coarse blocking key."""
    f = fold(token)
    if not f:
        return ""
    return f[0] + re.sub(r"[aeiou]", "", f[1:])


_TOKEN_RE = re.compile(r"[A-Za-z]+|[\u0900-\u0963\u0970-\u097F]+")


def name_tokens(name):
    """Normalised name tokens (Latin folded) from a raw name in any script."""
    out = []
    for tok in _TOKEN_RE.findall(name or ""):
        lat = devanagari_to_latin(tok) if has_devanagari(tok) else tok
        f = fold(lat)
        if f:
            out.append(f)
    return out
