"""Gazetteers and lexicons, loaded once. All lists live in raksha/data/*.txt."""
import os
from functools import lru_cache

from .translit import devanagari_to_latin, fold, has_devanagari, skeleton

_DATA = os.path.join(os.path.dirname(__file__), "data")


def _words(fname):
    out = []
    with open(os.path.join(_DATA, fname), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                out.extend(line.split())
    return out


def _pairs(fname):
    out = {}
    with open(os.path.join(_DATA, fname), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                parts = line.split()
                out[parts[0]] = parts[1] if len(parts) > 1 else "U"
    return out


class Lexicon:
    def __init__(self):
        self.first = set(_words("first_names.txt"))
        self.surnames = set(_words("surnames.txt"))
        self.names = self.first | self.surnames
        self.first_f = {fold(w) for w in self.first} - {""}
        self.sur_f = {fold(w) for w in self.surnames} - {""}
        self.names_f = self.first_f | self.sur_f
        self.drugs = set(_words("drugs.txt"))
        self.medical = set(_words("medical_terms.txt")) | self.drugs
        self.stop_latin = set(_words("stop_latin.txt"))
        self.stop_hindi = set(_words("stop_hindi.txt"))
        self.honor_pre = _pairs("honorifics.txt")
        self.honor_suf = _pairs("honorific_suffixes.txt")
        self.common = set(_words("common_words.txt"))
        self.places = set(_words("places.txt"))
        self.places_f = {fold(w) for w in self.places} - {""}
        self.places_sk = {skeleton(w) for w in self.places if len(w) >= 4} - {""}
        # consonant skeletons of English clinical/common words, to spot them written in Devanagari;
        # skeletons shared with any gazetteer name are dropped so names are never blocked by this
        eng = {w for w in (self.common | self.medical | self.stop_latin) if w.isascii() and w.isalpha() and len(w) >= 4}
        name_sk = {skeleton(w) for w in self.names if w.isascii()}
        self.loan_sk = {skeleton(w) for w in eng if len(skeleton(w)) >= 4} - name_sk - {""}
        # names that also collide with medical/common vocabulary: need context
        self.ambiguous = (self.names & (self.medical | self.stop_latin))

    def is_medical(self, tok):
        t = tok.lower().strip(".'")
        if t.endswith("'s"):
            t = t[:-2]
        return t in self.medical

    def is_stop(self, tok):
        t = tok.lower().strip(".")
        return t in self.stop_latin or tok in self.stop_hindi

    def is_place(self, tok):
        """Public place names in either script (Devanagari compared by fold / consonant skeleton)."""
        t = tok.strip(".")
        if has_devanagari(t):
            if t in self.places:
                return True
            lat = devanagari_to_latin(t)
            sk = skeleton(lat)
            return fold(lat) in self.places_f or (len(sk) >= 5 and sk in self.places_sk)
        tl = t.lower()
        return tl in self.places or fold(tl) in self.places_f

    def is_common(self, tok):
        t = tok.lower().strip(".")
        return t in self.common or t in self.stop_latin

    def is_surname_only(self, tok):
        """Family names and gendered name suffixes (Devi, Kumari, Bano, Yadav...) that are not given names."""
        t = tok.lower().strip(".")
        f = fold(t)
        return (t in self.surnames or f in self.sur_f) and t not in self.first and f not in self.first_f

    def is_name_latin(self, tok):
        t = tok.lower()
        return t in self.names or fold(t) in self.names_f


@lru_cache(maxsize=1)
def get_lexicon():
    return Lexicon()
