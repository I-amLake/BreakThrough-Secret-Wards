"""Gazetteers and lexicons, loaded once. All lists live in raksha/data/*.txt."""
import os
from functools import lru_cache

from .translit import fold

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

    def is_name_latin(self, tok):
        t = tok.lower()
        return t in self.names or fold(t) in self.names_f


@lru_cache(maxsize=1)
def get_lexicon():
    return Lexicon()
