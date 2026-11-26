#!/usr/bin/env python3
"""Unit tests for the unseen-name finder as integrated in Detector.

All person names below are invented syllable combinations (not taken from any kit/dev data or
from any list shipped in raksha/). Run:  python tests/test_namefind.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from raksha.detect import Detector  # noqa: E402
from raksha.namefind import CharNgramScorer  # noqa: E402


def names(text):
    return [text[s.start:s.end] for s in Detector().detect(text) if s.kind == "NAME"]


def masked(text, word):
    return any(word in n for n in names(text))


class UnseenNames(unittest.TestCase):
    def test_hinglish_ergative_and_dative(self):
        self.assertTrue(masked("Kal Thivaresh ne dawai li.", "Thivaresh"))
        self.assertTrue(masked("Doctor ne Pramithika ko discharge kiya.", "Pramithika"))

    def test_lowercase_hinglish(self):
        self.assertTrue(masked("aaj thivaresh ne khana nahi khaya", "thivaresh"))

    def test_devanagari_postposition(self):
        self.assertTrue(masked("कल थिवरेश ने दवा ली।", "थिवरेश"))

    def test_kinship_suffix(self):
        self.assertTrue(masked("Gonavati didi ko bukhar hai.", "Gonavati"))

    def test_in_document_propagation(self):
        t = "Thivaresh ne dawai li.\nReview: Thivaresh stable, BP 130/80."
        self.assertEqual(sum("Thivaresh" in n for n in names(t)), 2)


class NoOverRedaction(unittest.TestCase):
    def test_drugs_and_doses(self):
        for t in ["Tab Dolokind 650 1-0-1 x 5 days.", "Started Pantocid today.", "Syp Zerodol was given."]:
            self.assertEqual(names(t), [], t)

    def test_complaints_are_not_names(self):
        for t in ["Mareez ko bukhar hai.", "Dard ki shikayat hai.", "आज दस्त की शिकायत है।"]:
            self.assertEqual(names(t), [], t)

    def test_places_with_place_context(self):
        for t in ["Lucknow se aaye the.", "Barabanki ko refer kiya.", "लखनऊ को रेफर किया।"]:
            self.assertEqual(names(t), [], t)

    def test_clinical_words_after_weak_cue(self):
        self.assertEqual(names("Pneumonia ki dose badhayi."), [])
        self.assertEqual(names("निमोनिया की जांच हुई।"), [])


class Classifier(unittest.TestCase):
    def test_weights_load_and_separate(self):
        sc = CharNgramScorer()
        self.assertGreater(len(sc.weights), 1000)
        self.assertGreater(sc.prob("thivaresh"), sc.prob("paracetamol"))
        self.assertGreater(sc.prob("pramithika"), sc.prob("ultrasound"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
