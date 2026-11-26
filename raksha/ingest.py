"""File discovery, type sniffing, encoding detection and parsing. Never trusts extensions alone."""
import codecs
import csv
import io
import json
import os
import re
import unicodedata


class Unsupported(Exception):
    pass


class BinaryFile(Exception):
    pass


class EmptyFile(Exception):
    pass


class GarbledText(Exception):
    pass


class FhirInvalid(Exception):
    pass


TEXT_EXT = {".txt", ".text", ".note", ".notes", ".md", ".log", ".rtf_txt", ".hl7", ".xml", ".html", ".htm", ".dat"}
CSV_EXT = {".csv", ".tsv", ".tab", ".psv"}
JSON_EXT = {".json", ".fhir", ".ndjson", ".jsonl"}
BINARY_MAGIC = [b"%PDF", b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"\xd0\xcf\x11\xe0", b"\x1f\x8b", b"BZh",
                b"7z\xbc\xaf", b"Rar!", b"II*\x00", b"MM\x00*", b"RIFF", b"\x00\x00\x01\x00", b"SQLite format"]


def walk(root):
    out = []
    for dp, dns, fns in os.walk(root):
        dns.sort()
        for fn in sorted(fns):
            full = os.path.join(dp, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            out.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return sorted(out)


def decode(data):
    """Decode bytes to str. Raises GarbledText / BinaryFile."""
    if not data:
        raise EmptyFile()
    for magic in BINARY_MAGIC:
        if data.startswith(magic):
            raise BinaryFile()
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors="strict")
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        return data.decode("utf-16")
    if data.startswith(codecs.BOM_UTF32_LE) or data.startswith(codecs.BOM_UTF32_BE):
        return data.decode("utf-32")
    # UTF-16 without BOM: many NULs at alternating positions
    sample = data[:4000]
    if sample.count(b"\x00") > len(sample) * 0.3:
        even = sample[0::2].count(b"\x00")
        odd = sample[1::2].count(b"\x00")
        try:
            return data.decode("utf-16-le" if odd > even else "utf-16-be")
        except UnicodeDecodeError:
            raise BinaryFile()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        # deterministic legacy chain (no statistical charset guessing: identical on every machine)
        for e in ("cp1252", "latin-1"):
            try:
                text = data.decode(e)
                break
            except (UnicodeDecodeError, LookupError):
                continue
    if text is None:
        raise GarbledText()
    ctrl = sum(1 for c in text[:20000] if (unicodedata.category(c) == "Cc" and c not in "\r\n\t\f") or c == "\ufffd")
    if ctrl > max(3, 0.02 * min(len(text), 20000)):
        raise BinaryFile()
    return unicodedata.normalize("NFC", text)


def sniff_kind(relpath, text):
    ext = os.path.splitext(relpath)[1].lower()
    st = text.lstrip("\ufeff \t\r\n")
    if ext in (".ndjson", ".jsonl"):
        return "ndjson"
    if ext in JSON_EXT:
        return "json"
    if st[:1] in ("{", "["):
        try:
            json.loads(text)
            return "json"
        except (ValueError, RecursionError):
            if ext not in CSV_EXT and ext not in TEXT_EXT:
                return "json"
    if ext in CSV_EXT:
        return "csv"
    if ext in TEXT_EXT:
        return "text"
    # unknown extension: decide from content
    lines = [l for l in text.splitlines()[:30] if l.strip()]
    if len(lines) >= 3:
        for d in (",", "\t", "|", ";"):
            counts = [l.count(d) for l in lines]
            if counts[0] >= 2 and sum(1 for c in counts if c == counts[0]) >= 0.8 * len(counts):
                return "csv"
    return "text"


def parse_json(text):
    obj = json.loads(text)
    if not isinstance(obj, (dict, list)):
        raise Unsupported()
    return obj


def parse_ndjson(text):
    out = []
    for line in text.splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def is_fhir(obj):
    return isinstance(obj, dict) and isinstance(obj.get("resourceType"), str)


def check_fhir(obj):
    """Light structural R4 check (no network, no heavy schema libs)."""
    if obj.get("resourceType") == "Bundle":
        if "entry" in obj and not isinstance(obj["entry"], list):
            raise FhirInvalid()
        for e in obj.get("entry", []):
            if not isinstance(e, dict):
                raise FhirInvalid()
            r = e.get("resource")
            if r is not None and not (isinstance(r, dict) and isinstance(r.get("resourceType"), str)):
                raise FhirInvalid()
    return True


def detect_delimiter(text, ext):
    if ext in (".tsv", ".tab"):
        return "\t"
    if ext == ".psv":
        return "|"
    sample = "\n".join(text.splitlines()[:50])
    best, best_score = ",", -1
    for d in (",", "\t", ";", "|"):
        try:
            rows = list(csv.reader(io.StringIO(sample), delimiter=d))
        except csv.Error:
            continue
        lens = [len(r) for r in rows if r]
        if not lens:
            continue
        mode = max(set(lens), key=lens.count)
        if mode < 2:
            continue
        score = lens.count(mode) * mode
        if score > best_score:
            best, best_score = d, score
    return best


def parse_csv(text, ext):
    delim = detect_delimiter(text, ext)
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim, strict=False))
    while rows and not any(c.strip() for c in rows[-1]):
        rows.pop()
    if not rows:
        raise EmptyFile()
    lens = [len(r) for r in rows if any(c.strip() for c in r)]
    mode = max(sorted(set(lens)), key=lens.count)
    hdr = 0
    for i, r in enumerate(rows[:6]):
        if len(r) == mode:
            hdr = i
            break
    if mode < 2:
        raise Unsupported()
    return {"delim": delim, "preamble": rows[:hdr], "header": rows[hdr], "rows": rows[hdr + 1:]}
