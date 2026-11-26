"""Key handling, keyed pseudonyms and PII-free logging.

Design rules
* The secret is read only from the RAKSHA_SECRET environment variable and is never logged,
  written, or put into exception messages. Sub-keys are derived with HKDF-SHA256 so the raw
  secret is never used directly and each purpose has an independent key.
* Pseudonyms are HMAC-SHA256(k_psn, canonical_cluster_key): stable for the same secret,
  unlinkable / non-reversible without it, and different for a different secret.
* Logs carry only fixed event names and numbers. Exceptions are reduced to their class name.
"""
import hashlib
import hmac
import os
import sys
import time

PSN_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32 (no I, L, O, U)


class SecretMissing(Exception):
    pass


def load_secret():
    s = os.environ.get("RAKSHA_SECRET")
    if not s:
        raise SecretMissing()
    return s.encode("utf-8")


HKDF_SALT = b"raksha-v1"  # public, fixed salt (RFC 5869 allows a non-secret salt)


def _hkdf(ikm, info, length=32, salt=HKDF_SALT):
    """RFC 5869 HKDF-SHA256 (stdlib).

    Extract: PRK = HMAC-SHA256(key=salt, msg=IKM)   <- the RFC puts the salt in the key slot and the
    secret input keying material (here RAKSHA_SECRET) in the message slot; this is not reversed.
    Expand:  T(i) = HMAC-SHA256(key=PRK, msg=T(i-1) || info || i). Verified against RFC 5869 test case 1
    in tests/test_guardrails.py."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


class Keyring:
    def __init__(self, secret_bytes):
        self._k_psn = _hkdf(secret_bytes, b"pseudonym")
        self._k_shift = _hkdf(secret_bytes, b"date-shift")
        self._k_tok = _hkdf(secret_bytes, b"token")

    def _mac(self, key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def pseudonym(self, canonical, salt=0):
        d = self._mac(self._k_psn, canonical + ("" if not salt else "#%d" % salt))
        n = int.from_bytes(d[:8], "big")
        out = []
        for _ in range(6):
            out.append(PSN_ALPHABET[n & 31])
            n >>= 5
        return "PSN-" + "".join(out)

    def shift_days(self, key, lo, hi, min_abs):
        span = hi - lo + 1
        d = self._mac(self._k_shift, key)
        n = int.from_bytes(d[:8], "big")
        for i in range(64):
            v = lo + (n % span)
            if abs(v) >= min_abs:
                return v
            n = int.from_bytes(self._mac(self._k_shift, key + "#%d" % i)[:8], "big")
        return min_abs

    def token(self, kind, value, n=10):
        return self._mac(self._k_tok, kind + "\x00" + value).hex()[:n]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


class SafeLog:
    """Writes only event names and numeric fields to stderr. Strings are rejected."""

    def __init__(self, stream=None, quiet=False):
        self.stream = stream or sys.stderr
        self.quiet = quiet
        self.t0 = time.time()

    def event(self, name, **nums):
        if self.quiet:
            return
        parts = []
        for k in sorted(nums):
            v = nums[k]
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                v = "?"  # never print non-numeric values
            parts.append("%s=%s" % (k, v))
        self.stream.write("[raksha +%.1fs] %s %s\n" % (time.time() - self.t0, name, " ".join(parts)))
        self.stream.flush()


def error_category(exc):
    """Map an exception to a fixed reason string. Never uses str(exc)."""
    name = type(exc).__name__
    table = {
        "UnicodeDecodeError": "undecodable text encoding",
        "JSONDecodeError": "malformed or truncated JSON",
        "Error": "malformed CSV",
        "MemoryError": "file too large",
        "RecursionError": "structure too deeply nested",
        "FhirInvalid": "invalid FHIR resource",
        "Unsupported": "unsupported format",
        "BinaryFile": "unsupported binary format",
        "EmptyFile": "empty file",
        "GarbledText": "undecodable text encoding",
    }
    return table.get(name, "processing error")


def install_safe_excepthook():
    def hook(exc_type, exc, tb):
        sys.stderr.write("raksha: fatal internal error (%s); no output details are printed by design\n" % exc_type.__name__)
    sys.excepthook = hook
