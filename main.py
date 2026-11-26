#!/usr/bin/env python3
"""Raksha - Secret Wards privacy firewall.  Usage: python main.py --input IN --output OUT

Offline, CPU-only, no LLMs. Reads the key from RAKSHA_SECRET (never written anywhere).
"""
import argparse
import os
import sys


def _reexec_with_fixed_hashseed():
    # set iteration order must never influence output; belt-and-braces on top of explicit sorting
    if os.environ.get("PYTHONHASHSEED") != "0":
        env = dict(os.environ, PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
        try:
            os.execve(sys.executable, [sys.executable] + sys.argv, env)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description="Raksha privacy firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    sys.dont_write_bytecode = True
    from raksha.secure import Keyring, SafeLog, SecretMissing, install_safe_excepthook, load_secret
    install_safe_excepthook()
    log = SafeLog(quiet=a.quiet)
    try:
        secret = load_secret()
    except SecretMissing:
        sys.stderr.write("raksha: RAKSHA_SECRET is not set; refusing to run (nothing written)\n")
        return 2
    os.environ.pop("RAKSHA_SECRET", None)  # keep it out of any child process / crash dump
    keyring = Keyring(secret)
    del secret
    inp = os.path.abspath(a.input)
    out = os.path.abspath(a.output)
    if not os.path.isdir(inp):
        sys.stderr.write("raksha: input folder not found\n")
        return 2
    if out == inp or out.startswith(inp + os.sep):
        sys.stderr.write("raksha: output must not be inside the input folder\n")
        return 2
    os.makedirs(out, exist_ok=True)
    from raksha.config import load_policy
    from raksha.pipeline import run
    policy = load_policy(here)
    try:
        run(inp, out, policy, keyring, log)
    except Exception as exc:  # message never printed: it could contain data
        sys.stderr.write("raksha: run failed (%s)\n" % type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    _reexec_with_fixed_hashseed()
    sys.exit(main())
