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


def _check_output(inp, out):
    """Return an error string if the output folder is unsafe, else None.
    Refuse: a symlinked output folder, overlap with the input in either
    direction (also through symlinks), an existing non-directory, or a non-empty folder."""
    # only the folder itself: a symlinked system parent (macOS /tmp -> /private/tmp) is normal,
    # and overlap is checked on resolved paths below
    if os.path.islink(out):
        return "output folder must not be a symlink"
    ri, ro = os.path.realpath(inp), os.path.realpath(out)
    for a, b in ((ri, ro), (ro, ri)):
        if a == b or a.startswith(b.rstrip(os.sep) + os.sep):
            return "output and input folders must not overlap"
    if os.path.lexists(out):
        if not os.path.isdir(out):
            return "output exists and is not a folder"
        if os.listdir(out):
            return "output folder must be empty"
    return None


def _stage_dir(out):
    os.makedirs(out, exist_ok=True)
    stage = os.path.join(out, ".release-%d" % os.getpid())  # output was checked empty: no clash
    os.mkdir(stage, 0o700)
    return stage


def _release(stage, out):
    # each top-level entry moves with one atomic rename (same filesystem); the stage is removed
    for name in sorted(os.listdir(stage)):
        os.replace(os.path.join(stage, name), os.path.join(out, name))
    os.rmdir(stage)


def _discard(stage):
    import shutil
    shutil.rmtree(stage, ignore_errors=True)


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
    err = _check_output(inp, out)
    if err:
        sys.stderr.write("raksha: %s; refusing to run (nothing written)\n" % err)
        return 2
    from raksha.config import load_policy
    from raksha.pipeline import run
    policy = load_policy(here)
    stage = _stage_dir(out)  # inside the output folder: never TMPDIR/HOME, same filesystem
    try:
        run(inp, stage, policy, keyring, log)
        _release(stage, out)
    except Exception as exc:  # message never printed: it could contain data
        _discard(stage)
        sys.stderr.write("raksha: run failed (%s)\n" % type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    _reexec_with_fixed_hashseed()
    sys.exit(main())
