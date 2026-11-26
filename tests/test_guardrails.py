#!/usr/bin/env python3
"""Static guardrails: fail if forbidden packages appear in runtime code or requirements, if any
network module is imported by runtime code, or if a secret-looking literal is committed.

    python tests/test_guardrails.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORBIDDEN = ["openai", "anthropic", "google.generativeai", "google_generativeai", "transformers", "vllm",
             "llama_cpp", "llama-cpp-python", "ollama", "requests", "httpx"]
NETWORK = ["socket", "urllib", "http.client", "urllib3", "aiohttp", "ftplib", "smtplib"]
RUNTIME = ["main.py"] + [os.path.join("raksha", f) for f in sorted(os.listdir(os.path.join(ROOT, "raksha"))) if f.endswith(".py")]


def imports(src):
    out = set()
    for m in re.finditer(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))", src, re.M):
        if m.group(1):
            out.add(m.group(1))
        else:
            out.update(x.strip().split(" ")[0] for x in m.group(2).split(","))
    return out


def main():
    fails = []
    for rel in RUNTIME:
        src = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        mods = imports(src)
        for mod in mods:
            for bad in FORBIDDEN + NETWORK:
                if mod == bad or mod.startswith(bad + "."):
                    fails.append("%s imports %s" % (rel, mod))
        for bad in FORBIDDEN:
            if re.search(r"__import__\(\s*['\"]%s" % re.escape(bad), src) or re.search(r"importlib\.import_module\(\s*['\"]%s" % re.escape(bad), src):
                fails.append("%s dynamically imports %s" % (rel, bad))
        if re.search(r"RAKSHA_SECRET\s*=\s*['\"]", src):
            fails.append("%s hardcodes a secret" % rel)
    req = open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8").read().lower()
    for line in req.splitlines():
        name = re.split(r"[<>=\[; ]", line.split("#")[0].strip())[0].replace("_", "-")
        if name and any(name == b.replace("_", "-").replace(".", "-") or name == b for b in FORBIDDEN):
            fails.append("requirements.txt lists %s" % name)
    # no large model files in the repo
    for dp, dns, fns in os.walk(ROOT):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
        for f in fns:
            p = os.path.join(dp, f)
            if os.path.getsize(p) > 20 * 1024 * 1024 or f.endswith((".safetensors", ".gguf", ".onnx", ".pt", ".bin")):
                fails.append("model-like or huge file: %s" % os.path.relpath(p, ROOT))
    for f in fails:
        print("FAIL", f)
    print("guardrails: %s" % ("OK" if not fails else "%d problem(s)" % len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
