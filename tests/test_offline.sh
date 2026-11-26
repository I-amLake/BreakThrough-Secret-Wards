#!/usr/bin/env bash
# Run the full pipeline with NO network namespace, proving there are no runtime network calls or
# lazy downloads. Uses `unshare -n` (Linux, needs user namespaces) and falls back to a Python
# socket guard that makes every connection attempt fatal.
#
# Equivalent container command (as the organisers run it):
#   docker run --rm --network none --cpus=2 --memory=4g -e RAKSHA_SECRET=practice \
#     -v "$PWD":/app -v /path/to/input:/in:ro -v /path/to/out:/out -w /app python:3.11-slim \
#     sh -c "pip install -r requirements.txt >/dev/null 2>&1 || true; python main.py --input /in --output /out"
#   (install step needs network; run it in an image build stage when using --network none)
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/in"
printf 'UHID,Patient Name,Age,Mobile,Diagnosis\nZQ-881001,Kusum Lata,52,9876501234,Hypertension\n' > "$WORK/in/reg.csv"
printf 'Patient: Kusum Lata 52/F Mob 9876501234\nC/O fever x 3 days. Tab Dolo 650 1-0-1\n' > "$WORK/in/note.txt"
if unshare -rn true 2>/dev/null; then
  echo "[offline] using unshare -rn (no network namespace)"
  RAKSHA_SECRET=offline-test unshare -rn "$PY" "$REPO/main.py" --input "$WORK/in" --output "$WORK/out"
else
  echo "[offline] unshare unavailable; using socket guard"
  RAKSHA_SECRET=offline-test "$PY" - "$REPO" "$WORK" <<'PYEOF'
import socket, sys, runpy
def _blocked(*a, **k):
    raise SystemExit("NETWORK ACCESS ATTEMPTED")
socket.socket.connect = _blocked
socket.create_connection = _blocked
socket.getaddrinfo = _blocked
repo, work = sys.argv[1], sys.argv[2]
sys.argv = [repo + "/main.py", "--input", work + "/in", "--output", work + "/out"]
import os; os.environ["PYTHONHASHSEED"] = "0"
runpy.run_path(repo + "/main.py", run_name="__main__")
PYEOF
fi
test -f "$WORK/out/report.json" && test -f "$WORK/out/records.jsonl"
if grep -rq "Kusum\|9876501234" "$WORK/out"; then echo "[offline] FAIL: leak"; exit 1; fi
echo "[offline] OK: ran without network, outputs present, no leak"
