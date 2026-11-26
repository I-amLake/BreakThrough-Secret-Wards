#!/usr/bin/env bash
# Stigma Shield in 30 seconds: two invented OPD notes, identical except the diagnosis
# (HIV vs dengue). Development demo only; never used by main.py.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IN="$REPO/dev_eval/demo_stigma"
OUT="$(mktemp -d)/out"
export RAKSHA_SECRET="${RAKSHA_SECRET:-demo-secret-not-for-production}"
python3 "$REPO/main.py" --input "$IN" --output "$OUT" --quiet
show() {  # $1 = input file name
  local sha out
  sha=$(python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$IN/$1")
  out=$(python3 -c "import json,sys;r=json.load(open(sys.argv[1]));print(next(f['output'] for f in r['files'] if f['input_sha256']==sys.argv[2]))" "$OUT/report.json" "$sha")
  echo "================ $1 : BEFORE ================"; cat "$IN/$1"
  echo "================ $1 : AFTER  ================"; cat "$OUT/$out"; echo
}
show opd_control.txt
show opd_hiv.txt
echo "================ report.json stigma_shield (counts only) ================"
python3 -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1]))['stigma_shield'],indent=2))" "$OUT/report.json"
cat <<'TXT'
Same age, sex, village and hospital; only the diagnosis differs. For the HIV patient the shield
  - widened the age band (20-39 -> 0-39) and released only the state (alone in district => k < 5),
  - removed the name of the ART centre's hospital while keeping "HIV", "ART Centre", CD4 and the regimen,
  - planted invented Aadhaar/phone/names in an in-memory copy, re-ran detection, and checked none survived.
TXT
rm -rf "$(dirname "$OUT")"
