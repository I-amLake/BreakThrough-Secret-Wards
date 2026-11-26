# Raksha — Secret Wards privacy firewall (Yugaantar DevForge, Track 3)

Raksha turns a folder of messy Indian hospital exports (CSV/TSV in any encoding, nested JSON, FHIR R4
bundles, free-text notes in English, Devanagari Hindi and Hinglish) into a research-safe release:
direct identifiers removed, the same patient linked across files and hospitals under one keyed
pseudonym (`PSN-XXXXXX`), quasi-identifiers generalised, and all clinical content kept.

* **Models: None.** No LLMs, no generative models, no pretrained transformers, no spaCy/NER models.
  Everything is rules, small hand-written gazetteers, transliteration, phonetic/fuzzy matching and
  deterministic algorithms. Nothing is downloaded at run time; no network calls.
* Python 3, CPU only, offline, deterministic. Typical run on the practice set (200 files):
  about 3 s and 55 MB peak RSS. A synthetic 2,400-file / 6,400-record set runs in about 9 s and 225 MB.

## Quick start

```bash
pip install -r requirements.txt          # optional: every dependency has a stdlib fallback
export RAKSHA_SECRET='…'                 # required; never written anywhere
python main.py --input /path/to/input --output /path/to/out
python scripts/validate_output.py --input /path/to/input --output /path/to/out   # -> CONTRACT OK
```

If `RAKSHA_SECRET` is missing the program exits with code 2, prints a fixed message and writes
nothing. The secret is removed from the process environment right after it is read.

Container run as the organisers do it (install in a build stage, run with no network):

```bash
docker run --rm --network none --cpus=2 --memory=4g -e RAKSHA_SECRET=practice \
  -v "$PWD":/app -v /data/in:/in:ro -v /data/out:/out -w /app python:3.11-slim \
  python main.py --input /in --output /out
```

## Repository layout

```
main.py                 entry point (argparse, secret handling, fixed hash seed, safe errors)
raksha.toml             submission manifest
requirements.txt        PyYAML, RapidFuzz, charset-normalizer (all optional, pinned)
config/policy.yaml      every privacy/utility knob (reproduced below)
raksha/
  ingest.py             walking, encoding detection (BOM, UTF-16, cp1252), format sniffing, quarantine rules
  schema.py             header/key classifier (English, Hindi, Hinglish labels) + value-type inference
  translit.py           Devanagari -> Latin with schwa deletion, phonetic fold, consonant skeleton
  lexicon.py, data/     small hand-made gazetteers: given names, surnames, honorifics, drugs, medical terms
  detect.py             span detector: clinical shields, Indian IDs, phones, dates, ages, addresses, names
  dates.py              date finding/parsing with per-source day/month order votes, format-preserving shift
  core.py               record units, evidence extraction, rendering of replacements, filename sanitising
  handlers.py           per-format extract / rewrite (CSV/TSV, JSON, FHIR, text)
  linkage.py            rule-based record linkage with hard vetoes and veto-aware clustering
  privacy.py            age bands, location generalisation, k-anonymity planner, suppression, risk metrics
  secure.py             HKDF key derivation, HMAC pseudonyms and date shifts, PII-free logging
  pipeline.py           orchestration, output paths, residual sweep, records.jsonl, report.json
scripts/
  gen_data.py           synthetic multi-hospital generator with ground truth
  evaluate.py           local metrics on synthetic data (leaks, preservation, linkage, LOS, determinism, attacker)
  validate_output.py    minimal mirror of the output contract
tests/
  acceptance_extended.py  Hindi/Hinglish linkage, same-name non-merge, C/O traps, FHIR, PII filename,
                          quarantine + canary, 9-day stay, determinism, secret sensitivity
  test_guardrails.py      fails on forbidden packages (openai, anthropic, google.generativeai, transformers,
                          vllm, llama_cpp, ollama, requests, httpx), network modules, model files
  test_offline.sh         runs the pipeline under `unshare -rn` (no network namespace) or a socket guard
```

## Architecture

```
 input/ ──► Pass 0  LOAD      walk (sorted) ─ decode ─ sniff ─ parse ─► broken/binary/empty ⇒ QUARANTINE
              │
              ▼
           Pass 1  HARVEST   names from structured name columns of THIS input only ─► runtime lexicon
              │              per-source date-order votes (DD/MM vs MM/DD), safe filename tokens
              ▼
           Pass 2  EXTRACT   each record (CSV row / JSON record / FHIR Patient / text doc) ─► Unit:
              │              profile (names, relatives, IDs, phones, DOB, birth year, sex, village, PIN),
              │              QIs (age, district, diagnosis, length of stay), dates
              ▼
           Pass 3  LINK      blocking (IDs, phone, name skeletons, relative) ─► rule scoring with vetoes
              │              ─► veto-aware clustering ─► HMAC pseudonym per cluster
              ▼
           Pass 4  PLAN      per-patient keyed date shift; k-anonymity levels; rare diagnosis escalation
              │              ─► suppression; risk metrics
              ▼
           Pass 5  REWRITE   format-preserving rewrite ─► residual exact-value sweep ─► re-parse check
              ▼
 output/ ◄─ sanitized/…  records.jsonl  report.json
```

### Detection (Indian PII, three scripts)

* **Clinical shields first.** Doses (`650 mg`), frequencies (`1-0-1`), `x 5 days`, BP/pulse/labs,
  ICD codes, organisation names (`… Hospital`, `… Sadan`), UUIDs and eponyms (`Babinski sign`,
  `Koch's`) are protected spans that no PII rule may overwrite. Doctors (`Dr.`, `डॉ.`) are kept.
* **Identifiers.** Aadhaar (spaced, masked `XXXX XXXX 1234`, Verhoeff used as a booster), ABHA
  number/address, PAN, phones (+91, 0-prefixed, split `98765 43210`, landlines, Devanagari digits),
  emails, labelled IDs (UHID/MRN/IPD/Reg/policy/PM-JAY), glued record IDs (`DHH-IPD-00591`), PIN with context.
* **Names.** Context first, lists second: label:value pairs (`Naam:`, `मरीज़ का नाम:`, `Patient Name:`),
  relation markers with trap handling (`S/o`, `W/o`, `D/o`; `C/O fever` vs `C/O Ramesh`; `H/O TB` vs
  `H/O Ramesh`; `X की पत्नी Y`), relation nouns, Hinglish postpositions (`Asha ka BP`), honorifics and
  kinship suffixes (`ji`, `bhaiya`, `behenji`), role cues (`witnessed by`, `X Y (attendant)`,
  `X Y, mob 98…`), the subject of a relation marker (`Asha, W/o Kamal`), and the record's own
  patient name inside its free text. Gazetteers and the runtime lexicon (names learned from the
  structured columns of the current input) catch the rest; ambiguous words (`Asha` = ASHA worker)
  need person context. With the built-in gazetteer emptied, the practice set still leaks 0 of 3,230 values.
* **Hidden places.** File names and parent folders, JSON keys, CSV headers, export metadata paths,
  FHIR extensions (`…/mothers-name`), base64 attachments and base64 strings inside JSON are all scanned.

### Linkage

Profiles compare names via transliteration fold + consonant skeleton + Jaro-Winkler with IDF weights.
Following the truth rule, a pair is linkable only with (1) a shared strong identifier (Aadhaar, ABHA,
PAN, UHID/MRN, insurance), (2) a shared phone with a compatible given name and age, or (3) a matching
name plus a second clue (DOB, relative, or village with birth years within 1). A name alone never links.
Hard vetoes: conflicting strong IDs or DOBs, sex conflict, birth years more than 3 apart, incompatible
names (given- or family-name disagreement), same father/spouse relation with a different name. Clusters
merge only if no cross pair is vetoed; weak fragments attach only when exactly one cluster fits.

### Pseudonyms, dates and the secret

Sub-keys come from `RAKSHA_SECRET` with HKDF (stdlib RFC 5869) under separate labels for pseudonyms,
date shifts and file tokens. A pseudonym is `PSN-` + 6 Crockford base-32 characters of an HMAC over the
cluster anchor (the sorted input coordinates of its members), so it is stable for the same input and
secret, changes completely with a different secret, and cannot be inverted from patient data. Each
patient (or each unlinked record) gets its own keyed shift in ±[14,180] days, so intervals such as a
9-day stay are exact and there is no global offset to recover.

### Privacy layer — config/policy.yaml

```yaml
date_shift:   {min_days: -180, max_days: 180, min_abs_days: 14}
age:          {band_widths: [10, 20], topcode: 90}       # bands always contain the true age
location:     {keep_pin3_at_level: -1, keep_district_up_to_level: 1, tehsil: suppress}
k_anonymity:  {k: 5, max_level: 1, rare_diagnosis_min_level: 1}
linkage:      {age_veto_years: 3, phone_degree_cap: 6, max_block: 300, ...}
replacements: {relative: "[RELATIVE]", other_name: "[NAME]", unlinked_patient: "[PATIENT]"}
```

Level 0 releases 10-year age bands, sex and district (villages are generalised to their district,
house/locality/landmark/tehsil/PIN removed). Classes with fewer than k patients, and every record with
a diagnosis seen in fewer than k patients, move to level 1 (20-year bands). A record that is still
unique on demographics + diagnosis + length of stay is suppressed: 40-year band and state only, counted
in `records_suppressed`. Clinical content is never removed. `report.json` carries before/after risk
metrics (average and maximum re-identification risk, share below k).

**Trade-off.** In the scoring, the registry attacker gains far more from a 5-year band and a PIN prefix
than utility loses from 10/20-year bands, so we chose coarse demographics and full clinical retention.

### Security

No PII in logs (only counts), in error messages (fixed category strings), in exception traces (custom
excepthook), in `report.json` (no input names or paths; output names are sanitised and carry an HMAC
suffix when renamed), or on disk outside the output folder: nothing is written to TMPDIR or HOME, no
temp files, bytecode writing is disabled. Inputs are opened read-only. Broken, binary, empty, too-deep
or unparseable files are quarantined and never copied.

## Results

Practice set (`RAKSHA_SECRET=practice`, kit `check_dev.py`): CONTRACT OK; 0 of 3,230 identifiers
visible; 0 of 4 canaries; 4,855 of 4,855 medical values kept; linkage precision 1.00, recall 1.00;
0 raw copies; byte-identical across runs; a different secret changes every pseudonym and date shift.
Synthetic set (`scripts/gen_data.py --patients 60`): 0 leaks of 658 values, 100% clinical preservation,
linkage P 1.00 / R 0.98, 30 of 30 stays preserved.

## Known limitations

* Names never seen in a structured field, without any context cue and absent from the gazetteer can
  slip through in free text (no statistical NER by design).
* Free-text addresses without a trigger word (`Address`, `Vill.`, `पता`, `ग्राम`) are only partly found.
* Linkage is deliberately conservative: first-name-only fragments without phone/ID/relative stay unlinked.
* k-anonymity is computed within the release; small releases therefore get coarse bands.
* Formats beyond CSV/TSV/JSON/NDJSON/FHIR/text (PDF, images, XML, HL7v2) are quarantined.

## Design notes and credits

Built during the event. The two-pass design, clinical shielding, Verhoeff booster, IDF-weighted names,
phone-degree cap, veto-aware clustering, residual sweep, HKDF domain separation and cluster-anchored
pseudonyms follow our design review; CRF taggers, large census gazetteers and heavy anonymisation
libraries were rejected (no time, memorisation risk, or unnecessary weight). No development data,
names or answers are embedded in the code; gazetteers are generic hand-made lists.
