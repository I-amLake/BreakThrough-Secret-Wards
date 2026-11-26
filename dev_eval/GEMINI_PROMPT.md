# Prompt for Gemini 4 Neon: tricky test cases for Raksha

Copy everything inside the box below into Gemini 4 Neon (High thinking is best). Save Gemini's answer
as a plain text file, for example `cases.jsonl`, next to the repo. Then run:

```sh
python3 -m dev_eval.gemini_cases cases.jsonl --run          # see what leaks today
python3 -m dev_eval.improve --rounds 3 --gemini-cases cases.jsonl --kit ../kit   # learn from them
```

Gemini only writes test data. Raksha itself never calls Gemini or any other AI: everything after
the copy-paste runs offline on your laptop.

---

```text
You are helping test an OFFLINE privacy tool that removes personal data from Indian hospital records
(English, Hindi in Devanagari, and Hinglish = Hindi written in Latin letters). I need HARD, realistic
but completely SYNTHETIC test records. Invent every person, number and place detail. Never use a real
person, a real phone number, a real Aadhaar, or a celebrity.

OUTPUT FORMAT (very strict):
- Output ONLY JSON Lines: exactly one JSON object per line, nothing else. No markdown, no ``` fences,
  no numbering, no comments, no blank lines.
- Write 40 lines (40 cases).
- Each line has these keys:
  "id":        short unique id like "g01"
  "lang":      "en", "hi", "hinglish" or "mixed"
  "format":    "txt", "csv" or "json"
  "filename":  a file name for the record, e.g. "opd_note_ward3.txt" (may itself contain a person's name)
  "text":      the full record. For "csv" a header line plus rows; for "json" a JSON document written as
               a string. Use \n for line breaks inside the string.
  "pii":       list of {"text": ..., "type": ...} for EVERY piece of personal data in "text".
               "text" must be copied EXACTLY, character for character, from the record.
               type is one of: PATIENT_NAME, RELATIVE_NAME, OTHER_PERSON_NAME, PHONE, AADHAAR, ABHA, PAN,
               VOTER_ID, EMAIL, MRN, INSURANCE_ID, OTHER_ID, DOB, DATE, AGE, ADDRESS, VILLAGE, PIN
  "must_keep": list of strings copied EXACTLY from the record that are NOT personal data and must
               survive: medicines with dose and frequency (e.g. "Tab Dolo 650 1-0-1"), vitals
               ("BP 130/80"), lab values with units, diagnoses, ICD/SNOMED/LOINC codes, doctor names
               written as "Dr. ...", hospital names, "ASHA worker", eponyms such as "Bell's palsy".
               A must_keep string must never contain a pii string.

MAKE THEM HARD. Across the 40 cases, include all of these at least twice:
 1. Names that are also words (Asha, Kiran, Pooja, Ganga, Bharti, Bell) used both as a name and as a word.
 2. Surnames that are also medical eponyms (Bell, Wilson, Graves, Murphy) next to the real eponym.
 3. Initials-first and South Indian names (K. S. Lakshmi, R. Venkatesh), "Baby of", "B/O", "Late", Jr/Sr.
 4. Nicknames and relations in Hinglish ("Pappu bhaiya", "Munni ki mummy", "S/o", "W/o", "D/o").
 5. Devanagari names and Devanagari digits (९८७६५४३२१०).
 6. Phone numbers written in unusual ways: spaced digits, dots, dashes, +91/091 prefixes, Hindi or
    Hinglish number words ("nau aath saat ..."), English number words, a number split across a line.
 7. Personal data hidden in places people forget: the file name, a CSV column header, a JSON key, a
    URL query string, percent-encoding (%20), an HTML entity (&#97;), a base64 string.
 8. Look-alikes that are NOT personal data and must be kept: lab counts that look like PIN codes,
    "1-0-1" dose grids, batch/lot numbers, SNOMED codes, timestamps, amounts in rupees.
 9. A doctor ("Dr. ...", must be kept) in the same record as a patient or relative with a similar
    name (never the exact same name string, because a must_keep string may not contain a pii string).
10. Dates in many formats (12/03/2025, 12.3.25, 12 Mar '25, Hindi month names) and ages in words.

Before you answer, check every line: valid JSON, every pii and must_keep text appears exactly in
"text", nothing personal is missing from "pii". Then output the 40 lines only.
```
