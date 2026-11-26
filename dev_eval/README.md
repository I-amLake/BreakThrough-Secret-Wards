# dev_eval/ — development evaluation only

These scripts measure the pipeline during development. **They are never imported or run by
`main.py` or anything under `raksha/`** (asserted by `tests/test_isolation.py`, which also checks at
run time that the pipeline opens no answer-key or attacker file).

| script | what it does | reads |
|---|---|---|
| `gen_data.py` | synthetic multi-hospital generator with its own ground truth | nothing (writes a synthetic set) |
| `evaluate.py` | leaks, clinical preservation, linkage, determinism on a synthetic set | the synthetic set's `truth.json` |
| `attack_eval.py` | approximation of the kit's registry attacker on an output folder | practice answer key + attacker registry (kit) |
| `validate_output.py` | minimal mirror of the output contract | input + output folders |

The practice answer key and attacker registry are evaluation material, not runtime input; nothing
derived from them (names, IDs, places, thresholds) is stored in this repository.
