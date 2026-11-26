"""Policy loading: config/policy.yaml parsed by a tiny built-in YAML-subset reader (nested mappings,
scalars, inline lists, comments), so the result never depends on whether PyYAML is installed."""
import copy
import os
import re

DEFAULTS = {
    "date_shift": {"min_days": -180, "max_days": 180, "min_abs_days": 14},
    "age": {"band_widths": [10, 20], "topcode": 90, "suppressed_band_width": 40},
    "location": {"keep_pin3_at_level": -1, "keep_district_up_to_level": 1, "village_to": "district"},
    "k_anonymity": {"k": 5, "max_level": 1, "rare_diagnosis_min_level": 1, "suppress_below_k": False,
                    "rare_diagnosis_suppress": "unique_with_facts"},
    "linkage": {"age_veto_years": 3, "phone_degree_cap": 6, "max_block": 300, "weak_threshold": 3.0,
                "weak_same_hospital": True, "weak_attach_unique": False},
    "replacements": {"relative": "[RELATIVE]", "other_name": "[NAME]", "unlinked_patient": "[PATIENT]"},
}


def _merge(base, over):
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def _scalar(v):
    v = v.strip()
    if not v:
        return None
    if v[0] in "\"'" and v[-1] == v[0]:
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        return [_scalar(x) for x in v[1:-1].split(",") if x.strip()]
    if v.startswith("{") and v.endswith("}"):
        out = {}
        for part in v[1:-1].split(","):
            if ":" in part:
                k, x = part.split(":", 1)
                out[k.strip()] = _scalar(x)
        return out
    low = v.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"[-+]?\d+", v):
        return int(v)
    if re.fullmatch(r"[-+]?\d*\.\d+(?:[eE][-+]?\d+)?", v):
        return float(v)
    return v


def parse_yaml_subset(text):
    """Indentation-based mappings with scalar / inline-list values (what policy.yaml uses)."""
    root = {}
    stack = [(-1, root)]
    for raw in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip(" "))
        key, _, val = line.strip().partition(":")
        while stack and stack[-1][0] >= ind:
            stack.pop()
        parent = stack[-1][1]
        if val.strip() == "":
            parent[key.strip()] = {}
            stack.append((ind, parent[key.strip()]))
        else:
            parent[key.strip()] = _scalar(val)
    return root


def load_policy(repo_root):
    pol = copy.deepcopy(DEFAULTS)
    path = os.environ.get("RAKSHA_POLICY") or os.path.join(repo_root, "config", "policy.yaml")
    try:
        with open(path, encoding="utf-8") as fh:
            _merge(pol, parse_yaml_subset(fh.read()))
    except OSError:
        pass
    flat = dict(pol["linkage"])
    flat.update({
        "k": pol["k_anonymity"]["k"], "max_level": pol["k_anonymity"]["max_level"],
        "rare_dx_min_level": pol["k_anonymity"]["rare_diagnosis_min_level"],
        "age_band_widths": pol["age"]["band_widths"], "age_topcode": pol["age"]["topcode"],
        "suppress_band_width": pol["age"].get("suppressed_band_width", 40),
        "rare_dx_suppress": pol["k_anonymity"].get("rare_diagnosis_suppress", "unique_with_facts"),
        "suppress_below_k": bool(pol["k_anonymity"].get("suppress_below_k", False)),
        "village_to": pol["location"].get("village_to", "district"),
        "shift_lo": pol["date_shift"]["min_days"], "shift_hi": pol["date_shift"]["max_days"],
        "shift_min_abs": pol["date_shift"]["min_abs_days"],
        "pin3_level": pol["location"]["keep_pin3_at_level"],
        "district_level": pol["location"]["keep_district_up_to_level"],
        "repl": pol["replacements"],
    })
    return flat
