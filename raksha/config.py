"""Policy loading: config/policy.yaml if PyYAML is present, else built-in defaults (identical values)."""
import copy
import os

DEFAULTS = {
    "date_shift": {"min_days": -180, "max_days": 180, "min_abs_days": 14},
    "age": {"band_widths": [10, 20], "topcode": 90},
    "location": {"keep_pin3_at_level": -1, "keep_district_up_to_level": 1, "tehsil": "suppress"},
    "k_anonymity": {"k": 5, "max_level": 1, "rare_diagnosis_min_level": 1},
    "linkage": {"age_veto_years": 3, "phone_degree_cap": 6, "max_block": 300, "weak_threshold": 3.0,
                "weak_same_hospital": True, "weak_attach_unique": False, "link_threshold": 7.0,
                "cluster_threshold": 5.0},
    "replacements": {"relative": "[RELATIVE]", "other_name": "[NAME]", "unlinked_patient": "[PATIENT]"},
}


def _merge(base, over):
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_policy(repo_root):
    pol = copy.deepcopy(DEFAULTS)
    path = os.environ.get("RAKSHA_POLICY") or os.path.join(repo_root, "config", "policy.yaml")
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            _merge(pol, yaml.safe_load(fh) or {})
    except Exception:
        pass
    flat = dict(pol["linkage"])
    flat.update({
        "k": pol["k_anonymity"]["k"], "max_level": pol["k_anonymity"]["max_level"],
        "rare_dx_min_level": pol["k_anonymity"]["rare_diagnosis_min_level"],
        "age_band_widths": pol["age"]["band_widths"], "age_topcode": pol["age"]["topcode"],
        "shift_lo": pol["date_shift"]["min_days"], "shift_hi": pol["date_shift"]["max_days"],
        "shift_min_abs": pol["date_shift"]["min_abs_days"],
        "pin3_level": pol["location"]["keep_pin3_at_level"],
        "district_level": pol["location"]["keep_district_up_to_level"],
        "repl": pol["replacements"],
    })
    return flat
