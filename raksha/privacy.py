"""Quasi-identifier handling: truthful age bands, location tiers, k-anonymity escalation, risk metrics."""
from collections import Counter, defaultdict


def age_band(age, level, policy):
    """Band that always contains the true age; width per level from policy (+40y when suppressed); top-coded."""
    if age is None:
        return None
    top = policy["age_topcode"]
    if age >= top:
        return "%d+" % top
    widths = list(policy["age_band_widths"]) + [40]
    width = widths[min(level, len(widths) - 1)]
    lo = (int(age) // width) * width
    hi = min(lo + width - 1, top - 1)
    return "%d-%d" % (lo, hi)


def pin3(pin):
    return pin[:3] + "XXX" if pin and len(pin) >= 3 else None


class Planner:
    """Decides a generalisation level per record so every equivalence class has >= k patients."""

    def __init__(self, policy):
        self.p = policy
        self.k = policy["k"]

    def _qi(self, r, level):
        geo = r.get("district") if level <= self.p.get("district_level", 2) else r.get("state")
        if level == 0 and r.get("pin"):
            geo = (geo or "") + "|" + r["pin"][:3]
        return (age_band(r.get("age"), level, self.p), r.get("sex"), geo)

    def plan(self, recs):
        """recs: list of dict(rid, pkey, age, sex, district, state, pin, dx, los). Returns {rid: level}."""
        maxlvl = self.p["max_level"]
        level = {r["rid"]: 0 for r in recs}
        dx_count = defaultdict(set)
        for r in recs:
            for d in r.get("dx", ()):
                dx_count[d].add(r["pkey"])
        rare_dx = {d for d, s in dx_count.items() if len(s) < self.k}
        for r in recs:
            if any(d in rare_dx for d in r.get("dx", ())):
                level[r["rid"]] = max(level[r["rid"]], self.p["rare_dx_min_level"])
        for _ in range(maxlvl + 1):
            classes = defaultdict(set)
            for r in recs:
                classes[(level[r["rid"]],) + self._qi(r, level[r["rid"]])].add(r["pkey"])
            changed = False
            for r in recs:
                key = (level[r["rid"]],) + self._qi(r, level[r["rid"]])
                if len(classes[key]) < self.k and level[r["rid"]] < maxlvl:
                    level[r["rid"]] += 1
                    changed = True
            if not changed:
                break
        self.rare_dx = rare_dx
        # suppression: records with a rare diagnosis that are STILL unique in the attacker view
        # (demographics + diagnosis + length of stay) lose district/PIN and get a 40-year band.
        self.max_level = maxlvl + 1
        self.suppressed = set()
        classes = defaultdict(set)
        keyf = lambda r: (level[r["rid"]],) + self._qi(r, level[r["rid"]]) + (tuple(sorted(r.get("dx", ()))), r.get("los"))
        for r in recs:
            classes[keyf(r)].add(r["pkey"])
        for r in recs:
            if any(d in rare_dx for d in r.get("dx", ())) and len(classes[keyf(r)]) < self.k:
                self.suppressed.add(r["rid"])
                level[r["rid"]] = self.max_level
        return level

    def risk(self, recs, level):
        """Re-identification risk over released QIs (patient-level equivalence classes).

        prosecutor risk per record = 1 / |EC|. Reports average, max, share of records with |EC| < k,
        both for demographic QIs only and for the attacker-knowledge view (+ diagnosis + LOS).
        """
        def metrics(keyf):
            classes = defaultdict(set)
            for r in recs:
                classes[keyf(r)].add(r["pkey"])
            if not recs:
                return {"avg_risk": 0.0, "max_risk": 0.0, "share_below_k": 0.0, "min_class": 0}
            risks = [1.0 / len(classes[keyf(r)]) for r in recs]
            below = sum(1 for r in recs if len(classes[keyf(r)]) < self.k)
            return {"avg_risk": round(sum(risks) / len(risks), 4), "max_risk": round(max(risks), 4),
                    "share_below_k": round(below / len(recs), 4), "min_class": min(len(v) for v in classes.values())}

        base = metrics(lambda r: (r.get("age"), r.get("sex"), r.get("village") or r.get("district"), r.get("pin")))
        demo = metrics(lambda r: (level[r["rid"]],) + self._qi(r, level[r["rid"]]))
        facts = metrics(lambda r: (level[r["rid"]],) + self._qi(r, level[r["rid"]]) + (tuple(sorted(r.get("dx", ()))), r.get("los")))
        return {"k": self.k, "before_generalization": base, "after_demographic_qi": demo,
                "after_with_diagnosis_and_los": facts, "rare_diagnoses": len(self.rare_dx),
                "levels": dict(sorted(Counter(level.values()).items()))}
