"""Quasi-identifier handling: truthful age bands, location tiers, k-anonymity escalation, risk metrics."""
from collections import Counter, defaultdict


def _widths(policy):
    return list(policy["age_band_widths"]) + [policy.get("suppress_band_width", 40)]


def band_range(amin, amax, level, policy):
    """Aligned band at this level's width that contains EVERY age in [amin, amax] (widened by whole
    steps when the ages straddle a boundary); top-coded. Always truthful: never excludes a true age."""
    if amin is None:
        return None
    if amax is None:
        amax = amin
    amin, amax = int(amin), int(amax)
    if amin < 0 or amax > 120 or amin > amax:
        return None
    top = policy["age_topcode"]
    if amin >= top:
        return "%d+" % top
    widths = _widths(policy)
    w = widths[min(max(level, 0), len(widths) - 1)]
    # Prefer the aligned band (0-9, 10-19 ...: most patients share it); if the patient's ages straddle
    # its edge, try the half-step band (35-44 for 10-year, 20-59 for 40-year) before widening in steps.
    step = max(1, w // 2)
    lo = (amin // w) * w
    if lo + w - 1 < amax and (amin // step) * step + w - 1 >= amax:
        lo = (amin // step) * step
    hi = lo + w - 1
    while hi < amax:
        hi += step
    if amax >= top:
        return "%d+" % lo
    return "%d-%d" % (lo, min(hi, top - 1))


def age_band(age, level, policy):
    """Band for a single age (see band_range)."""
    return band_range(age, age, level, policy)


def pin3(pin):
    return pin[:3] + "XXX" if pin and len(pin) >= 3 else None


class Planner:
    """Patient-level k-anonymity over the quasi-identifiers that are actually RELEASED.

    One level per patient (all of a patient's visits share it) and one age band per patient covering
    the ages seen across visits, so linked visits cannot be intersected into a narrower range (A4).
    Equivalence class = (released age band, sex, released geography). Patients in classes < k are
    escalated level by level up to max_level; those still < k are suppressed (geography -> state,
    widest band) when policy suppress_below_k is true, otherwise only when they also carry a rare
    diagnosis (the attacker's strongest join key).
    """

    def __init__(self, policy):
        self.p = policy
        self.k = policy["k"]
        self.rare_dx = set()
        self.suppressed = set()

    def geo(self, r, level):
        if level <= self.p.get("district_level", 1):
            g = r.get("district")
        else:
            g = None         # suppressed: only the state (or nothing) is released - matches everyone
        if g and r.get("pin") and level <= self.p.get("pin3_level", -1):
            g = g + "|" + r["pin"][:3]
        return g

    def qi(self, r, level):
        return (band_range(r.get("amin"), r.get("amax"), level, self.p), r.get("sex"), self.geo(r, level))

    @staticmethod
    def _compatible(a, b):
        return all(x is None or y is None or x == y for x, y in zip(a, b))

    def class_sizes(self, pats, keyf):
        """Patients indistinguishable from each patient on the released QIs. A QI that is not released
        (None) matches anything, as it would for an attacker. Patients with no released QI at all are
        not counted (they hide nobody). Returns {pkey: size}."""
        from itertools import combinations
        by_key = defaultdict(set)
        for r in pats:
            by_key[keyf(r)].add(r["pkey"])
        keys = [k for k in by_key if any(x is not None for x in k[:3])]
        n = len(next(iter(by_key))) if by_key else 0
        # index: for every None-pattern P of the counted keys and every subset T of P, the number of
        # patients per projection onto T (linear time instead of comparing all key pairs)
        idx = defaultdict(lambda: defaultdict(int))
        for k in keys:
            P = tuple(i for i in range(n) if k[i] is not None)
            for m in range(len(P) + 1):
                for T in combinations(P, m):
                    idx[(P, T)][tuple(k[i] for i in T)] += len(by_key[k])
        patterns = sorted({P for P, _ in idx})
        size_of = {}
        for k in by_key:
            if k not in keys:
                size_of[k] = len(by_key[k])
                continue
            F = {i for i in range(n) if k[i] is not None}
            tot = 0
            for P in patterns:
                T = tuple(i for i in P if i in F)
                tot += idx[(P, T)].get(tuple(k[i] for i in T), 0)
            size_of[k] = tot
        return {r["pkey"]: size_of[keyf(r)] for r in pats}

    def plan(self, pats):
        """pats: list of dict(pkey, amin, amax, sex, district, state, pin, dx(set), los(tuple)).
        Returns {pkey: level}; level max_level+1 == suppressed."""
        maxlvl = self.p["max_level"]
        self.max_level = maxlvl + 1
        level = {r["pkey"]: 0 for r in pats}
        dx_count = defaultdict(set)
        for r in pats:
            for d in r.get("dx", ()):
                dx_count[d].add(r["pkey"])
        self.rare_dx = {d for d, s in dx_count.items() if len(s) < self.k}
        for r in pats:
            if any(d in self.rare_dx for d in r.get("dx", ())):
                level[r["pkey"]] = max(level[r["pkey"]], min(self.p["rare_dx_min_level"], maxlvl))

        demo = lambda r: self.qi(r, level[r["pkey"]])
        for _ in range(maxlvl + 1):
            c = self.class_sizes(pats, demo)
            changed = False
            for r in pats:
                if c[r["pkey"]] < self.k and level[r["pkey"]] < maxlvl:
                    level[r["pkey"]] += 1
                    changed = True
            if not changed:
                break
        c = self.class_sizes(pats, demo)
        cf = self.class_sizes(pats, lambda r: demo(r) + (tuple(sorted(r.get("dx", ()))), r.get("los")))
        for r in pats:
            small = c[r["pkey"]] < self.k
            mode = self.p.get("rare_dx_suppress", "unique_with_facts")
            has_rare = any(d in self.rare_dx for d in r.get("dx", ()))
            rare = has_rare and ((mode == "unique_with_facts" and cf[r["pkey"]] < self.k) or (mode == "small_class" and small))
            if (small and self.p.get("suppress_below_k")) or rare:
                self.suppressed.add(r["pkey"])
                level[r["pkey"]] = self.max_level
        return level

    def risk(self, pats, level):
        """Prosecutor risk 1/|EC| per patient over released QIs (and + diagnosis + LOS)."""
        scored = [r for r in pats if any(r.get(f) is not None for f in ("amin", "sex", "district"))]

        def metrics(keyf):
            if not scored:
                return {"avg_risk": 0.0, "max_risk": 0.0, "share_below_k": 0.0, "min_class": 0}
            c = self.class_sizes(scored, keyf)
            risks = [1.0 / max(1, c[r["pkey"]]) for r in scored]
            return {"avg_risk": round(sum(risks) / len(risks), 4), "max_risk": round(max(risks), 4),
                    "share_below_k": round(sum(1 for r in scored if c[r["pkey"]] < self.k) / len(scored), 4),
                    "min_class": min(c.values())}

        base = metrics(lambda r: ("%s-%s" % (r["amin"], r["amax"]) if r.get("amin") is not None else None, r.get("sex"),
                                  "|".join(x for x in (r.get("district"), r.get("village"), r.get("pin")) if x) or None))
        demo = metrics(lambda r: self.qi(r, level[r["pkey"]]))
        facts = metrics(lambda r: self.qi(r, level[r["pkey"]]) + (tuple(sorted(r.get("dx", ()))), r.get("los")))
        return {"k": self.k, "unit": "patient", "patients": len(pats), "patients_with_qi": len(scored), "before_generalization": base,
                "after_demographic_qi": demo, "after_with_diagnosis_and_los": facts,
                "rare_diagnoses": len(self.rare_dx), "suppressed_patients": len(self.suppressed),
                "levels": dict(sorted(Counter(level.values()).items()))}
