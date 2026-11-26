"""Cross-script, conservative record linkage.

* Every record is reduced to an IdentityProfile (folded name tokens, initials, relatives,
  phones, government/hospital IDs, birth-year estimate, sex, PIN/district, hospital).
* Multi-key blocking: strong IDs, phone, (rarest name skeleton, sex), (given name, relative name).
* Pairwise score = Fellegi-Sunter style log-odds sum with IDF-weighted name agreement and
  HARD VETOES (different Aadhaar/ABHA/PAN, opposite sex, birth years more than age_veto_years (3) apart, different
  spouse/parent with clearly different names, conflicting DOB).
* Clustering: linkable edges in descending score order (deterministic ties); two clusters merge only
  if NO cross pair between them is vetoed (complete-link veto check: no transitive bridging).
* Weak fragments (first name only, nothing else) attach only to exactly ONE compatible cluster in
  the same hospital; otherwise they get patient = null.
"""
import functools
from array import array
import math
from collections import defaultdict


class JaroWinkler:
    """Pure-Python Jaro-Winkler. Deliberately the ONLY implementation (no RapidFuzz switch), so the
    result is identical on every interpreter and with or without optional packages installed."""
    @staticmethod
    def similarity(a, b):
        if a == b:
            return 1.0
        la, lb = len(a), len(b)
        if not la or not lb:
            return 0.0
        md = max(la, lb) // 2 - 1
        ma, mb = [False] * la, [False] * lb
        m = 0
        for i in range(la):
            for j in range(max(0, i - md), min(lb, i + md + 1)):
                if not mb[j] and a[i] == b[j]:
                    ma[i] = mb[j] = True
                    m += 1
                    break
        if not m:
            return 0.0
        t, k = 0, 0
        for i in range(la):
            if ma[i]:
                while not mb[k]:
                    k += 1
                t += a[i] != b[k]
                k += 1
        jaro = (m / la + m / lb + (m - t / 2) / m) / 3
        pre = 0
        for x, y in zip(a[:4], b[:4]):
            if x != y:
                break
            pre += 1
        return jaro + pre * 0.1 * (1 - jaro)

from .translit import skeleton

STRONG_ID = ("AADHAAR", "ABHA", "PAN")


class Profile:
    __slots__ = ("rid", "hospital", "names", "initials", "rels", "phones", "ids", "byears", "sex", "pins",
                 "districts", "weak", "has_identity", "dobs", "villages")

    def __init__(self, rid, hospital):
        self.rid = rid
        self.hospital = hospital
        self.names = []        # list of folded token tuples (one per name mention)
        self.initials = set()
        self.rels = []         # (canon, folded token tuple)
        self.phones = set()
        self.ids = defaultdict(set)
        self.byears = []
        self.sex = None
        self.pins = set()
        self.districts = set()
        self.weak = True
        self.has_identity = False
        self.dobs = set()
        self.villages = set()

    def finalize(self):
        toks = {t for n in self.names for t in n}
        full = any(len(n) >= 2 for n in self.names)
        strong = bool(self.phones or any(self.ids.values()))
        self.has_identity = bool(toks or strong)
        self.weak = not (full or strong or (toks and (self.rels or self.byears)))


@functools.lru_cache(maxsize=65536)
def _tok_sim(a, b):
    if a == b:
        return 1.0
    if len(a) == 1 or len(b) == 1:
        return 0.9 if a[0] == b[0] else 0.0
    if skeleton(a) == skeleton(b) and len(a) > 2:
        return 0.93
    return JaroWinkler.similarity(a, b)


# folded honorific-like or very common second names that do not distinguish people
_GENERIC_SURNAME = {"devi", "dev", "kumari", "kumar", "singh", "sing", "kaur", "bai", "begum", "bano", "katun", "katoon",
                    "bibi", "lal", "prasad", "prasd", "ram", "das", "nat", "cand", "kumr"}


class Linker:
    def __init__(self, policy, log=None):
        self.p = policy
        self.log = log
        self.idf = {}

    # ------------------------------------------------------------- name comparison
    def _name_pair(self, n1, n2):  # noqa: C901
        """Compare two token tuples. Returns (score_in_logodds, compatible_bool, level)."""
        if not n1 or not n2:
            return 0.0, True, 0
        full1 = [t for t in n1 if len(t) > 1]
        full2 = [t for t in n2 if len(t) > 1]
        if not full1 or not full2:
            return 0.0, True, 0
        used = set()
        matched_w = 0.0
        matched = 0
        for t in full1:
            best, bj = 0.0, None
            for j, u in enumerate(full2):
                if j in used:
                    continue
                s = _tok_sim(t, u)
                if s > best:
                    best, bj = s, j
            if bj is not None and best >= 0.88:
                used.add(bj)
                matched += 1
                matched_w += self.idf.get(t, 3.0) * (1.0 if best >= 0.97 else 0.8)
        # initials compatibility: "T. Durovan" vs "Thivaresh Durovan"
        ini1 = [t for t in n1 if len(t) == 1]
        ini2 = [t for t in n2 if len(t) == 1]
        un2 = [u for j, u in enumerate(full2) if j not in used]
        un1 = [t for t in full1 if not any(_tok_sim(t, u) >= 0.88 for u in full2)]
        # an initial is fine when it matches a leftover token / initial, or when the other name simply
        # stops earlier ("Tarachand R" vs "Tarachand": nothing on the other side to disagree with)
        ini_ok = all(any(u[0] == i for u in un2) or i in ini2 or (not un2 and not ini2) for i in ini1) and \
            all(any(t[0] == i for t in un1) or i in ini1 or (not un1 and not ini1) for i in ini2)
        if matched == 0:
            # "T Rawat" vs "Tarachand R", "Tarachand" vs "T Rawat": full tokens explained by the other side's initials,
            # with unexplained full tokens left on at most one side
            ex1 = [t for t in full1 if any(t[0] == i for i in ini2)]
            ex2 = [u for u in full2 if any(u[0] == i for i in ini1)]
            left1 = [t for t in full1 if t not in ex1]
            left2 = [u for u in full2 if u not in ex2]
            if (ex1 or ex2) and not (left1 and left2) and ini_ok:
                return 0.5, True, 0
            return -6.0, False, 0
        # given-name disagreement with a surname match (Thivaresh Durovan vs Kelvansh Durovan) is a mismatch
        if matched >= 1 and un1 and un2:
            g1, g2 = full1[0], full2[0]
            if _tok_sim(g1, g2) < 0.8 and g1 in un1 and g2 in un2:
                return -5.0, False, 0
            # surname disagreement with a given-name match (Thivaresh Durovan vs Thivaresh Kalvoti)
            l1, l2 = full1[-1], full2[-1]
            if len(full1) >= 2 and len(full2) >= 2 and l1 in un1 and l2 in un2 and _tok_sim(l1, l2) < 0.8 \
                    and l1 not in _GENERIC_SURNAME and l2 not in _GENERIC_SURNAME:
                return -5.0, False, 0
        level = 3 if matched >= 2 else (2 if (len(full1) == 1 or len(full2) == 1) else 1)
        score = min(5.0, matched_w)
        if not ini_ok:
            score -= 4.0
        return score, ini_ok or matched >= 2, level

    def name_score(self, a, b):
        best = (-6.0, False, 0)
        if not a.names or not b.names:
            return 0.0, True, 0
        for n1 in a.names[:4]:
            for n2 in b.names[:4]:
                r = self._name_pair(n1, n2)
                if r[0] > best[0]:
                    best = r
        return best

    # ------------------------------------------------------------- pair decision
    def score(self, a, b):
        """Return (score, veto, linkable).

        Linkable only with (1) a shared exact identifier, (2) a shared phone plus compatible names,
        or (3) matching names plus a second clue (same DOB, same relative, or same village/PIN with
        birth years within 1). A name alone never links (homonyms)."""
        for k in STRONG_ID:
            x, y = a.ids.get(k), b.ids.get(k)
            if x and y and not (x & y):
                return -99.0, True, False
        if a.sex and b.sex and a.sex != b.sex:
            return -99.0, True, False
        d = None
        if a.byears and b.byears:
            d = min(abs(x - y) for x in a.byears for y in b.byears)
            if d > self.p["age_veto_years"]:
                return -99.0, True, False
        if a.dobs and b.dobs and not (a.dobs & b.dobs):
            return -99.0, True, False
        shared_id = [k for k in a.ids if b.ids.get(k) and (a.ids[k] & b.ids[k])]
        ns, ncompat, level = self.name_score(a, b)
        both_named = bool(a.names and b.names)
        if both_named and not ncompat and not any(k in STRONG_ID for k in shared_id):
            return -99.0, True, False
        rel_match = False
        for c1, n1 in a.rels:
            for c2, n2 in b.rels:
                if not n1 or not n2:
                    continue
                r, comp, _ = self._name_pair(n1, n2)
                if comp and r > 0 and (c1 == c2 or "G" in (c1, c2) or {c1, c2} <= {"P", "PM"} or "C" in (c1, c2)):
                    rel_match = True
                elif c1 == c2 and c1 in ("P", "SP") and not comp:
                    return -99.0, True, False  # same relation (father / spouse) with a different name
        phone_shared = bool(a.phones & b.phones)
        place = bool((a.pins & b.pins) or (a.villages & b.villages))
        dob_same = bool(a.dobs & b.dobs)
        s = ns
        s += 12.0 * len(shared_id) + (5.0 if phone_shared else 0.0) + (4.0 if rel_match else 0.0)
        s += (3.0 if dob_same else 0.0) + (1.5 if place else 0.0) + ((2.0 if d <= 1 else 0.0) if d is not None else 0.0)
        name_ok = both_named and ncompat and level >= 1
        given_ok = both_named and ncompat and ns > 0
        linkable = False
        if shared_id and (not both_named or ncompat or any(k in STRONG_ID for k in shared_id)):
            linkable = True
        elif phone_shared and given_ok and (d is None or d <= 2):
            linkable = True
        elif name_ok and (dob_same or rel_match or (place and d is not None and d <= 1)):
            linkable = True
        elif given_ok and rel_match and (d is None or d <= 2):
            linkable = True  # fragment: "Gonavati, W/o Kelvansh"
        return s, False, linkable

    # ------------------------------------------------------------- blocking
    def _blocks(self, profs):
        blocks = defaultdict(list)
        df = defaultdict(int)
        for p in profs:
            for t in {t for n in p.names for t in n if len(t) > 1}:
                df[t] += 1
        n = max(1, len(profs))
        self.idf = {t: min(6.0, 1.0 + math.log(n / c)) for t, c in df.items()}
        phone_deg = defaultdict(int)
        for p in profs:
            for ph in p.phones:
                phone_deg[ph] += 1
        single = set()  # skeletons of one-token names ("Gonavati ji"): full names must meet these fragments
        for p in profs:
            for nm in p.names:
                full = [t for t in nm if len(t) > 1]
                if len(full) == 1:
                    single.add(skeleton(full[0]))
        for p in profs:
            keys = set()
            for k in ("AADHAAR", "ABHA", "PAN", "MRN", "INSURANCE"):
                for v in p.ids.get(k, ()):
                    keys.add((k, v))
            for ph in p.phones:
                if phone_deg[ph] <= self.p["phone_degree_cap"]:
                    keys.add(("PH", ph))
            for nm in p.names:
                full = [t for t in nm if len(t) > 1]
                sexes = (p.sex, "?") if p.sex else ("?",)
                if len(full) >= 2:
                    # given + family name block (much smaller than a block per token)
                    for sx in sexes:
                        keys.add(("SK", skeleton(full[0]) + "|" + skeleton(full[-1]), sx))
                for t in full:
                    if len(full) == 1 or skeleton(t) in single:
                        for sx in sexes:
                            keys.add(("SK", skeleton(t), sx))
                for c, rn in p.rels:
                    rf = [t for t in rn if len(t) > 1]
                    if full and rf:
                        keys.add(("REL", skeleton(full[0]), skeleton(rf[0])))
            for k in keys:
                blocks[k].append(p.rid)
        return blocks

    # ------------------------------------------------------------- clustering
    def link(self, profs):
        """profs: list of Profile (rid = index). Returns list cluster_id or None per rid."""
        for p in profs:
            p.finalize()
        byid = {p.rid: p for p in profs}
        blocks = self._blocks(profs)
        cap = self.p["max_block"]
        N = len(profs) + 1
        pairs = set()   # pair keys a * N + b (ints, not tuples: memory)
        for key in sorted(blocks, key=lambda k: tuple(str(x) for x in k)):
            ids = sorted(set(blocks[key]))
            if len(ids) > cap:
                if key[0] == "SK":
                    continue
                ids = ids[:cap]
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    pairs.add(ids[i] * N + ids[j])
        # only the veto bit of a scored pair is needed later (cluster merges check vetoes)
        # Scores are sums of a few fixed weights, so few distinct values: bucket the edge keys by
        # score in compact int arrays (keys arrive ascending = (a, b) order). Iterating buckets by
        # descending score gives exactly the order of sorting (-score, a, b) tuples, in ~8 B/edge.
        scored, vetoed = pairs, set()
        buckets = defaultdict(lambda: array("q"))
        n_edges = 0
        for key in sorted(pairs):
            a, b = divmod(key, N)
            sc, veto, ok = self.score(byid[a], byid[b])
            if veto:
                vetoed.add(key)
            elif ok:
                buckets[sc].append(key)
                n_edges += 1
        n_pairs = len(pairs)

        def edges():
            for sc in sorted(buckets, reverse=True):
                for key in buckets[sc]:
                    a, b = divmod(key, N)
                    yield -sc, a, b
        parent = {p.rid: p.rid for p in profs}
        members = {p.rid: [p.rid] for p in profs}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        # linkable neighbours per record, packed (CSR: offsets + one int array, ~8 B per edge end)
        deg = array("q", [0]) * (N + 1)
        for sc in buckets:
            for key in buckets[sc]:
                a, b = divmod(key, N)
                deg[a + 1] += 1
                deg[b + 1] += 1
        for i in range(1, N + 1):
            deg[i] += deg[i - 1]
        nbr = array("q", [0]) * deg[N]
        fill = array("q", deg)
        for sc in sorted(buckets, reverse=True):
            for key in buckets[sc]:
                a, b = divmod(key, N)
                nbr[fill[a]] = b
                fill[a] += 1
                nbr[fill[b]] = a
                fill[b] += 1
        del fill

        def vetoed_pair(a, b):
            a, b = (a, b) if a < b else (b, a)
            k = a * N + b
            if k not in scored:
                scored.add(k)
                if self.score(byid[a], byid[b])[1]:
                    vetoed.add(k)
            return k in vetoed

        def clusters_vetoed(r1, r2):
            return any(vetoed_pair(x, y) for x in members[r1] for y in members[r2])

        def ambiguous(x):
            """Homonym guard: a lone record linkable to two clusters that are provably different people
            (a veto between them, e.g. same name but different father) cannot be assigned: abstain."""
            roots = sorted({find(c) for c in nbr[deg[x]:deg[x + 1]]} - {find(x)})[:12]
            return any(clusters_vetoed(roots[i], roots[j]) for i in range(len(roots)) for j in range(i + 1, len(roots)))

        for negsc, a, b in edges():
            ra, rb = find(a), find(b)
            if ra == rb:
                continue
            # (only for name-based edges: a shared exact ID or phone is not a homonym question)
            pa, pb = byid[a], byid[b]
            hard = bool(pa.phones & pb.phones) or any(pb.ids.get(k) and (v & pb.ids[k]) for k, v in pa.ids.items())
            if not hard and ((len(members[ra]) == 1 and ambiguous(a)) or (len(members[rb]) == 1 and ambiguous(b))):
                continue
            ok = True
            for x in members[ra]:
                for y in members[rb]:
                    if vetoed_pair(x, y):
                        ok = False
                        break
                if not ok:
                    break
            if not ok:
                continue
            if len(members[ra]) < len(members[rb]) or (len(members[ra]) == len(members[rb]) and rb < ra):
                ra, rb = rb, ra
            parent[rb] = ra
            members[ra].extend(members[rb])
            members[ra].sort()
            del members[rb]
        # weak fragments: attach to exactly one compatible cluster in the same hospital
        assign = {}
        for p in profs:
            if not p.has_identity:
                assign[p.rid] = None
            elif not p.weak or len(members.get(find(p.rid), ())) > 1:
                assign[p.rid] = find(p.rid)
        roots = sorted(members)
        given_index = defaultdict(set)
        for r in roots:
            for rid in members[r]:
                q = byid[rid]
                if q.weak:
                    continue
                for nm in q.names:
                    full = [t for t in nm if len(t) > 1]
                    if full:
                        given_index[skeleton(full[0])].add(r)
        for p in profs:
            if p.rid in assign:
                continue
            cands = set()
            for nm in p.names:
                full = [t for t in nm if len(t) > 1]
                if full:
                    cands |= given_index.get(skeleton(full[0]), set())
            good = []
            for r in sorted(cands):
                mem = [byid[x] for x in members[r] if not byid[x].weak]
                if not mem:
                    continue
                if self.p["weak_same_hospital"] and not any(m.hospital == p.hospital for m in mem):
                    continue
                okc, tot, lk = True, 0.0, False
                for m in mem:
                    sc, veto, ok = self.score(p, m)
                    if veto:
                        okc = False
                        break
                    tot = max(tot, sc)
                    lk = lk or ok
                if okc and (lk or (self.p["weak_attach_unique"] and tot >= self.p["weak_threshold"])):
                    good.append(r)
            assign[p.rid] = good[0] if len(good) == 1 else None
        self.stats = {"edges": n_edges, "pairs": n_pairs}
        return [assign[p.rid] for p in profs], members
