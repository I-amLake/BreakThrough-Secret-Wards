"""Two-pass pipeline: ingest+detect+extract -> link -> privacy plan -> rewrite+sweep -> report."""
import hashlib
import json
import os
import re
import sys
import time
from collections import defaultdict

from . import core, handlers, ingest
from .detect import Detector, PII_KINDS
from .ingest import BinaryFile, EmptyFile, FhirInvalid, GarbledText, Unsupported
from .linkage import Linker
from .privacy import Planner, band_range
from .secure import SafeLog, error_category, sha256_bytes
from .translit import devanagari_to_latin, fold, has_devanagari, name_tokens, skeleton

GENERIC_TOKENS = {"kumar", "devi", "ji", "md", "mohd", "mohammad", "bai", "begum", "bano", "kumari", "singh", "kaur",
                  "lal", "prasad", "ram", "khan", "sahab", "shri", "smt"}


class Doc:
    def __init__(self, rel, data):
        self.rel = rel
        self.data = data
        self.sha = sha256_bytes(data)
        self.kind = None
        self.text = None
        self.obj = None
        self.units = []
        self.status = None
        self.reason = None
        self.out_rel = None
        self.hospital = None
        self.header_changed = False
        self.output = None


def peak_rss_mb():
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rc = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        r = max(r, rc)
        if sys.platform == "darwin":
            return round(r / (1024.0 * 1024.0), 1)  # bytes on macOS
        return round(r / 1024.0, 1)  # kilobytes on Linux
    except Exception:
        return 0.0


class Engine:
    def __init__(self, policy, keyring, log=None):
        self.policy = policy
        self.keys = keyring
        self.log = log or SafeLog()
        self.dyn = set()
        self.detector = Detector(self.dyn)
        self.entities = defaultdict(int)
        self.ids_detected = 0
        self.order_votes = defaultdict(lambda: [0, 0])
        self.token_df = defaultdict(int)
        self.n_docs = 0
        self.safe_file_tokens = set()
        self.current_patient_refs = set()

    # ------------------------------------------------------------ helpers used by handlers
    def count_ids(self, n):
        self.ids_detected += n

    def _source_tokens(self, doc):
        toks = set(re.findall(r"[a-z]{4,}", doc.rel.lower()))
        if doc.text:
            first = doc.text.strip().split("\n", 1)[0][:120].lower()
            toks |= set(re.findall(r"[a-z]{4,}", first))
        return toks

    def source_order(self, doc):
        """Day/month order for a file whose own dates are all ambiguous: votes of files from the same
        source (shared file-name / header tokens such as a hospital code). Words common to most files
        ("discharge", "summary") are not a source and do not vote; no evidence -> DMY (Indian default)."""
        dv = mv = 0
        cap = max(3, int(0.4 * max(1, self.n_docs)))
        for t in sorted(self._source_tokens(doc)):
            if self.token_df.get(t, 0) > cap:
                continue
            a, b = self.order_votes.get(t, (0, 0))
            dv += a
            mv += b
        return "mdy" if mv > dv else "dmy"

    def doc_order(self, doc):
        if getattr(doc, "_order", None):
            return doc._order
        from .dates import numeric_order_votes
        dv, mv = numeric_order_votes(doc.text or "")
        doc._order = "mdy" if mv > dv else ("dmy" if dv > mv else self.source_order(doc))
        return doc._order

    def doc_year(self, doc):
        m = re.findall(r"(?<!\d)(19\d{2}|20\d{2})(?!\d)", doc.text or "")
        if m:
            return int(max(set(m), key=m.count))
        return self.ref_year

    def unit_ctx(self, doc, unit):
        return core.Ctx(self, unit)

    def file_ctx(self, doc):
        if len(doc.units) == 1:
            return core.Ctx(self, doc.units[0])
        p = self.policy
        return core.Ctx(self, None, shift=self.keys.shift_days("file|" + doc.sha, p["shift_lo"], p["shift_hi"], p["shift_min_abs"]))

    # ------------------------------------------------------------ pass 0: load
    def load(self, root):
        docs = []
        for rel in ingest.walk(root):
            try:
                with open(os.path.join(root, rel), "rb") as fh:
                    data = fh.read()
            except OSError:
                data = b""
            d = Doc(rel, data)
            docs.append(d)
            try:
                d.text = ingest.decode(data)
                d.kind = ingest.sniff_kind(rel, d.text)
                if d.kind == "json":
                    d.obj = ingest.parse_json(d.text)
                    if ingest.is_fhir(d.obj):
                        ingest.check_fhir(d.obj)
                        d.kind = "fhir"
                elif d.kind == "ndjson":
                    raise Unsupported()
                elif d.kind == "text" and re.search(r"<\?xml|<ClinicalDocument|<html", d.text[:500], re.I):
                    raise Unsupported()
                d.status = "ok"
            except (Unsupported, BinaryFile, EmptyFile, GarbledText, FhirInvalid, ValueError, RecursionError,
                    UnicodeDecodeError, MemoryError) as exc:
                self._quarantine(d, exc)
            d.hospital = self._hospital(d)
        return docs

    def _quarantine(self, d, exc):
        if os.environ.get("RAKSHA_DEBUG") == "1":  # developer-only; never set in evaluation
            import traceback
            traceback.print_exc()
        d.status = "quarantined"
        d.reason = error_category(exc)
        d.text = None
        d.obj = None

    def _hospital(self, d):
        txt = (d.text or "")[:400]
        m = re.search(r"([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3})\s+(?:Hospital|Sadan|Multispeciality|Charitable|Clinic|Nursing Home)", txt)
        if m:
            return fold(m.group(1).split()[0])
        if d.obj is not None and isinstance(d.obj, dict):
            s = json.dumps(d.obj, ensure_ascii=False)[:600]
            m = re.search(r'"(?:hospital|facility|name)"\s*:\s*"([A-Z][A-Za-z]+)', s)
            if m:
                return fold(m.group(1))
        m = re.match(r"(?:rx_|nursing_)?([a-z]{4,})", d.rel.rsplit("/", 1)[-1].lower())
        return m.group(1) if m else None

    # ------------------------------------------------------------ lexicon harvest (runtime, from this input only)
    def harvest(self, docs):
        from .schema import classify_label
        lex = self.detector.lex
        found = []

        def add(v):
            for t in re.findall(r"[A-Za-z]{3,}|[\u0900-\u0963\u0970-\u097F]{2,}", str(v)):
                f = fold(name_tokens(t)[0]) if name_tokens(t) else ""
                if len(f) >= 3 and f not in GENERIC_TOKENS and not lex.is_medical(t) and not lex.is_stop(t):
                    found.append(f)

        def walk(node, parent=None, depth=0):
            if depth > 40:
                return
            if isinstance(node, dict):
                parent = handlers._dict_ctx(node, parent)
                for k, v in node.items():
                    t = handlers._key_type(k, parent)
                    if isinstance(v, (dict, list)):
                        walk(v, handlers._child_ctx(k, t, parent), depth + 1)
                    elif t in ("name", "first_name", "last_name", "relative") and isinstance(v, str):
                        add(v)
            elif isinstance(node, list):
                for el in node:
                    walk(el, parent, depth + 1)

        self.n_docs = len(docs)
        for d in docs:
            if d.status != "ok":
                continue
            if d.kind == "csv":
                try:
                    handlers.csv_prepare(d, self)
                except Exception as exc:
                    self._quarantine(d, exc)
                    continue
                for ci, t in enumerate(d.types):
                    if t in ("name", "first_name", "last_name", "relative"):
                        for r in d.rows:
                            add(r[ci])
            elif d.kind == "json":
                walk(d.obj)
            elif d.kind == "fhir":
                for r in handlers._resources(d.obj):
                    if r.get("resourceType") in ("Patient", "RelatedPerson"):
                        for n in r.get("name", []) or []:
                            if isinstance(n, dict):
                                add(n.get("text", "") + " " + " ".join(n.get("given", []) or []) + " " + str(n.get("family", "")))
                        for c in r.get("contact", []) or []:
                            if isinstance(c, dict) and isinstance(c.get("name"), dict):
                                add(c["name"].get("text", ""))
            if d.text:
                from .dates import numeric_order_votes
                dv, mv = numeric_order_votes(d.text)
                for t in self._source_tokens(d):
                    self.token_df[t] += 1
                if dv or mv:
                    for t in self._source_tokens(d):
                        self.order_votes[t][0] += dv
                        self.order_votes[t][1] += mv
        self.dyn.update(found)
        # filename tokens common to many files are structure words, not names
        cnt = defaultdict(int)
        for d in docs:
            for t in set(re.findall(r"[a-z]{3,}", d.rel.lower())):
                cnt[t] += 1
        self.safe_file_tokens = {t for t, c in cnt.items() if c >= 3}

    # ------------------------------------------------------------ pass 1: extract
    def extract(self, docs):
        years = []
        for d in docs:
            if d.text:
                years += re.findall(r"(?<!\d)(20[0-4]\d)(?!\d)", d.text[:20000])
        self.ref_year = int(max(set(years), key=years.count)) if years else 2025
        for d in docs:
            if d.status != "ok":
                continue
            try:
                if d.kind == "csv":
                    d.units = handlers.csv_extract(d, self)
                elif d.kind == "json":
                    d.units = handlers.json_extract(d, self)
                elif d.kind == "fhir":
                    d.units = handlers.fhir_extract(d, self)
                else:
                    d.units = handlers.text_extract(d, self)
            except Exception as exc:
                self._quarantine(d, exc)
                d.units = []

    def learn_names(self, docs):
        """Second chance for names seen once in a cued context: tokens of free-text names tagged as
        patient / relative / cued (any script) join the runtime lexicon, so the rewrite pass also
        catches the same word where it stands alone ("Subodh aur uski wife ..." -> later "Subodh").
        Only words that cannot be ordinary vocabulary are learnt (3+ letters, Titlecase or Devanagari,
        not stop/common/medical/ambiguous/honorific)."""
        lex = self.detector.lex
        learnt = set()
        for d in docs:
            for name in getattr(d, "cued_names", None) or []:
                for raw in re.findall(r"[A-Za-z]+|[\u0900-\u097F]+", name):
                    if has_devanagari(raw):
                        if len(raw) >= 3 and self.detector._tok_ok_deva(raw, True) and not lex.is_place(raw):
                            f = fold(devanagari_to_latin(raw))
                            if len(f) >= 3 and f not in lex.medical:
                                learnt.add(f)
                        continue
                    if not re.fullmatch(r"[A-Z][a-z]{2,}", raw):
                        continue
                    tl = raw.lower()
                    if lex.is_common(raw) or lex.is_medical(raw) or tl in lex.ambiguous or tl in lex.honor_pre or tl in lex.honor_suf \
                            or lex.is_place(raw):
                        continue
                    learnt.add(fold(tl))
        learnt.discard("")
        self.dyn.update(learnt)
        return len(learnt)

    # ------------------------------------------------------------ pass 2: link + plan
    def link_and_plan(self, docs):
        units = []
        for d in docs:
            for u in d.units:
                u.rid = len(units)
                u.prof.rid = u.rid
                u.key = d.sha + "|" + u.loc
                units.append(u)
        linker = Linker(self.policy)
        labels, members = linker.link([u.prof for u in units])
        clusters = defaultdict(list)
        for u, lab in zip(units, labels):
            if lab is not None:
                clusters[lab].append(u)
        issued = {}
        for lab in sorted(clusters, key=lambda l: min(x.key for x in clusters[l])):
            mem = clusters[lab]
            anchor = hashlib.sha256(json.dumps(sorted(x.key for x in mem)).encode()).hexdigest()
            salt = 0
            psn = self.keys.pseudonym(anchor)
            while psn in issued:
                salt += 1
                psn = self.keys.pseudonym(anchor, salt)
            issued[psn] = lab
            for x in mem:
                x.psn = psn
        p = self.policy
        for u in units:
            key = ("psn|" + u.psn) if u.psn else ("unit|" + u.key)
            u.shift = self.keys.shift_days(key, p["shift_lo"], p["shift_hi"], p["shift_min_abs"])
        # propagate cluster-level QI (age/sex/district) to members missing them; true values only
        for lab, mem in clusters.items():
            for field in ("district", "state"):
                vals = sorted({x.qi.get(field) for x in mem if x.qi.get(field)})
                if len(vals) == 1:
                    for x in mem:
                        x.qi.setdefault(field, vals[0])
        planner = Planner(self.policy)
        groups = defaultdict(list)
        for u in units:
            groups[u.psn or ("unit|" + u.key)].append(u)
        pats = []
        for pkey in sorted(groups):
            mem = groups[pkey]
            ages = [x.age for x in mem if x.age is not None and 0 <= x.age <= 120]
            dists = sorted({"".join(skeleton(t) for t in name_tokens(x.qi["district"])) for x in mem if x.qi.get("district")})
            states = sorted({x.qi.get("state") for x in mem if x.qi.get("state")})
            pins = sorted({x.qi.get("pin") for x in mem if x.qi.get("pin")})
            sexes = sorted({x.prof.sex for x in mem if x.prof.sex})
            pats.append({"pkey": pkey, "amin": min(ages) if ages else None, "amax": max(ages) if ages else None,
                         "sex": sexes[0] if len(sexes) == 1 else None, "district": "|".join(dists) or None,
                         "state": "|".join(states) or None, "pin": pins[0] if len(pins) == 1 else None,
                         "village": next((v for x in mem for v in sorted(x.prof.villages)), None),
                         "dx": set().union(*[x.dx for x in mem]), "los": tuple(sorted(str(x.los) for x in mem if x.los is not None))})
        levels = planner.plan(pats)
        self.risk = planner.risk(pats, levels)
        self.suppressed = set()
        for r in pats:
            lvl = levels[r["pkey"]]
            band = band_range(r["amin"], r["amax"], lvl, self.policy)
            for u in groups[r["pkey"]]:
                u.level = lvl
                u.band = band
                u.arange = (r["amin"], r["amax"]) if r["amin"] is not None else None
                if r["pkey"] in planner.suppressed:
                    self.suppressed.add(u.rid)
        self.units = units
        self.link_stats = {"clusters": len(clusters), "linked_records": sum(1 for u in units if u.psn)}

    # ------------------------------------------------------------ pass 3: rewrite
    def rewrite(self, docs, out_root):
        san = os.path.join(out_root, "sanitized")
        used = set()
        for d in docs:
            if d.status != "ok":
                continue
            try:
                if d.kind == "csv":
                    body = handlers.csv_rewrite(d, self)
                elif d.kind == "json":
                    body = handlers.json_rewrite(d, self)
                elif d.kind == "fhir":
                    body = handlers.fhir_rewrite(d, self)
                else:
                    body = handlers.text_rewrite(d, self)
                body = self.sweep(body)
                if d.kind in ("json", "fhir"):
                    json.loads(body)  # must still parse
                d.output = body.encode("utf-8")
                d.out_rel = self.out_path(d, used)
                d.status = "sanitized"
            except Exception as exc:
                self._quarantine(d, exc)
                d.output = None
        for d in docs:
            if d.status == "sanitized":
                full = os.path.join(san, d.out_rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "wb") as fh:
                    fh.write(d.output)
                d.output = None

    def out_path(self, d, used):
        parts = d.rel.split("/")
        psn = d.units[0].psn if len(d.units) == 1 else None
        newparts = []
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                stem, dot, ext = part.rpartition(".")
                if not dot:
                    stem, ext = part, ""
                ns, ch = core.sanitize_token_string(stem, self, None)
                if ch:
                    ns = re.sub(r"(redacted[_\- ]*)+", "redacted_", ns).strip("_- ") or "file"
                    ns = ns + "_" + self.keys.token("fname", d.sha, 8)
                    self.renamed += 1
                newparts.append(ns + (("." + ext) if dot else ""))
            else:
                ns, ch = core.sanitize_token_string(part, self, None)
                if ch:
                    ns = "dir_" + self.keys.token("dir", part, 8)
                newparts.append(ns)
        rel = "/".join(newparts)
        base, n = rel, 1
        while rel in used:
            n += 1
            stem, dot, ext = base.rpartition(".")
            rel = (stem + "_%d." % n + ext) if dot else base + "_%d" % n
        used.add(rel)
        return rel

    def build_sweep(self):
        """Exact-value residual sweep over every identifier value seen in this input (set lookups, O(text))."""
        names, ids = set(), set()
        for u in self.units:
            for n in u.names_raw:
                n2 = " ".join(n.split()).lower()
                if len(n2) >= 6 and " " in n2:
                    names.add(n2)
            for k, vs in u.prof.ids.items():
                for v in vs:
                    if len(v) >= 6 and sum(c.isdigit() for c in v) >= 4:
                        ids.add(v.lower())
        self._sweep_names = names
        self._sweep_ids = ids
        self._sweep_maxw = max((n.count(" ") + 1 for n in names), default=0)

    _RX_SW_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9/_\-]*[0-9][A-Za-z0-9/_\-]*")
    _RX_SW_WORD = re.compile(r"[A-Za-z\u0900-\u097F]+")

    def sweep(self, body):
        hits = []
        if self._sweep_ids:
            for m in self._RX_SW_ID.finditer(body):
                t = m.group(0).lower()
                if t in self._sweep_ids or re.sub(r"[/_\-]", "", t) in self._sweep_ids:
                    hits.append((m.start(), m.end()))
        if self._sweep_names and self._sweep_maxw >= 2:
            words = [(m.start(), m.end()) for m in self._RX_SW_WORD.finditer(body)]
            i = 0
            while i < len(words):
                done = False
                for n in range(min(self._sweep_maxw, len(words) - i), 1, -1):
                    seg = words[i:i + n]
                    if any(body[seg[k][1]:seg[k + 1][0]] not in (" ", "  ") for k in range(n - 1)):
                        continue
                    key = " ".join(body[a:b] for a, b in seg).lower()
                    if key in self._sweep_names:
                        hits.append((seg[0][0], seg[-1][1]))
                        i += n
                        done = True
                        break
                if not done:
                    i += 1
        if not hits:
            return body
        hits.sort()
        out, last = [], 0
        for a, b in hits:
            if a < last:
                continue
            out.append(body[last:a])
            out.append("[REDACTED]")
            last = b
        out.append(body[last:])
        return "".join(out)

    # ------------------------------------------------------------ outputs
    def write_records(self, docs, out_root):
        lines = []
        for d in docs:
            if d.status != "sanitized":
                continue
            for u in d.units:
                rec = {"file": "sanitized/" + d.out_rel, "loc": u.loc, "patient": u.psn}
                if u.out and u.out != u.loc:
                    rec["out"] = u.out
                if u.rid in self.suppressed:
                    rec["status"] = "suppressed"
                elif self._generalized(u):
                    rec["status"] = "generalized"
                lines.append(json.dumps(rec, ensure_ascii=False))
        with open(os.path.join(out_root, "records.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        return len(lines)

    @staticmethod
    def _generalized(u):
        """A quasi-identifier of this record was released coarsened: exact age/DOB -> band,
        PIN -> prefix or removed, village/tehsil/address -> district or removed."""
        return bool(u.age is not None or u.prof.dobs or u.qi.get("pin") or u.prof.villages or u.prof.pins)

    def write_report(self, docs, out_root, t0, n_records):
        files = []
        for d in docs:
            if d.status == "sanitized":
                e = {"input_sha256": d.sha, "output": "sanitized/" + d.out_rel, "status": "sanitized"}
                if d.out_rel != d.rel:
                    e["renamed"] = True
            else:
                e = {"input_sha256": d.sha, "output": None, "status": "quarantined", "reason": (d.reason or "processing error").replace(" ", "_")}
            files.append(e)
        exported = [u for d in docs if d.status == "sanitized" for u in d.units]
        rep = {
            "schema": "raksha-report/1",
            "files": files,
            "counts": {
                "files_total": len(docs),
                "files_sanitized": sum(1 for d in docs if d.status == "sanitized"),
                "files_quarantined": sum(1 for d in docs if d.status != "sanitized"),
                "records_processed": n_records,
                "identifiers_detected": int(self.ids_detected),
                "records_linked": sum(1 for u in exported if u.psn),
                "records_generalized": sum(1 for u in exported if u.rid not in self.suppressed and self._generalized(u)),
                "records_suppressed": sum(1 for u in exported if u.rid in self.suppressed),
                "records_quarantined": sum(len(d.units) for d in docs if d.status != "sanitized"),
            },
            "entities": dict(sorted((k, int(v)) for k, v in self.entities.items())),
            "privacy": self.risk,
            "linkage": self.link_stats,
            "timing": {"seconds": round(time.time() - t0, 2)},
            "resources": {"peak_rss_mb": peak_rss_mb()},
        }
        with open(os.path.join(out_root, "report.json"), "w", encoding="utf-8") as fh:
            json.dump(rep, fh, ensure_ascii=False, indent=2)
        return rep


def run(input_dir, output_dir, policy, keyring, log):
    t0 = time.time()
    eng = Engine(policy, keyring, log)
    eng.renamed = 0
    os.makedirs(os.path.join(output_dir, "sanitized"), exist_ok=True)
    docs = eng.load(input_dir)
    log.event("loaded", files=len(docs), quarantined=sum(1 for d in docs if d.status != "ok"))
    eng.harvest(docs)
    eng.extract(docs)
    eng.learn_names(docs)
    log.event("extracted", records=sum(len(d.units) for d in docs))
    eng.link_and_plan(docs)
    log.event("linked", clusters=eng.link_stats["clusters"], linked=eng.link_stats["linked_records"])
    eng.build_sweep()
    eng.rewrite(docs, output_dir)
    n = eng.write_records(docs, output_dir)
    rep = eng.write_report(docs, output_dir, t0, n)
    log.event("done", sanitized=rep["counts"]["files_sanitized"], quarantined=rep["counts"]["files_quarantined"],
              seconds=rep["timing"]["seconds"], peak_rss_mb=rep["resources"]["peak_rss_mb"])
    return rep
