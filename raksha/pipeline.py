"""Two-pass pipeline: ingest+detect+extract -> link -> privacy plan -> rewrite+sweep -> report."""
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections import defaultdict

from . import core, handlers, ingest, stigma
from .detect import Detector, PII_KINDS
from .ingest import BinaryFile, ContentMismatch, CorruptBytes, EmptyFile, FhirInvalid, GarbledText, NonStandardJson, UnsafeEntry, Unsupported
from .linkage import Linker
from .privacy import Planner, band_range
from .secure import SafeLog, error_category, sha256_bytes
from .translit import devanagari_to_latin, fold, has_devanagari, name_tokens, skeleton

GENERIC_TOKENS = {"kumar", "devi", "ji", "md", "mohd", "mohammad", "bai", "begum", "bano", "kumari", "singh", "kaur",
                  "lal", "prasad", "ram", "khan", "sahab", "shri", "smt"}


# a name right after a doctor title is the clinician (kept), even when a patient has the same name
_RX_DR_BEFORE = re.compile(r"(?:\b(?:Dr|DR|dr|Prof)\.?|Doctor|डॉ\.?|डा\.)\s*$")


class Doc:
    def __init__(self, rel, data):
        self.rel = rel
        self.sha = sha256_bytes(data)  # raw bytes are not kept (memory); text/obj carry the content
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
        self.order_votes = defaultdict(lambda: [0, 0])
        self.token_df = defaultdict(int)
        self.n_docs = 0
        self.safe_file_tokens = set()
        self.current_patient_refs = set()
        self.shield = {"patients_flagged": 0, "records_flagged": 0, "records_hardened": 0, "facility_names_removed": 0,
                       "selfcheck_files": 0, "selfcheck_planted": 0, "selfcheck_caught": 0,
                       "files_resanitized_strict": 0, "files_requarantined": 0}

    # ------------------------------------------------------------ helpers used by handlers
    def count_ids(self, n, kind="ID"):
        """Every removed / replaced identifier is counted once, by type, in self.entities;
        report.json's identifiers_detected is their sum, so the two always agree."""
        if n > 0:
            self.entities[kind] += n

    def add_entities(self, ents, n):
        """Typed counts from a free-text render plus any untyped remainder of its total n."""
        for k, c in ents.items():
            self.entities[k] += c
        extra = n - sum(ents.values())
        if extra > 0:
            self.entities["ID"] += extra

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
            return int(max(sorted(set(m)), key=m.count))
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
            full = os.path.join(root, rel)
            if os.path.islink(full) or not stat.S_ISREG(os.lstat(full).st_mode):
                d = Doc(rel, b"")
                d.sha = ingest.unsafe_entry_sha(root, rel)
                docs.append(d)
                self._quarantine(d, UnsafeEntry())
                d.hospital = None
                continue
            try:
                data = ingest.read_nofollow(full)
            except OSError:
                data = b""
            d = Doc(rel, data)
            docs.append(d)
            try:
                base = rel.rsplit("/", 1)[-1]
                ext = os.path.splitext(base)[1].lower()
                if base.startswith(".") and ext not in (ingest.TEXT_EXT | ingest.CSV_EXT | ingest.JSON_EXT):
                    raise Unsupported()
                d.text = ingest.decode(data)
                d.kind = ingest.sniff_kind(rel, d.text)
                if d.kind == "json":
                    d.obj = ingest.parse_json(d.text, rel)
                    if ingest.is_fhir(d.obj):
                        ingest.check_fhir(d.obj)
                        d.kind = "fhir"
                elif d.kind == "ndjson":
                    raise Unsupported()
                elif d.kind == "text" and re.search(r"<\?xml|<ClinicalDocument|<html", d.text[:500], re.I):
                    raise Unsupported()
                d.status = "ok"
            except (Unsupported, BinaryFile, EmptyFile, GarbledText, FhirInvalid, CorruptBytes, NonStandardJson, ContentMismatch,
                    ValueError, RecursionError,
                    UnicodeDecodeError, MemoryError) as exc:
                self._quarantine(d, exc)
            d.hospital = self._hospital(d)
        return docs

    def _quarantine(self, d, exc):
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
        self.ref_year = int(max(sorted(set(years)), key=years.count)) if years else 2025
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
            else:
                self._tag_stigma(d)

    def _tag_stigma(self, d):
        """Stigma Shield: which records mention a stigmatised condition (categories only, in memory)."""
        if not (self.policy.get("stigma") or {}).get("enabled"):
            return
        try:
            if d.kind == "csv":
                rows = getattr(d, "rows", None) or []
                for u in d.units:
                    ri = int(u.loc.split(":")[1])
                    u.stigma = stigma.categories(" ".join(str(c) for c in rows[ri])) if ri < len(rows) else ()
            elif d.kind == "json":
                for (ptr, node), u in zip(getattr(d, "records", None) or [], d.units):
                    u.stigma = stigma.categories(json.dumps(node, ensure_ascii=False))
            elif d.kind == "fhir":
                cats = stigma.categories(json.dumps(d.obj, ensure_ascii=False))
                for u in d.units:
                    u.stigma = cats
            else:
                cats = stigma.categories(d.text or "")
                for u in d.units:
                    u.stigma = cats
        except (ValueError, IndexError, TypeError):
            pass

    def learn_names(self, docs):
        """Second chance for names seen once in a cued context: tokens of free-text names tagged as
        patient / relative / cued (any script) join the runtime lexicon, so the rewrite pass also
        catches the same word where it stands alone ("Thivaresh aur uski wife ..." -> later "Thivaresh").
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
                         "stigma": tuple(sorted({c for x in mem for c in x.stigma})),
                         "dx": set().union(*[x.dx for x in mem]), "los": tuple(sorted(str(x.los) for x in mem if x.los is not None))})
        levels = planner.plan(pats)
        self.risk = planner.risk(pats, levels)
        self.suppressed = set()
        for r in pats:
            lvl = levels[r["pkey"]]
            band = band_range(r["amin"], r["amax"], lvl, self.policy)
            if r["stigma"]:
                self.shield["patients_flagged"] += 1
            for u in groups[r["pkey"]]:
                u.stigma_pat = r["stigma"]
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
            sg = self.policy.get("stigma") or {}
            stig = bool(sg.get("enabled")) and any(u.stigma_pat for u in d.units)
            if stig:
                n = sum(1 for u in d.units if u.stigma_pat)
                self.shield["records_flagged"] += n
                self.shield["records_hardened"] += n
                self.detector.set_strict(1, sg.get("name_threshold_drop", 0.35))
            try:
                if d.kind == "text" or d.kind not in ("csv", "json", "fhir"):
                    body = self._text_shielded(d, stig, sg)
                elif d.kind == "csv":
                    body = handlers.csv_rewrite(d, self)
                elif d.kind == "json":
                    body = handlers.json_rewrite(d, self)
                elif d.kind == "fhir":
                    body = handlers.fhir_rewrite(d, self)
                if stig and d.kind in ("json", "fhir"):
                    body, nf = stigma.strip_facilities(body)
                    self.shield["facility_names_removed"] += nf
                body = self.sweep(body)
                if d.kind in ("json", "fhir"):
                    json.loads(body)  # must still parse
                d.output = body.encode("utf-8")
                d.out_rel = self.out_path(d, used)
                d.status = "sanitized"
            except Exception as exc:
                self._quarantine(d, exc)
                d.output = None
            finally:
                self.detector.set_strict(0)
        for d in docs:
            if d.status == "sanitized":
                full = os.path.join(san, d.out_rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "wb") as fh:
                    fh.write(d.output)
                d.output = None

    def _text_shielded(self, d, stig, sg):
        """Free-text rewrite; for a stigmatised patient (or every file with selfcheck: all) the honey-PII
        self-check must pass, else the file is re-sanitised in the strictest mode, else quarantined."""
        mode = sg.get("selfcheck", "stigma")
        check = bool(sg.get("enabled")) and (mode == "all" or (mode == "stigma" and stig))
        snap = dict(self.entities)
        body = handlers.text_rewrite(d, self)
        if stig:
            body, nf = stigma.strip_facilities(body)
            self.shield["facility_names_removed"] += nf
        if not check:
            return body
        self.shield["selfcheck_files"] += 1
        if self._selfcheck(d, stig):
            return body
        self.shield["files_resanitized_strict"] += 1
        self.entities.clear()
        self.entities.update(snap)
        self.detector.set_strict(2, sg.get("name_threshold_drop", 0.35))
        body = handlers.text_rewrite(d, self)
        body, _ = stigma.strip_facilities(body)
        mode_fail = sg.get("selfcheck_on_fail", "auto")
        if self._selfcheck(d, True, count=False) or mode_fail == "keep_strict":
            return body
        st = self._last_check
        # auto: a surviving number (Aadhaar/phone/ID: a format hole) or most planted names surviving
        # (the detector is blind in this file) -> quarantine; a few context-dependent names -> strict output
        if mode_fail == "auto" and not st["num"] and st["name"] * 2 <= st["names"]:
            return body
        self.entities.clear()
        self.entities.update(snap)
        self.shield["files_requarantined"] += 1
        raise ValueError("selfcheck failed")

    def _selfcheck(self, d, stig, count=True):
        """Honey-PII self-check (in memory only). Every identifier detected in the file is replaced by an
        invented one of the same shape (keyed by HMAC(secret, file hash)); the shadow file goes through the
        same detect + render path; True when no planted value survives. Nothing is logged or written."""
        det = self.detector
        u = d.units[0]
        text = d.text or ""
        ctx = self.unit_ctx(d, u)
        order, year = self.doc_order(d), self.doc_year(d)
        spans = sorted((s for s in det.detect(text, None, order, year) if s.kind in stigma.HONEY_KINDS),
                       key=lambda s: s.start)
        honey = stigma.Honey(hashlib.sha256(self.keys.token("honey", d.sha, 32).encode()).digest(), d.sha)
        lex = det.lex

        def score(w):
            if lex.is_common(w) or lex.is_medical(w) or lex.is_place(w) or fold(devanagari_to_latin(w) if has_devanagari(w) else w.lower()) in det.dyn:
                return -1.0
            if det.name_finder is not None:
                return det.name_finder.score_token(w)[0] + det.name_score(w)
            return det.name_score(w)
        parts, planted, added, pos = [], [], [], 0
        for s in spans:
            if s.start < pos:
                continue
            orig = text[s.start:s.end]
            if s.kind == "NAME":
                fake = honey.name_like(orig, score)
                for o, f in zip(orig.split(), fake.split()):
                    fo = fold(devanagari_to_latin(o) if has_devanagari(o) else o.lower())
                    ff = fold(devanagari_to_latin(f) if has_devanagari(f) else f.lower())
                    if fo in det.dyn and ff not in det.dyn:
                        det.dyn.add(ff)
                        added.append(ff)
                    if len(f) >= 3:
                        planted.append(("NAME", f))
            elif sum(c.isdigit() for c in orig) >= 6:
                fake = honey.digits_like(orig, s.kind)
                planted.append(("NUM", fake))
            else:
                continue
            parts.append(text[pos:s.start])
            parts.append(fake)
            pos = s.end
        self._last_check = {"num": 0, "name": 0, "names": 0}
        if not planted:
            for f in added:
                det.dyn.discard(f)
            return True
        parts.append(text[pos:])
        shadow = "".join(parts)
        try:
            spans2 = det.detect(shadow, None, order, year)
            out, _, _ = core.render(shadow, spans2, self.unit_ctx(d, u))
            out, _ = core.b64_tokens_sub(out, ctx)
            if stig:
                out, _ = stigma.strip_facilities(out)
        finally:
            for f in added:
                det.dyn.discard(f)
        low = out.lower()
        survived = 0
        for kind, v in planted:
            if kind == "NAME":
                hit = re.search(r"(?<![\w\u0900-\u097F])" + re.escape(v.lower()) + r"(?![\w\u0900-\u097F])", low)
            else:
                hit = v in out
            survived += bool(hit)
            if hit:
                self._last_check["num" if kind == "NUM" else "name"] += 1
        self._last_check["names"] = sum(1 for k, _ in planted if k == "NAME")
        if count:
            self.shield["selfcheck_planted"] += len(planted)
            self.shield["selfcheck_caught"] += len(planted) - survived
        return survived == 0

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
                ns = self._shift_name_dates(ns, d)
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

    _RX_FNAME_DATE = re.compile(r"(?<!\d)(?:((?:19|20)\d{2})([-_.]?)(0[1-9]|1[0-2])\2(0[1-9]|[12]\d|3[01])"
                                r"|(0[1-9]|[12]\d|3[01])([-_.])(0[1-9]|1[0-2])\6((?:19|20)\d{2}))(?!\d)")

    def _shift_name_dates(self, stem, d):
        """A visit date in a file name ("opd_2024-03-05.txt") is a real date: shift it like the dates
        inside the file (the record's own shift, or the file shift for multi-patient files)."""
        if not self._RX_FNAME_DATE.search(stem):
            return stem
        import datetime as dt
        ctx = self.unit_ctx(d, d.units[0]) if len(d.units) == 1 else self.file_ctx(d)

        def sub(m):
            try:
                if m.group(1):
                    v = dt.date(int(m.group(1)), int(m.group(3)), int(m.group(4))) + dt.timedelta(days=ctx.shift)
                    sep = m.group(2)
                    return "%04d%s%02d%s%02d" % (v.year, sep, v.month, sep, v.day)
                v = dt.date(int(m.group(8)), int(m.group(7)), int(m.group(5))) + dt.timedelta(days=ctx.shift)
                sep = m.group(6)
                return "%02d%s%02d%s%04d" % (v.day, sep, v.month, sep, v.year)
            except ValueError:
                return m.group(0)
        return self._RX_FNAME_DATE.sub(sub, stem)

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
                    if key in self._sweep_names and not _RX_DR_BEFORE.search(body[max(0, seg[0][0] - 8):seg[0][0]]):
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
                # k-anonymity escalation coarsens a record's quasi-identifiers to the top level but
                # the record itself is still exported and locatable: that is "generalized", not
                # "suppressed" (which would mean the record was removed)
                if u.rid in self.suppressed or self._generalized(u):
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
                "identifiers_detected": int(sum(self.entities.values())),
                "records_linked": sum(1 for u in exported if u.psn),
                "records_generalized": sum(1 for u in exported if u.rid in self.suppressed or self._generalized(u)),
                "records_suppressed": 0,  # no record is ever dropped; rare QIs are coarsened instead
                "records_quarantined": sum(len(d.units) for d in docs if d.status != "sanitized"),
            },
            "entities": dict(sorted((k, int(v)) for k, v in self.entities.items())),
            "privacy": self.risk,
            "linkage": self.link_stats,
            "stigma_shield": dict(self.shield),
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
    # re-hash every input: a file that changed while we ran is reported (count only, no names)
    changed = 0
    for d in docs:
        try:
            now = sha256_bytes(ingest.read_nofollow(os.path.join(input_dir, d.rel)))
        except OSError:
            now = None
        if d.sha != now and not (now is None and d.status == "quarantined"):
            changed += 1
    eng.inputs_changed = changed
    if changed:
        sys.stderr.write("raksha: warning: %d input file(s) changed during the run\n" % changed)
    n = eng.write_records(docs, output_dir)
    rep = eng.write_report(docs, output_dir, t0, n)
    log.event("done", sanitized=rep["counts"]["files_sanitized"], quarantined=rep["counts"]["files_quarantined"],
              seconds=rep["timing"]["seconds"], peak_rss_mb=rep["resources"]["peak_rss_mb"])
    return rep
