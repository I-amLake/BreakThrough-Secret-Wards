"""Format handlers. Each has extract(doc, eng) -> units and rewrite(doc, eng) -> bytes."""
import base64
import csv
import datetime as dt
import io
import json
import re

from . import core
from .core import Ctx, Unit, add_name, apply_dob, band_for, finalize_unit, has_digits, norm_id, parse_age, parse_sex, render, render_value, rel_from_value, set_age, spans_evidence
from .dates import numeric_order_votes, parse_full
from .detect import DIGITS, PII_KINDS, digits_only, label_relation, norm_phone
from .privacy import age_band, pin3
from .schema import classify_label, date_order_hint, infer_from_values, value_type
from .translit import fold, name_tokens


# ===================================================================== structured field logic (CSV + JSON)
def field_evidence(unit, ftype, value, label, eng, order=None):
    if value is None or isinstance(value, bool):
        return
    v = str(value).strip()
    if not v or v.lower() in ("null", "none", "na", "n/a", "-"):
        return
    if ftype in ("name", "first_name", "last_name"):
        if not re.search(r"\d|@", v):
            unit._name_parts.append(v)
    elif ftype == "relative":
        (canon, psex), nm = rel_from_value(v, label_relation(label))
        toks = tuple(t for t in name_tokens(nm) if t)
        if toks:
            unit.prof.rels.append((canon, toks))
        if psex and not unit.prof.sex:
            unit._sex_hint = psex
    elif ftype in ("phone", "contact"):
        d = digits_only(v)
        if len(d) >= 10:
            unit.prof.phones.add(norm_phone(v))
        elif ftype == "contact" and not d:
            toks = tuple(t for t in name_tokens(v) if t)
            if toks:
                unit.prof.rels.append(("G", toks))
    elif ftype == "email" and "@" in v:
        unit.prof.ids["EMAIL"].add(v.lower())
    elif ftype == "aadhaar":
        d = digits_only(v)
        if len(d) == 12:
            unit.prof.ids["AADHAAR"].add(d)
    elif ftype == "abha":
        unit.prof.ids["ABHA"].add(norm_id(v))
    elif ftype == "pan":
        unit.prof.ids["PAN"].add(norm_id(v))
    elif ftype in ("mrn", "insurance"):
        nv = norm_id(v)
        if sum(c.isdigit() for c in nv) >= 3:
            unit.prof.ids["INSURANCE" if ftype == "insurance" else "MRN"].add(nv)
    elif ftype == "dob":
        r = parse_full(v, order)
        if r:
            apply_dob(unit, r[0])
    elif ftype == "age":
        set_age(unit, parse_age(v))
        sx = parse_sex(re.sub(r"\d", " ", v)) if re.search(r"[/ ]\s*[MFmf]\b|male|female|पुरुष|महिला", v) else None
        if sx and not unit.prof.sex:
            unit.prof.sex = sx
    elif ftype == "sex":
        sx = parse_sex(v)
        if sx:
            unit.prof.sex = sx
    elif ftype == "pin":
        d = digits_only(v)
        if len(d) == 6:
            unit.prof.pins.add(d)
            unit.qi["pin"] = d
    elif ftype == "district":
        unit.prof.districts.add(fold(v))
        unit.qi["district"] = v
    elif ftype == "state":
        unit.qi["state"] = v
    elif ftype in ("village", "tehsil", "city"):
        if ftype == "village":
            unit.prof.villages.add(" ".join(name_tokens(v)))
        unit.qi.setdefault("_" + ftype, v)
    elif ftype == "address":
        spans = eng.detector.detect(v)
        meta = eng.detector.parse_address(v)
        if meta.get("pin"):
            unit.prof.pins.add(meta["pin"])
            unit.qi.setdefault("pin", meta["pin"])
        if meta.get("district"):
            unit.qi.setdefault("district", meta["district"])
            unit.prof.districts.add(fold(meta["district"]))
        if meta.get("state"):
            unit.qi.setdefault("state", meta["state"])
        spans_evidence(unit, v, [s for s in spans if s.kind == "NAME" and s.role == "relative"])
    elif ftype == "date":
        r = parse_full(v, order)
        if r:
            unit.dates.append(r[0])
            lab = str(label).lower()
            if re.search(r"admi|doa|\badm", lab):
                unit._adm = r[0]
            elif re.search(r"disch|dod", lab):
                unit._dis = r[0]
            elif unit.ref_date is None:
                unit.ref_date = r[0]
    elif ftype == "diagnosis":
        unit.dx.add(v.strip().lower()[:80])
    if ftype in ("text", None, "clinical", "contact", "hospital", "record_id", "diagnosis"):
        spans = eng.detector.detect(v, ftype, order)
        spans_evidence(unit, v, [s for s in spans if s.kind != "AGE" and s.kind != "DOB"])
        for d in core.ICD_RX.findall(v):
            unit.dx.add(d)


def start_unit(loc, hospital):
    u = Unit(loc, hospital)
    u._name_parts = []
    u._sex_hint = None
    u._adm = None
    u._dis = None
    return u


def end_unit(u, eng):
    if u._name_parts:
        add_name(u, " ".join(u._name_parts), eng)
    if not u.prof.sex and u._sex_hint:
        u.prof.sex = u._sex_hint
    if u._adm and u._dis and u._dis >= u._adm:
        u.los = (u._dis - u._adm).days
    if u._adm and not u.ref_date:
        u.ref_date = u._adm
    finalize_unit(u, getattr(eng, "ref_year", None))
    for a in ("_name_parts", "_sex_hint", "_adm", "_dis"):
        pass
    return u


def rewrite_field(ftype, value, ctx, label, slot, order=None):
    """Return the sanitised value for a structured field. slot: dict tracking PSN placement."""
    eng = ctx.eng
    pol = eng.policy
    if value is None or isinstance(value, bool):
        return value, 0
    is_num = isinstance(value, (int, float))
    v = str(value)
    if not v.strip():
        return value, 0
    def numeric(rep):
        return 0 if is_num else rep
    if ftype in ("name", "first_name", "last_name"):
        if ctx.psn and not slot.get("name"):
            slot["name"] = True
            ctx.psn_used = True
            return ctx.psn, 1
        if ctx.psn:
            return "", 1
        return pol["repl"]["unlinked_patient"], 1
    if ftype == "relative":
        (canon, _), nm = rel_from_value(v)
        prefix = v[: len(v) - len(nm)] if nm and v.endswith(nm) else ""
        return prefix + pol["repl"]["relative"], 1
    if ftype in ("phone",):
        return numeric("[PHONE]"), 1
    if ftype == "contact":
        return (numeric("[PHONE]") if digits_only(v) else pol["repl"]["relative"]), 1
    if ftype == "email":
        return "[EMAIL]", 1
    if ftype == "aadhaar":
        return numeric("[AADHAAR]"), 1
    if ftype == "abha":
        return numeric("[ABHA]"), 1
    if ftype == "pan":
        return "[PAN]", 1
    if ftype in ("mrn",):
        if ctx.psn and not slot.get("name") and not slot.get("mrn") and slot.get("mrn_ok", True):
            slot["mrn"] = True
            ctx.psn_used = True
            return numeric(ctx.psn), 1
        if ctx.psn:
            ctx.psn_used = True
            return numeric(ctx.psn), 1
        return numeric("[ID]"), 1
    if ftype == "insurance":
        return "[INSURANCE-ID]", 1
    if ftype == "dob":
        b = band_for(ctx, ctx.age)
        return (b if b else "[DOB]"), 1
    if ftype == "age":
        age = parse_age(v)
        if age is None:
            # implausible (negative / > 120) or unreadable: never echo digits, never fake a band
            return ("[AGE]" if has_digits(v) else value), 0
        b = band_for(ctx, age)
        if is_num:
            return b, 0
        return re.sub(r"(?<![\d.])\d{1,3}(?![\d.])", b, v.translate(DIGITS), count=1), 0
    if ftype == "pin":
        d = digits_only(v)
        if len(d) == 6 and ctx.level <= pol["pin3_level"]:
            return (int(d[:3]) if is_num else pin3(d)), 1
        return numeric("[PIN]"), 1
    if ftype in ("village", "tehsil", "city"):
        # Truthful generalisation up the administrative chain village -> tehsil -> district: the cell
        # is replaced by the record's OWN tehsil (policy village_to: tehsil) or district, both read
        # from the same record. Nothing is invented; with no known parent unit the value is masked.
        dist = ctx.qi.get("district")
        if ftype == "city" and dist and name_tokens(v) == name_tokens(dist) and ctx.level <= pol["district_level"]:
            return value, 0
        teh = ctx.qi.get("_tehsil")
        if ftype != "tehsil" and teh and pol.get("village_to") == "tehsil" and ctx.level == 0:
            return teh, 1
        if dist and ctx.level <= pol["district_level"]:
            return dist, 1
        return "[" + ftype.upper() + "]", 1
    if ftype == "district":
        if ctx.level <= pol["district_level"]:
            return value, 0
        return "[DISTRICT]", 1
    if ftype == "address":
        meta = eng.detector.parse_address(v)
        if not meta.get("district") and ctx.qi.get("district"):
            meta["district"] = ctx.qi["district"]
        return core.address_repl(meta, ctx, eng), 1
    if ftype == "date":
        r = parse_full(v, order)
        if r and not is_num:
            try:
                return r[1](r[0] + dt.timedelta(days=ctx.shift)), 0
            except Exception:
                return "[DATE]", 0
    if ftype in ("doctor", "sex", "state", "hospital"):
        if ftype == "doctor":
            return value, 0
        new, n, _ = render_value(v, ctx, ftype)
        return (value if is_num else new), n
    if is_num:
        # bare numbers that are identifiers (Aadhaar as int, phone as int)
        d = str(value)
        if re.fullmatch(r"[2-9]\d{11}", d) or re.fullmatch(r"[6-9]\d{9}", d) or re.fullmatch(r"91[6-9]\d{9}", d):
            return 0, 1
        return value, 0
    new, n, ents = render_value(v, ctx, ftype)
    for k, c in ents.items():
        eng.entities[k] = eng.entities.get(k, 0) + c
    return new, n


# ===================================================================== CSV / TSV
class CsvDoc:
    pass


def _realign(row, L, expect):
    if len(row) == L:
        return row, False
    if len(row) < L:
        return row + [""] * (L - len(row)), True
    extra = len(row) - L
    best, best_s = None, -1
    for pos in range(L):
        cand = row[:pos] + [",".join(row[pos:pos + extra + 1])] + row[pos + extra + 1:]
        s = sum(1 for i, c in enumerate(cand) if value_type(c) == expect[i])
        if s > best_s:
            best, best_s = cand, s
    return best, True


def csv_prepare(doc, eng):
    from .ingest import parse_csv
    import os
    ext = os.path.splitext(doc.rel)[1].lower()
    if doc.text.count('"') % 2 == 1:
        from .ingest import Unsupported
        raise Unsupported()
    p = parse_csv(doc.text, ext)
    header = p["header"]
    L = len(header)
    good = [r for r in p["rows"] if len(r) == L]
    expect = []
    for i in range(L):
        vt = [value_type(r[i]) for r in good[:200]]
        expect.append(max(sorted(set(vt)), key=vt.count) if vt else "text")
    rows, fixed = [], 0
    for r in p["rows"]:
        nr, ch = _realign(r, L, expect)
        rows.append(nr)
        fixed += ch
    types, orders = [], []
    file_votes = numeric_order_votes(doc.text)
    for i, h in enumerate(header):
        t = classify_label(h)
        col = [r[i] for r in rows if i < len(r)]
        if t in (None, "contact", "clinical", "hospital", "text", "name") or t is None:
            inf = infer_from_values(col, eng.dyn)
            if t is None and inf:
                t = inf
            elif t == "contact":
                t = "phone" if inf == "phone" else ("relative" if inf == "name" else "contact")
            elif t == "name" and inf in ("phone", "email", "aadhaar", "mrn", "date"):
                t = inf
        types.append(t)
        o = date_order_hint(h)
        if not o:
            dv, mv = numeric_order_votes("\n".join(col))
            o = "mdy" if mv > dv else ("dmy" if dv > mv else None)
        if not o:
            o = "mdy" if file_votes[1] > file_votes[0] else ("dmy" if file_votes[0] > file_votes[1] else eng.source_order(doc))
        orders.append(o)
    doc.csv = p
    doc.rows = rows
    doc.types = types
    doc.orders = orders
    doc.hospital_col = next((i for i, t in enumerate(types) if t == "hospital"), None)


def csv_extract(doc, eng):
    units = []
    for ri, row in enumerate(doc.rows):
        hosp = row[doc.hospital_col] if doc.hospital_col is not None else doc.hospital
        u = start_unit("row:%d" % ri, hosp)
        for ci, val in enumerate(row):
            field_evidence(u, doc.types[ci], val, doc.csv["header"][ci], eng, doc.orders[ci])
        units.append(end_unit(u, eng))
    return units


def csv_rewrite(doc, eng):
    p = doc.csv
    out = io.StringIO()
    w = csv.writer(out, delimiter=p["delim"], lineterminator="\n")
    fctx = eng.file_ctx(doc)
    for pr in p["preamble"]:
        w.writerow([render_value(c, fctx)[0] for c in pr])
    hdr = []
    for h in p["header"]:
        nh, changed = core.sanitize_token_string(h, eng) if _header_has_pii(h, eng) else (h, False)
        if changed:
            doc.header_changed = True
        hdr.append(nh)
    w.writerow(hdr)
    has_name = any(t in ("name", "first_name") for t in doc.types)
    for ri, row in enumerate(doc.rows):
        u = doc.units[ri]
        ctx = eng.unit_ctx(doc, u)
        slot = {"mrn_ok": True}
        if not has_name:
            slot["mrn_ok"] = True
        new = []
        for ci, val in enumerate(row):
            ctx.order = doc.orders[ci]
            nv, n = rewrite_field(doc.types[ci], val, ctx, p["header"][ci], slot, doc.orders[ci])
            eng.count_ids(n)
            new.append(nv if isinstance(nv, str) else str(nv))
        if ctx.psn and not ctx.psn_used:
            for ci, t in enumerate(doc.types):
                if t in ("text", None) and new[ci] is not None:
                    new[ci] = (ctx.psn + " " + new[ci]).strip()
                    ctx.psn_used = True
                    break
        w.writerow(new)
    return out.getvalue()


def _header_has_pii(h, eng):
    spans = [s for s in eng.detector.detect(re.sub(r"[_]+", " ", h)) if s.kind in PII_KINDS and s.kind not in ("ADDRESS",)]
    if spans:
        return True
    return bool(re.search(r"\d{5,}", h))


# ===================================================================== JSON (non-FHIR)
IDENT_TYPES = {"name", "first_name", "last_name", "mrn", "phone", "aadhaar", "abha", "pan", "email", "insurance"}


def _ptr_escape(k):
    return str(k).replace("~", "~0").replace("/", "~1")


_GENERIC_NAME_KEY = re.compile(r"(?i)^(?:name|title|label|display|text|value)$")
_PERSONISH = re.compile(r"(?i)patient|person|member|^pt|demograph|subject|beneficiar|record|rows?$|data|items?$|entries|visits?|admission|registration|opd|ipd|results?$|^doc|export|list|bulk|batch")


def _key_type(key, parent):
    if parent == "_other":
        t = classify_label(key, None)
        if t in ("name", "first_name", "last_name") and _GENERIC_NAME_KEY.match(str(key).strip()):
            return None  # "panels[].name", "drugs[].name": not a person
        return t
    return classify_label(key, parent)


_PERSON_SIBLINGS = {"phone", "age", "sex", "dob", "aadhaar", "email", "abha", "pan", "contact", "relative", "address"}
_PERSON_KEY = re.compile(r"(?i)(?:^|_)by(?:$|_)|contact|witness|caller|guardian|attendant|kin|informant|requester|reporter|visitor|escort|raised|owner|customer|user|applicant|claimant|insured|nominee|donor")


def _dict_ctx(node, parent):
    """A dict under a non-person context still describes a person if it carries person attributes."""
    if parent == "_other" and isinstance(node, dict):
        for k in node:
            if classify_label(k, None) in _PERSON_SIBLINGS:
                return None
    return parent


def _child_ctx(key, t, parent):
    """Parent context passed to a nested dict/list."""
    if t:
        return t
    if parent and parent != "_other":
        return parent
    if _PERSONISH.search(str(key)) or _PERSON_KEY.search(str(key)):
        return parent if parent != "_other" else None
    return "_other"


def _identifying(node, parent=None, depth=0):
    if depth > 4:
        return False
    if isinstance(node, dict):
        for k, v in node.items():
            t = _key_type(k, parent)
            if t in IDENT_TYPES and v not in (None, "", [], {}) and not isinstance(v, (dict, list)):
                return True
            if isinstance(v, dict) and _identifying(v, _dict_ctx(v, _child_ctx(k, t, parent)), depth + 1):
                return True
    return False


def find_records(obj):
    """Return list of (pointer, node). Context-aware: dicts under non-person keys ("panels", "drugs")
    are records only if they carry person attributes."""
    recs = []

    def walk(node, ptr, depth, ctx):
        if depth > 60:
            return
        if isinstance(node, list):
            for i, el in enumerate(node):
                p = ptr + "/" + str(i)
                if isinstance(el, dict) and _identifying(el, _dict_ctx(el, ctx)):
                    recs.append((p, el))
                else:
                    walk(el, p, depth + 1, ctx)
        elif isinstance(node, dict):
            c = _dict_ctx(node, ctx)
            vals = [v for v in node.values() if isinstance(v, dict)]
            keyed = len(vals) >= 2 and len(vals) == len(node) and \
                sum(1 for k, v in node.items() if isinstance(v, dict) and _identifying(v, _dict_ctx(v, c))) >= 2
            for k, v in node.items():
                p = ptr + "/" + _ptr_escape(k)
                if keyed and isinstance(v, dict) and _identifying(v, _dict_ctx(v, c)):
                    recs.append((p, v))
                else:
                    walk(v, p, depth + 1, _child_ctx(k, _key_type(k, c), c))

    walk(obj, "", 0, None)
    if not recs and isinstance(obj, dict) and _identifying(obj):
        recs.append(("doc", obj))
    return recs


def _json_evidence(node, unit, eng, parent=None, label="", order=None, depth=0):
    if depth > 50:
        return
    if isinstance(node, dict):
        parent = _dict_ctx(node, parent)
        for k, v in node.items():
            t = _key_type(k, parent)
            if isinstance(v, (dict, list)):
                _json_evidence(v, unit, eng, _child_ctx(k, t, parent), k, order, depth + 1)
            else:
                ft = t
                if ft is None and isinstance(v, str) and len(v) < 40:
                    ft = None
                field_evidence(unit, ft, v, k, eng, order)
    elif isinstance(node, list):
        for el in node:
            if isinstance(el, (dict, list)):
                _json_evidence(el, unit, eng, parent, label, order, depth + 1)
            else:
                field_evidence(unit, parent if parent in ("diagnosis",) else None, el, label, eng, order)


def json_extract(doc, eng):
    obj = doc.obj
    recs = find_records(obj)
    doc.records = recs
    units = []
    order = eng.doc_order(doc)
    for ptr, node in recs:
        u = start_unit(ptr, doc.hospital)
        _json_evidence(node, u, eng, None, "", order)
        units.append(end_unit(u, eng))
    return units


def _rewrite_json(node, ctx, eng, slot, parent=None, label="", order=None, depth=0, key_fn=None):
    if depth > 200:
        return None
    if isinstance(node, dict):
        out = {}
        parent = _dict_ctx(node, parent)
        for k, v in node.items():
            t = _key_type(k, parent)
            nk = key_fn(k) if key_fn else k
            while nk in out:
                nk = nk + "_"
            if isinstance(v, (dict, list)):
                out[nk] = _rewrite_json(v, ctx, eng, slot, _child_ctx(k, t, parent), k, order, depth + 1, key_fn)
            else:
                if isinstance(v, str) and _pathlike(v):
                    nv, ch = core.sanitize_token_string(v, eng, None)
                    eng.count_ids(1 if ch else 0)
                    out[nk] = nv
                    continue
                nv, n = rewrite_field(t, v, ctx, k, slot, order)
                eng.count_ids(n)
                out[nk] = nv
        return out
    if isinstance(node, list):
        res = []
        for el in node:
            if isinstance(el, (dict, list)):
                res.append(_rewrite_json(el, ctx, eng, slot, parent, label, order, depth + 1, key_fn))
            else:
                nv, n = rewrite_field(parent if parent not in ("name", "first_name", "last_name") else parent, el, ctx, label, slot, order) \
                    if parent in IDENT_TYPES or parent in ("relative", "address", "dob", "village") else rewrite_field(None, el, ctx, label, slot, order)
                eng.count_ids(n)
                res.append(nv)
        return res
    nv, n = rewrite_field(parent, node, ctx, label, slot, order)
    eng.count_ids(n)
    return nv


def _pathlike(v):
    return len(v) > 6 and " " not in v.strip() and ("\\" in v or v.count("/") >= 2) and not v.startswith("http")


def json_rewrite(doc, eng):
    obj = doc.obj
    order = eng.doc_order(doc)
    rec_ptrs = {ptr: u for (ptr, _), u in zip(doc.records, doc.units)}

    def key_fn_for(ctx):
        def kf(k):
            if _key_needs_clean(k, eng):
                nk, ch = core.sanitize_token_string(str(k), eng, ctx.psn if ctx else None)
                if ch:
                    eng.count_ids(1)
                return nk
            return k
        return kf

    fctx = eng.file_ctx(doc)

    def walk(node, ptr, depth, parent=None, label=""):
        if ptr in rec_ptrs or (ptr == "" and "doc" in rec_ptrs):
            u = rec_ptrs.get(ptr) or rec_ptrs["doc"]
            ctx = eng.unit_ctx(doc, u)
            ctx.order = order
            slot = {}
            res = _rewrite_json(node, ctx, eng, slot, None, "", order, 0, key_fn_for(ctx))
            if ctx.psn and not ctx.psn_used and isinstance(res, dict):
                # guarantee in-record pseudonym
                res["patient_pseudonym"] = ctx.psn
            return res
        if isinstance(node, dict):
            out = {}
            parent = _dict_ctx(node, parent)
            kf = key_fn_for(None)
            for k, v in node.items():
                nk = kf(k)
                while nk in out:
                    nk = nk + "_"
                p = ptr + "/" + _ptr_escape(k)
                t = _key_type(k, parent)
                if isinstance(v, (dict, list)):
                    out[nk] = walk(v, p, depth + 1, _child_ctx(k, t, parent), k)
                else:
                    if isinstance(v, str) and _pathlike(v):
                        nv, ch = core.sanitize_token_string(v, eng, None)
                        eng.count_ids(1 if ch else 0)
                        out[nk] = nv
                    else:
                        nv, n = rewrite_field(t, v, fctx, k, {}, order)
                        eng.count_ids(n)
                        out[nk] = nv
            return out
        if isinstance(node, list):
            return [walk(el, ptr + "/" + str(i), depth + 1, parent, label) if isinstance(el, (dict, list))
                    else rewrite_field(parent if parent in IDENT_TYPES else None, el, fctx, label, {}, order)[0]
                    for i, el in enumerate(node)]
        return node

    res = walk(obj, "", 0)
    # output pointers for records whose keys were renamed
    for ptr, u in rec_ptrs.items():
        if ptr == "doc":
            continue
        parts = ptr.split("/")[1:]
        newparts, cur = [], obj
        for part in parts:
            k = part.replace("~1", "/").replace("~0", "~")
            if isinstance(cur, list):
                newparts.append(part)
                cur = cur[int(k)]
            else:
                nk = key_fn_for(None)(k) if _key_needs_clean(k, eng) else k
                if _key_needs_clean(k, eng):
                    nk, _ = core.sanitize_token_string(str(k), eng, u.psn)
                newparts.append(_ptr_escape(nk))
                cur = cur[k]
        op = "/" + "/".join(newparts)
        if op != ptr:
            u.out = op
    return json.dumps(res, ensure_ascii=False, indent=2) + "\n"


def _key_needs_clean(k, eng):
    s = str(k)
    if classify_label(s) is not None and not re.search(r"\d{4,}", s):
        return False
    if re.search(r"\d{5,}", s):
        return True
    spans = [sp for sp in eng.detector.detect(re.sub(r"[_\-]+", " ", s)) if sp.kind in PII_KINDS]
    if spans:
        return True
    return any(fold(t) in eng.dyn for t in re.findall(r"[A-Za-z]{3,}|[\u0900-\u097F]+", s))


# ===================================================================== FHIR R4
FHIR_DATE_RX = re.compile(r"^\d{4}(-\d{2}(-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?)?)?$")
FHIR_KEEP_KEYS = {"resourceType", "id", "fullUrl", "reference", "system", "code", "unit", "status", "use", "type",
                  "url", "profile", "gender", "contentType", "language", "version", "div_status"}


def _fhir_shift(v, days):
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})(.*)$", v)
    if m:
        d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))) + dt.timedelta(days=days)
        return "%04d-%02d-%02d%s" % (d.year, d.month, d.day, m.group(4))
    m = re.match(r"^(\d{4})-(\d{2})$", v)
    if m:
        d = dt.date(int(m.group(1)), int(m.group(2)), 15) + dt.timedelta(days=days)
        return "%04d-%02d" % (d.year, d.month)
    return v


def _resources(b):
    if b.get("resourceType") == "Bundle":
        return [e.get("resource") for e in b.get("entry", []) if isinstance(e, dict) and isinstance(e.get("resource"), dict)]
    return [b]


def fhir_extract(doc, eng):
    b = doc.obj
    u = start_unit("doc", doc.hospital)
    pats = [r for r in _resources(b) if r.get("resourceType") == "Patient"]
    for r in pats[:1]:
        for n in r.get("name", []) or []:
            if isinstance(n, dict):
                txt = n.get("text") or " ".join((n.get("given") or []) + ([n.get("family")] if n.get("family") else []))
                if txt:
                    u._name_parts = [txt]
        for idf in r.get("identifier", []) or []:
            if isinstance(idf, dict) and idf.get("value"):
                sysv = str(idf.get("system", "")).lower()
                kind = "ABHA" if ("healthid" in sysv or "abha" in sysv or "ndhm" in sysv) else (
                    "AADHAAR" if "aadhaar" in sysv or "uidai" in sysv else ("PAN" if "pan" in sysv else "MRN"))
                val = digits_only(idf["value"]) if kind == "AADHAAR" else norm_id(idf["value"])
                u.prof.ids[kind].add(val)
        for t in r.get("telecom", []) or []:
            if isinstance(t, dict) and t.get("value"):
                if t.get("system") == "email":
                    u.prof.ids["EMAIL"].add(str(t["value"]).lower())
                elif len(digits_only(t["value"])) >= 10:
                    u.prof.phones.add(norm_phone(t["value"]))
        sx = parse_sex(r.get("gender", ""))
        if sx:
            u.prof.sex = sx
        if r.get("birthDate"):
            pr = parse_full(r["birthDate"])
            if pr and len(r["birthDate"]) >= 10:
                apply_dob(u, pr[0])
        for a in r.get("address", []) or []:
            if isinstance(a, dict):
                if a.get("postalCode"):
                    d = digits_only(a["postalCode"])
                    if len(d) == 6:
                        u.prof.pins.add(d)
                        u.qi["pin"] = d
                if a.get("district"):
                    u.qi["district"] = a["district"]
                    u.prof.districts.add(fold(a["district"]))
                if a.get("state"):
                    u.qi["state"] = a["state"]
                if a.get("city"):
                    u.prof.villages.add(" ".join(name_tokens(a["city"])))
        for c in r.get("contact", []) or []:
            if isinstance(c, dict) and isinstance(c.get("name"), dict):
                nm = c["name"].get("text") or " ".join(c["name"].get("given", []) + [c["name"].get("family", "")])
                rel = "G"
                txt = json.dumps(c.get("relationship", ""), ensure_ascii=False).lower()
                if "husband" in txt or "wife" in txt or "spouse" in txt:
                    rel = "SP"
                elif "father" in txt or "mother" in txt or "parent" in txt:
                    rel = "P"
                toks = tuple(t for t in name_tokens(nm) if t)
                if toks:
                    u.prof.rels.append((rel, toks))
    for r in _resources(b):
        rt = r.get("resourceType")
        if rt == "Encounter":
            per = r.get("period") or {}
            if per.get("start") and per.get("end"):
                a, z = parse_full(per["start"][:10]), parse_full(per["end"][:10])
                if a and z and z[0] >= a[0]:
                    u._adm, u._dis = a[0], z[0]
            for idf in r.get("identifier", []) or []:
                if isinstance(idf, dict) and idf.get("value"):
                    u.prof.ids["MRN"].add(norm_id(idf["value"]))
        if rt == "Condition":
            for c in (r.get("code") or {}).get("coding", []) or []:
                if c.get("code"):
                    u.dx.add(c["code"])
    # narrative / free text evidence (age, ids)
    texts = []
    _collect_strings(b, texts)
    for t in texts:
        spans = eng.detector.detect(t)
        spans_evidence(u, t, [s for s in spans if s.kind not in ("DATE",)], patient_mode=True)
    return [end_unit(u, eng)]


def _collect_strings(node, out, key=None, depth=0):
    if depth > 60:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if k in FHIR_KEEP_KEYS or k == "data":
                continue
            _collect_strings(v, out, k, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _collect_strings(v, out, key, depth + 1)
    elif isinstance(node, str) and key in ("div", "text", "display", "valueString", "description", "title", "comment", "source", "value"):
        out.append(node)


def fhir_rewrite(doc, eng):
    b = json.loads(json.dumps(doc.obj))
    u = doc.units[0]
    ctx = eng.unit_ctx(doc, u)
    pol = eng.policy
    psn = ctx.psn
    for r in _resources(b):
        rt = r.get("resourceType")
        if rt == "Patient":
            r["identifier"] = [{"system": "urn:raksha:pseudonym", "value": psn or "UNLINKED"}]
            r["name"] = [{"use": "anonymous", "text": psn or "[PATIENT]"}]
            ctx.psn_used = bool(psn)
            for k in ("telecom", "photo"):
                if k in r:
                    del r[k]
                    eng.count_ids(1)
            if "birthDate" in r:
                del r["birthDate"]
                eng.count_ids(1)
            if u.age is not None:
                r.setdefault("extension", []).append({"url": "urn:raksha:age-band", "valueString": u.band or age_band(u.age, u.level, pol)})
            addrs = []
            for a in r.get("address", []) or []:
                if not isinstance(a, dict):
                    continue
                na = {}
                if a.get("district") and u.level <= pol["district_level"]:
                    na["district"] = a["district"]
                if a.get("state"):
                    na["state"] = a["state"]
                if a.get("postalCode") and u.level <= pol["pin3_level"]:
                    na["postalCode"] = pin3(digits_only(a["postalCode"]))
                if a.get("country"):
                    na["country"] = a["country"]
                addrs.append(na)
                eng.count_ids(1)
            if "address" in r:
                r["address"] = addrs
            if "contact" in r:
                newc = []
                for c in r["contact"]:
                    if isinstance(c, dict):
                        nc = {k: v for k, v in c.items() if k in ("relationship",)}
                        if not nc:
                            nc = {"relationship": [{"text": "contact"}]}
                        newc.append(nc)
                        eng.count_ids(1)
                r["contact"] = newc
        elif rt == "RelatedPerson":
            for k in ("name", "telecom", "address", "identifier", "photo"):
                if k in r:
                    del r[k]
                    eng.count_ids(1)
    refs = set()
    if b.get("resourceType") == "Bundle":
        for e in b.get("entry", []):
            r = e.get("resource") if isinstance(e, dict) else None
            if isinstance(r, dict) and r.get("resourceType") in ("Patient", "RelatedPerson"):
                if e.get("fullUrl"):
                    refs.add(e["fullUrl"])
                if r.get("id"):
                    refs.add("Patient/" + str(r["id"]))
    eng.current_patient_refs = refs
    b = _fhir_walk(b, ctx, eng, None)
    eng.current_patient_refs = set()
    return json.dumps(b, ensure_ascii=False, indent=2) + "\n"


def _fhir_walk(node, ctx, eng, key, depth=0, parent=None):
    if depth > 80:
        return node
    if isinstance(node, dict):
        rt = node.get("resourceType")
        out = {}
        for k, v in node.items():
            if k == "data" and isinstance(v, str) and node.get("contentType"):
                out[k] = _attachment(v, node.get("contentType"), ctx, eng)
                continue
            if rt == "Practitioner" and k == "name":
                out[k] = v
                continue
            if k.startswith("value") and isinstance(v, (str, int, float)) and not isinstance(v, bool) and isinstance(node.get("url"), str):
                # extension: the url names the field ("…/mothers-name", "…/aadhaar")
                et = classify_label(re.sub(r"[-_]", " ", node["url"].rstrip("/").rsplit("/", 1)[-1]))
                if et in IDENT_TYPES or et in ("relative", "address", "dob", "village", "tehsil", "pin", "contact"):
                    if et in ("name", "first_name", "last_name"):
                        et = "relative" if re.search(r"(?i)mother|father|spouse|husband|wife|guardian|kin|relative", node["url"]) else et
                    nv, n = rewrite_field(et, v, ctx, k, {"name": True, "mrn": True}, None)
                    eng.count_ids(n)
                    out[k] = nv
                    continue
            out[k] = _fhir_walk(v, ctx, eng, k, depth + 1, node)
        if out.get("resourceType") in ("Patient", "Encounter", "Condition", "Observation", "Procedure", "MedicationRequest",
                                       "DocumentReference", "Composition", "DiagnosticReport", "Claim", "Coverage") and "identifier" in out \
                and out.get("resourceType") != "Patient":
            ids = out["identifier"] if isinstance(out["identifier"], list) else [out["identifier"]]
            for idf in ids:
                if isinstance(idf, dict) and "value" in idf and re.search(r"\d{3,}", str(idf["value"])) and not re.fullmatch(r"[0-9a-f-]{36}", str(idf["value"])):
                    idf["value"] = "[ID]"
                    eng.count_ids(1)
        return out
    if isinstance(node, list):
        return [_fhir_walk(v, ctx, eng, key, depth + 1, parent) for v in node]
    if isinstance(node, str):
        if key in FHIR_KEEP_KEYS and key not in ("value",):
            return node
        if FHIR_DATE_RX.match(node) and len(node) >= 7:
            return _fhir_shift(node, ctx.shift)
        if key == "display" and isinstance(parent, dict) and str(parent.get("reference", "")).startswith(("Practitioner", "Organization")):
            return node
        new, n, ents = render_value(node, ctx)
        eng.count_ids(n)
        for k2, c in ents.items():
            eng.entities[k2] = eng.entities.get(k2, 0) + c
        if key == "display" and isinstance(parent, dict) and str(parent.get("reference", "")) in eng.current_patient_refs:
            # displays of references to the Patient are patient names, even if no gazetteer knows them
            return ctx.psn or "[PATIENT]"
        return new
    return node


def _attachment(data, ctype, ctx, eng):
    try:
        raw = base64.b64decode(data, validate=False)
        txt = raw.decode("utf-8")
    except Exception:
        eng.count_ids(1)
        return base64.b64encode(b"[binary attachment removed]").decode()
    new, n, _ = render_value(txt, ctx)
    eng.count_ids(n)
    return base64.b64encode(new.encode("utf-8")).decode()


# ===================================================================== text notes
_RX_KIN_AFTER = re.compile(r"(?i)\s+(?:bhaiya|bhaiyya|bhai|chachu|chacha|chachi|didi|mama|mami|bhabhi|mausi|mausa|nana|nani|dada|dadi|uncle|aunty|fufa|bua|bhaiyaji|chachaji|mamaji)\b|\s*(?:भैया|भाई|चाचा|चाची|दीदी|मामा|मामी|भाभी|मौसी)")


def text_extract(doc, eng):
    order = eng.doc_order(doc)
    year = eng.doc_year(doc)
    text = doc.text
    spans = eng.detector.detect(text, None, order, year)
    doc.spans = spans
    u = start_unit("doc", doc.hospital)
    for s in spans:  # "Jagdish Chachu:", "Kamal Bhaiya" - kinship address terms denote family, not the patient
        if s.kind == "NAME" and s.role != "patient" and _RX_KIN_AFTER.match(text, s.end):
            s.role = "relative"
    names = [s for s in spans if s.kind == "NAME" and s.role != "relative"]
    pat = [s for s in names if s.role == "patient"]
    chosen = None
    if pat:
        chosen = pat[0]
    else:
        groups = []
        for s in names:
            toks = {t for t in core.name_keys(s.text) if len(t) > 1}
            if not toks:
                continue
            for g in groups:
                if g & toks:
                    g |= toks
                    break
            else:
                groups.append(set(toks))
        if names and len(groups) <= 2:
            chosen = names[0]
    if chosen is not None:
        keys = {t for t in core.name_keys(chosen.text) if len(t) > 1}
        for s in names:
            toks = {t for t in core.name_keys(s.text) if len(t) > 1}
            same = bool(toks & keys) or any(_given_compat(a, b) for a in toks for b in keys)
            s.meta["is_patient"] = same
            if same:
                add_name(u, s.text, eng)
    else:
        for s in names:
            s.meta["is_patient"] = False
    sx = core.sex_hints(text, spans)
    if sx:
        u.prof.sex = sx
    spans_evidence(u, text, spans, patient_mode=True)
    # filename clues
    fn = doc.rel.rsplit("/", 1)[-1]
    for m in re.finditer(r"[A-Za-z]{1,6}[-_]?\d{2,4}[-_]\d{3,8}|[A-Za-z]{2,6}\d{5,10}|\d{6,}", fn):
        v = norm_id(m.group(0).replace("_", "-"))
        if sum(c.isdigit() for c in v) >= 5:
            u.prof.ids["MRN"].add(v)
    lines = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1] for l in text.splitlines() if ":" in l}
    adm = dis = None
    for s in spans:
        if s.kind != "DATE":
            continue
        before = text[max(0, s.start - 30):s.start].lower()
        if re.search(r"admi|doa\b|भर्ती", before):
            adm = adm or s.meta["date"]
        elif re.search(r"disch|dod\b|छुट्टी", before):
            dis = dis or s.meta["date"]
    if adm and dis and dis >= adm:
        u.los = (dis - adm).days
        u.ref_date = adm
    m = re.search(r"(?im)^\s*(?:diagnosis|final diagnosis|dx|निदान)\s*[:\-]\s*(.+)$", text)
    if m and not core.ICD_RX.search(m.group(1)):
        u.dx.add(m.group(1).strip().lower()[:80])
    finalize_unit(u, getattr(eng, "ref_year", None))
    doc.name_keymap = {(s.start, s.end): s.meta.get("is_patient") for s in spans if s.kind == "NAME"}
    doc.cued_names = sorted({s.text for s in spans if s.kind == "NAME" and s.role in ("patient", "relative", "cued")})
    doc.spans = None
    return [u]


def _given_compat(a, b):
    from .linkage import _tok_sim
    return len(a) > 2 and len(b) > 2 and _tok_sim(a, b) >= 0.9


def text_rewrite(doc, eng):
    u = doc.units[0]
    ctx = eng.unit_ctx(doc, u)
    ctx.order = eng.doc_order(doc)
    ctx.year = eng.doc_year(doc)
    spans = eng.detector.detect(doc.text, None, ctx.order, ctx.year)
    # re-apply patient decisions (same detector, same text -> same spans)
    keymap = doc.name_keymap
    for s in spans:
        if s.kind == "NAME" and (s.start, s.end) in keymap and keymap[(s.start, s.end)] is not None:
            s.meta["is_patient"] = keymap[(s.start, s.end)]
    new, n, ents = render(doc.text, spans, ctx)
    eng.count_ids(n)
    for k, c in ents.items():
        eng.entities[k] = eng.entities.get(k, 0) + c
    if ctx.psn and not ctx.psn_used:
        new = "Patient: %s\n%s" % (ctx.psn, new)
    return new
