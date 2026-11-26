#!/usr/bin/env python3
"""Local synthetic privacy regression arena. Run only against a trusted team checkout.

No network, external data, production imports or third-party benchmark dependencies.
The evaluated CLI still needs its own dependencies. Exit 0 = passes all local gates,
1 = a measured failure, 2 = benchmark infrastructure error. --seed varies the cohort.
Registry and truth remain in the parent process. All files are temporary.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from datetime import date, timedelta
import hashlib
import hmac
import io
from itertools import combinations
import json
import math
import os
from pathlib import Path
import random
import re
import secrets
import statistics
import subprocess
import sys
import tempfile
import unicodedata
from urllib.parse import unquote, quote

KEEP = ("Dr. Ramesh Gupta reviewed the patient", "C/O fever and vomiting",
        "K/C/O Type 2 DM", "H/O TB in 2018", "Asha worker visited home",
        "Tab. Maya 50mg", "Syrup Anand", "Babinski sign positive", "Koch's lesion seen")
SHIELD = ("PLHIV; ICTC; CD4 count 180", "MTP second trimester", "मानसिक रोग",
          "garbhpaat", "nasha mukti kendra", "POCSO counselling", "leprosy follow-up")
HOSP = ("ART Centre, GMC Lucknow", "Sahyog Clinic", "North Ward Hospital", "River District Hospital")
PSN = re.compile(r"PSN-[0-9A-HJKMNP-TV-Z]{6,52}\Z")
ABC = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
WORDS = "shunya ek do teen chaar paanch chhah saat aath nau".split()


def norm(s):
    chars = unicodedata.normalize("NFKC", str(s)).casefold()
    return "".join(str(unicodedata.decimal(c)) if c.isdecimal() else c
                   for c in chars if c.isalnum() or unicodedata.category(c).startswith("M"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def views(text):
    """Inspect literal, JSON-escaped, URL and bounded base64 representations."""
    decoded = unquote(text)
    decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m[1],16)), decoded)
    result = [decoded]
    for word in re.findall(r"(?<![\w+/])[A-Za-z0-9+/]{8,2048}={0,2}(?![\w+/])", decoded):
        try:
            result.append(base64.b64decode(word,validate=True).decode("utf8"))
        except (ValueError,UnicodeError):
            pass
    return norm("\n".join(result))


@dataclass
class Unit:
    who: int
    file: str
    loc: str
    row: dict
    clinical: tuple
    shield: bool = False


class Corpus:
    def __init__(self, seed):
        rng = random.Random(seed)
        self.files, self.bad, self.units = {}, set(), []
        self.registry, self.tokens = [], defaultdict(set)
        self.canaries = [f"CANARY_TRACK3_SECRET_{rng.getrandbits(64):016X}" for _ in range(5)]
        self.n = 20
        names = ["Md. Rizwan","Sunita Devi","Sunita Devi","Asha Kumari","Ramesh Kumar"]
        given = "Nalin Kavya Ishan Manav Tarun Leena Esha Neel Ira Uday".split()
        family = "Kadam Verma Desai Saini Rao Pal Nair Sen Shah Das".split()
        shared = "9890000077"
        for i in range(5*self.n):
            name = names[i] if i<len(names) else given[i%10]+" "+family[(i//10+i)%10]
            age = (35,42,54,28)[i] if i<4 else rng.randint(19,75)
            self.registry.append(dict(patient_name=name,age=str(age),gender="FM"[i%2],
                district=f"District {i%9}",tehsil=f"Tehsil {i%17}",village=f"Village {i%29}",
                dob=date(2024-age, 3, 15).isoformat(),state="Uttar Pradesh",pin=str(220000+i*17),guardian=f"{given[i%10]} {family[(i+2)%10]}",
                phone=shared if 5<=i<13 else str(9800000000+i*33+seed%10000),
                aadhaar=str(300000000000+i*997+seed%10000),email=f"trial{i}.case@example.invalid",
                house=f"House {100+i}",hospital=HOSP[i%4]))
        for visit in range(2):
            for hospital in range(4):
                rel=f"registry/{visit}-{hospital}."+("tsv" if visit else "csv")
                rows=[]
                for i,p in enumerate(self.registry[:self.n]):
                    if (i+visit)%4 != hospital:
                        continue
                    start=date(2024,1,10)+timedelta(days=rng.randrange(200)+visit*215)
                    condition=SHIELD[i] if i<len(SHIELD) else ("Glucose 95 mg/dL" if i%2 else "BP 150/90")
                    row=dict(p, hospital=HOSP[hospital],MRN=f"MRN-{hospital}-{i+seed%9000:05}",
                             admission=start.isoformat(),discharge=(start+timedelta(days=9)).isoformat(),
                             diagnosis=condition)
                    if i==0 and visit==0:
                        row["patient_name"]="मोहम्मद रिज़वान"
                    if i==1 or i==2:
                        row["guardian"]=("Kiran Bedi","Anil Joshi")[i-1]
                        p["guardian"]=row["guardian"]
                    self.units.append(Unit(i,rel,f"row:{len(rows)}",row,(condition,),i<len(SHIELD)))
                    rows.append(row)
                    for field in ("patient_name","phone","MRN","aadhaar","email"):
                        self.tokens[i].add(row[field])
                table=io.StringIO(newline="")
                writer=csv.DictWriter(table,fieldnames=list(rows[0]),delimiter="\t" if visit else ",")
                writer.writeheader();writer.writerows(rows)
                self.files[rel]=table.getvalue().encode("utf-16" if visit else "utf-8-sig")
        def add(rel,value):
            self.files[rel]=value.encode() if isinstance(value,str) else json.dumps(value,ensure_ascii=False).encode()
        phone="9876543210"
        name="Ramesh Kumar"
        aad="123456789012"
        encoded=base64.b64encode(name.encode()).decode()
        directory=f"case_{self.registry[4]['email']}"
        note_path=f"{directory}/discharge_summary_{phone}_Ramesh.txt"
        note="\n".join((*KEEP,"Attendant Ramesh Gupta was informed","C/O Ramesh Chand","H/O Sunita Devi",
                        "Asha Kumari, age 28",f"+91 98765 \n 43210; encoded {encoded}",
                        quote(name), "patient: Ra\u200bmesh Ku\u200cmar", "９８７６５４３２１０",
                        "१२३४-५६७८-९०१२","XXXX XXXX 1234","1234 5678 9012",
                        "mobile: "+" ".join(WORDS[int(d)] for d in phone),
                        "Dawa time par li. BP 118/78 tha. मरीज को बुखार है।",self.canaries[0]))
        add(note_path,note)
        self.units.append(Unit(4,note_path,"doc",{"patient_name":name,"phone":phone,"note":note},KEEP))
        self.tokens[4].update((name,phone,aad,"XXXX XXXX 1234","Ramesh Gupta","Ramesh Chand",
                               " ".join(WORDS[int(d)] for d in phone)))
        rel="visits/nested.json"
        row=dict(self.registry[3],clinical_note="Pulse 74/min")
        add(rel,{"visits":[row],"metadata":{f"patient_aadhaar_{aad}":encoded,"callback":self.canaries[1]}})
        self.units.append(Unit(3,rel,"/visits/0",row,("Pulse 74/min",)))
        rel="fhir/encounter.json"
        person=self.registry[0]
        add(rel,{"resourceType":"Bundle","type":"collection","entry":[{"resource":{
            "resourceType":"Patient","id":"p1","name":[{"text":person["patient_name"]}],
            "telecom":[{"system":"phone","value":person["phone"]}]}},{"resource":{
            "resourceType":"Observation","id":"o1","status":"final","subject":{"reference":"Patient/p1"},
            "code":{"text":"Serum sodium"},"valueQuantity":{"value":139,"unit":"mmol/L"}}},{"resource":{
            "resourceType":"Binary","id":"b1","contentType":"text/plain","data":
            base64.b64encode(self.canaries[2].encode()).decode()}}]})
        self.units.append(Unit(0,rel,"doc",person,("Serum sodium","139","mmol/L")))
        add("admin/contacts.csv",f"contact_{phone},memo\n{self.canaries[3]},appointment\n")
        add("admin/log.json",{"operator_note":quote(self.canaries[4]),"source_path":"../../secret.txt"})
        self.bad={"broken/quotes.csv","broken/width.csv","broken/mixed.tsv","broken/data.pdf",
                  "broken/photo.jpg","broken/empty.txt","broken/invalid.txt"}
        self.files.update(dict(zip(sorted(self.bad),[b"%PDF-1.4\x00",b"",b"bad\xff\xfe\x81",
            b"name\tage\nCase,35\n",b"\xff\xd8\xff\0",b'name,age\n"open,45\n',b"name,age\nOne,Two,45\n"])))
        self.context_note=note_path


def materialize(root,files):
    for name,data in files.items():
        path=root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)


def invoke(repo,root,inp,key,tag):
    out=root/tag;out.mkdir()
    home=root/(tag+"-home");home.mkdir()
    temp=root/(tag+"-tmp");temp.mkdir()
    python=repo/".venv/bin/python"
    env=dict(os.environ,RAKSHA_SECRET=key,HOME=str(home),TMPDIR=str(temp),PYTHONDONTWRITEBYTECODE="1",
             PYTHONHASHSEED="92" if tag=="repeat" else "11")
    try:
        p=subprocess.run([str(python) if python.is_file() else sys.executable,str(repo/"main.py"),
                          "--input",str(inp),"--output",str(out)],env=env,cwd=repo,
                         stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
        return out,p.returncode,p.stdout,(home,temp)
    except subprocess.TimeoutExpired:
        return out,124,b"",(home,temp)


def files_under(root):
    result={}
    for p in root.rglob("*"):
        if p.is_symlink():
            raise ValueError("symlink in output")
        if p.is_file():
            result[p.relative_to(root).as_posix()]=p.read_bytes()
    return result


def decode(data):
    if data.startswith((b"\xff\xfe",b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-8-sig",errors="replace")


class Release:
    def __init__(self,c,run):
        out,self.exit,logs,extra=run
        self.errors=[]; self.rows={};self.ids={};self.released_ids={};self.surface=[];self.exported={}
        self.rawfiles=files_under(out)
        content={k:decode(v) for k,v in self.rawfiles.items()}
        try:
            report=json.loads(content["report.json"])
            mappings={r["input_sha256"]:r for r in report["files"]}
            expected={digest(v) for v in c.files.values()}
            if set(mappings)!=expected or len(report["files"])!=len(c.files):
                self.errors.append("file manifest")
            for name,raw in c.files.items():
                m=mappings.get(digest(raw),{})
                path=m.get("output")
                if name in c.bad:
                    if not (m.get("status")=="quarantined" and path is None and m.get("reason")):
                        self.errors.append("fault disposition")
                elif m.get("status")=="sanitized" and isinstance(path,str) and path.startswith("sanitized/") and path in content:
                    self.exported[name]=path
                else:
                    self.errors.append("missing clean file")
            counts=report["counts"]
            for field,expected_count in (("files_total",len(c.files)),("files_sanitized",len(self.exported)),
                                         ("files_quarantined",len(c.bad))):
                if counts.get(field)!=expected_count:self.errors.append("inaccurate file totals")
            actual={k for k in content if k.startswith("sanitized/")}
            if actual!=set(self.exported.values()):
                self.errors.append("undeclared output")
            index={}
            for line in content["records.jsonl"].splitlines():
                r=json.loads(line);pair=(r["file"],r["loc"])
                if pair in index:self.errors.append("duplicate locator")
                index[pair]=r
            for i,u in enumerate(c.units):
                path=self.exported.get(u.file)
                if not path:continue
                item=index.get((path,u.loc),{})
                loc=item.get("out",u.loc)
                text=content[path]
                if loc.startswith("row:"):
                    fields=list(csv.DictReader(io.StringIO(text),delimiter="\t" if path.endswith(".tsv") else ","))
                    obj=fields[int(loc[4:])]
                elif loc.startswith("/"):
                    obj=json.loads(text)
                    for token in loc[1:].split("/"):
                        token=token.replace("~1","/").replace("~0","~")
                        obj=obj[int(token)] if isinstance(obj,list) else obj[token]
                elif loc=="doc":
                    obj=json.loads(text) if path.endswith(".json") else {"note":text}
                else:
                    self.errors.append("unknown locator");continue
                self.rows[i]=obj
                pid=item.get("patient")
                if not item:self.errors.append("unindexed record")
                if pid is not None:
                    if isinstance(pid,str) and pid and pid in json.dumps(obj,ensure_ascii=False):
                        self.released_ids[i]=pid
                        if PSN.fullmatch(pid):self.ids[i]=pid
                        else:self.errors.append("invalid pseudonym format")
                    else:self.errors.append("unbound pseudonym")
        except (KeyError,ValueError,TypeError,IndexError,csv.Error):
            self.errors.append("invalid release structure")
        for path,text in content.items():
            if path==self.exported.get(c.context_note):
                text=text.replace(KEEP[0],"",1)
            self.surface.extend((views(path),views(text)))
        self.surface.append(views(decode(logs)))
        for folder in extra:
            for path,data in files_under(folder).items():
                self.surface.extend((views(path),views(decode(data))))


def mean(values):
    values=list(values)
    return statistics.mean(values) if values else 0.0


def band(v):
    m=re.fullmatch(r"\s*(\d{1,3})(?:\s*[-–]\s*(\d{1,3}))?\s*",str(v))
    return (int(m[1]),int(m[2] or m[1])) if m else None


def evidence(row):
    """Extract registry clues from this fixture's tabular, nested and narrative formats."""
    flat=dict(row)
    text=json.dumps(row,ensure_ascii=False)
    def walk(v):
        if isinstance(v,list):
            for item in v:walk(item)
        if isinstance(v,dict):
            if v.get("resourceType")=="Patient":
                names=v.get("name",[])
                if names and isinstance(names[0],dict):flat["patient_name"]=names[0].get("text","")
                for item in v.get("telecom",[]):
                    if item.get("system")=="phone":flat["phone"]=item.get("value","")
            for item in v.values():walk(item)
    walk(row)
    if not flat.get("age"):
        m=re.search(r"(?:age|आयु)\s*[:=]?\s*(\d{1,3}(?:-\d{1,3})?)",text,re.I)
        if m:flat["age"]=m[1]
    if not flat.get("phone"):
        m=re.search(r"(?<!\d)(?:\+91[ -]?)?([6-9]\d{4}[ -]?\d{5})(?!\d)",text)
        if m:flat["phone"]=re.sub(r"\D","",m[1])
    return flat


def chances(registry,rows):
    """A2/A3 skip-empty filtering and weighted identity clues over the synthetic registry."""
    rows=[evidence(r) for r in rows]
    candidates=list(range(len(registry)))
    for field in ("phone","email","aadhaar","district","gender","age","dob","tehsil","village","pin"):
        for row in rows:
            value=str(row.get(field) or "").strip()
            if not value:continue
            def matches(index):
                person=registry[index]
                if field in {"phone","email","aadhaar"} and (index*37)%100>=60:
                    return False
                if field=="dob":
                    return re.search(r"(?:19|20)\d{2}",value) and person[field][:4] in value
                if field=="phone" and re.search(r"[xX*]",value):
                    digits=re.sub(r"[^0-9xX*]","",value)
                    return len(digits)==10 and all(d.lower() in {"x","*",v} for d,v in zip(digits,person[field]))

                if field=="age":
                    b=band(value)
                    return b and b[0]-1<=int(person[field])<=b[1]+2
                if field=="aadhaar":
                    return person[field][-4:]==value[-4:]
                if field=="pin" and value.endswith("***"):
                    return person[field].startswith(value[:3])
                return norm(person[field])==norm(value)
            retained=[i for i in candidates if matches(i)]
            if retained:candidates=retained
    scores={}
    text=norm(" ".join(json.dumps(r,ensure_ascii=False) for r in rows))
    for i in candidates:
        p=registry[i]; full=p["patient_name"]; tokens=full.split()
        weight=60 if norm(full) in text else (8 if norm(tokens[0]) in text else 1)*(3 if norm(tokens[-1]) in text else 1)
        for key,scale in (("guardian",8),("house",2)):
            if norm(p[key]) in text: weight*=scale
        scores[i]=weight
    total=sum(scores.values())
    return {i:s/total for i,s in scores.items()}


def dates(row):
    try:return tuple(date.fromisoformat(row[k]) for k in ("admission","discharge"))
    except (KeyError,ValueError,TypeError):return (None,None)


def groups_for(rows,ids):
    """Pool on either released identifier, including transitive shared references."""
    parent={i:i for i in rows}
    def root(i):
        while parent[i]!=i:
            parent[i]=parent[parent[i]];i=parent[i]
        return i
    seen={}
    for i,row in rows.items():
        for value in [ids.get(i),row.get("patient_ref"),row.get("MRN")]:
            if not isinstance(value,str) or not re.fullmatch(r"[\w./-]{4,}",value):continue
            if value in seen:parent[root(i)]=root(seen[value])
            seen[value]=i
    groups=defaultdict(list)
    for i in rows:groups[root(i)].append(i)
    return list(groups.values())


def arena_risk(c,rows,ids):
    groups=groups_for(rows,ids)
    record={i:chances(c.registry,[r]).get(c.units[i].who,0) for i,r in rows.items()}
    confident=set(); profiles=[]
    for members in groups:
        rs=[rows[i] for i in members]
        prob=chances(c.registry,rs)
        for i in members:
            who=c.units[i].who
            if max(record[i],prob.get(who,0))>=0.5:confident.add(who)
        profiles.append((members,rs,prob))
    # Three known targets, one synthetic nonmember. Targets and visit facts are
    # visible to the evaluator; true profile membership is used only to grade.
    facts={u.who:u.row for u in reversed(c.units) if u.who<3 and dates(u.row)[0]}
    offsets=defaultdict(set)
    for who,fact in facts.items():
        for _,rs,prob in profiles:
            if prob.get(who,0)>=0.9:
                for row in rs:
                    day=dates(row)[0]
                    if day:offsets[(day-dates(fact)[0]).days].add(who)
    votes=sorted(((len(v),d) for d,v in offsets.items()),key=lambda x:(-x[0],abs(x[1]),x[1]))
    delta=votes[0][1] if votes and votes[0][0]>=2 else 0
    decoy=dict(facts[0],admission="2020-01-01",discharge="2020-01-03",diagnosis="decoy")
    results=[]; decoy_hit=False
    for who,fact in [*facts.items(),(c.n,decoy)]:
        weighted=[]
        rare=sum(any(r.get("diagnosis")==fact["diagnosis"] for r in rs) for _,rs,_ in profiles)<=3
        for members,rs,prob in profiles:
            if not prob.get(who):continue
            day,end=dates(fact)
            hitday=any(dates(r)[0] and (dates(r)[0]-day).days==delta for r in rs)
            stay=any(a and b and b-a==end-day for a,b in map(dates,rs))
            cond=any(r.get("diagnosis")==fact["diagnosis"] for r in rs)
            if hitday or stay or cond:
                score=(1+int(hitday))*(8 if cond and rare else 1)*(2 if any(r.get("hospital")==fact["hospital"] for r in rs) else 1)*prob[who]
                weighted.append((members,score))
        total=sum(s for _,s in weighted)
        if who==c.n:
            decoy_hit=bool(weighted);continue
        results.append(sum(s for m,s in weighted if any(c.units[i].who==who for i in m))/total if total else 0)
    return mean(record.get(i,0) for i in range(len(c.units))),len(confident)/c.n,mean(results),delta,decoy_hit


def insecure_labels(original):
    """Known-bad controls for our own synthetic IDs. Never receives a release secret."""
    for value in {original,original.lower(),original.upper(),re.sub(r"\D","",original)}-{""}:
        data=value.encode()
        yield value.casefold()
        yield value[::-1].casefold()
        yield base64.b64encode(data).decode().casefold()
        for binary in (hashlib.md5(data,usedforsecurity=False).digest(),hashlib.sha1(data).digest(),
                       hashlib.sha256(data).digest(),hashlib.sha512(data).digest(),
                       hmac.digest(b"practice",data,"sha256"),hmac.digest(b"",data,"sha256")):
            yield binary.hex()
            bits=int.from_bytes(binary,"big")
            width=(len(binary)*8+4)//5
            bits <<= width*5-len(binary)*8
            yield "".join(ABC[(bits>>(5*i))&31] for i in reversed(range(width))).lower()


def invertible(c,release):
    reverse=defaultdict(set); tokens=defaultdict(set)
    for i,u in enumerate(c.units):
        if i in release.released_ids:tokens[u.who].add(release.released_ids[i].removeprefix("PSN-").casefold())
        reverse[u.who].update(str(u.row[k]) for k in ("MRN","aadhaar","phone","patient_name") if u.row.get(k))
    exposed=0
    for who,pids in tokens.items():
        transforms=[result for v in reverse[who] for result in insecure_labels(v)]
        if any(any(t.startswith(p) for t in transforms) or
               any(v.isdigit() and len(v)>=8 and v in p for v in reverse[who]) for p in pids):
            exposed+=1
    return exposed,len(tokens)


def shifts(c,release):
    byperson=defaultdict(set);expected=Counter();measured=Counter();intervals=True
    for i,u in enumerate(c.units):
        original,discharge=dates(u.row)
        if original:
            expected[u.who]+=1
            start,end=dates(release.rows.get(i,{}))
            if start and end:
                measured[u.who]+=1
                intervals &= end-start==discharge-original
                byperson[u.who].add((start-original).days)
    valid={p:next(iter(v)) for p,v in byperson.items() if len(v)==1 and measured[p]==expected[p]}
    return valid,intervals and len(valid)==len(expected) and all(0<abs(d)<=180 for d in valid.values())


def corr_sample(x,y):
    if len(x)<4 or len(set(x))<2 or len(set(y))<2:return None,None
    mx,my=mean(x),mean(y)
    a=[v-mx for v in x];b=[v-my for v in y]
    den=math.sqrt(sum(v*v for v in a)*sum(v*v for v in b))
    def corr():return sum(i*j for i,j in zip(a,b))/den
    observed=corr();rng=random.Random(2026);extreme=0
    for _ in range(999):
        rng.shuffle(b)
        extreme+=abs(corr())>=abs(observed)-1e-12
    return observed,(extreme+1)/1000


def chaos(repo,tmp,key):
    root=tmp/"chaos"/"input";root.mkdir(parents=True)
    marker=secrets.token_hex(18).encode()
    outside=root.parent/"secret.txt";outside.write_bytes(marker)
    (root/"nest").mkdir()
    (root/"nest"/"outside.txt").symlink_to("../../secret.txt")
    (root/"loop").symlink_to(".",target_is_directory=True)
    (root/"valid.txt").write_text("C/O fever",encoding="utf8")
    out,code,logs,extras=invoke(repo,tmp,root,key,"chaos-out")
    allbytes=[logs,*files_under(out).values()]
    for p in extras:allbytes.extend(files_under(p).values())
    boundary=outside.read_bytes()==marker and all(marker not in s for s in allbytes)
    valid=any(b"C/O fever" in s for s in files_under(out/"sanitized").values())
    return code,boundary,valid


def benchmark(repo,seed,tmp):
    c=Corpus(seed)
    source=tmp/"input";materialize(source,c.files)
    key_a,key_b=secrets.token_hex(32),secrets.token_hex(32)
    runs=[invoke(repo,tmp,source,key,t) for key,t in ((key_a,"a"),(key_a,"repeat"),(key_b,"b"))]
    releases=[Release(c,r) for r in runs]
    a,repeat,b=releases
    chaos_code,boundary,continued=chaos(repo,tmp,key_a)
    checks=[]
    def gate(title,ok,detail):
        checks.append(bool(ok))
        print(f"{'PASS' if ok else 'FAIL':4}  {title:<34} {detail}")
    print(f"Synthetic Secret Wards arena | seed {seed} | {c.n} patients | {len(c.registry)} registry entries | {len(c.units)} labelled records")
    print("Local reproduction of public principles; ratios are relative to this synthetic raw baseline.")
    print("Sensitive-condition policy is a team stress target. This run does not certify legal compliance.")
    gate("CLI and manifest integrity",all(r.exit==0 and not r.errors for r in releases),
         f"exit codes {[r.exit for r in releases]}; structural findings {dict(Counter(e for r in releases for e in r.errors))}")
    gate("Input immutability",files_under(source)==c.files,"checked all input paths and bytes")
    def snapshot(r):return {k:v for k,v in r.rawfiles.items() if k.startswith("sanitized/") or k=="records.jsonl"}
    gate("Same-secret determinism",bool(snapshot(a)) and snapshot(a)==snapshot(repeat),"independent runs and hash seeds")
    gate("Filesystem chaos",chaos_code==0 and boundary and continued,
         f"exit={chaos_code}; sibling sentinel intact/unreleased={boundary}; valid neighbour delivered={continued}")
    gate("Secret leakage",all(not any(norm(k) in s for s in r.surface) for k,r in zip((key_a,key_a,key_b),releases)),
         "release, filenames, stdout/stderr and remaining HOME/TMP files")
    components={}
    for tag,r in (("A",a),("B",b)):
        print(f"\nRelease {tag}")
        total=sum(map(len,c.tokens.values()))
        exposed={who:[v for v in values if any(norm(v) in surface for surface in r.surface)] for who,values in c.tokens.items()}
        hits=sum(map(len,exposed.values()))
        gate("Direct PII Leak Rate",hits==0 and bool(r.rows),f"{hits}/{total} patient-token pairs ({hits/total:.1%}); A1 exposed {sum(bool(v) for v in exposed.values())}/{c.n} people")
        found=sum(any(norm(t) in surface for surface in r.surface) for t in c.canaries)
        gate("Canary Leak Count",found==0 and bool(r.rows),f"{found}/5")
        kept=required=0
        for i,u in enumerate(c.units):
            obj=r.rows.get(i,{})
            text=json.dumps(obj,ensure_ascii=False)
            kept+=sum(s in text for s in u.clinical);required+=len(u.clinical)
        gate("Clinical Span Retention",kept/required>=.98,f"{kept}/{required} ({kept/required:.1%}); missing records count as losses")
        true=fp=fn=0
        for i,j in combinations(range(len(c.units)),2):
            same=c.units[i].who==c.units[j].who
            pred=i in r.ids and r.ids[i]==r.ids.get(j)
            true+=same and pred;fp+=pred and not same;fn+=same and not pred
        precision=true/(true+fp) if true+fp else 0
        recall=true/(true+fn) if true+fn else 0
        gate("Linkage Precision & Recall",precision==1 and recall>=.95,
             f"P={precision:.4f} R={recall:.4f}; TP={true} FP={fp} FN={fn}")
        primary={p:{r.ids.get(i) for i,u in enumerate(c.units) if u.who==p and u.loc.startswith("row:")} for p in range(c.n)}
        def linked(p):return len(primary[p])==1 and None not in primary[p]
        gate("Cross-script fragment",linked(0),"both hospital records need the same in-record PSN")
        gate("Homonym and shared-phone guards",all(linked(p) for p in [1,2,*range(5,13)]) and
             primary[1].isdisjoint(primary[2]) and len(set.union(*(primary[p] for p in range(5,13))))==8,
             "two separated homonyms and eight distinct linked household/service-phone users")
        eligible=[(i,u) for i,u in enumerate(c.units) if u.shield]
        age_ok=facility_ok=location_ok=0
        sensitive_fields=("village","tehsil","district","pin")
        for i,u in eligible:
            row=r.rows.get(i,{})
            banded=band(row.get("age"))
            age_ok+=bool(banded and banded[0]<=int(u.row["age"])<=banded[1] and banded[1]-banded[0]+1>=20)
            text=norm(json.dumps(row,ensure_ascii=False))
            facility_ok+=bool(row) and norm(u.row["hospital"]) not in text
            # Each distinct registry patient has a unique village. Apply the rule
            # when the raw (district, age, condition) cell has fewer than five patients.
            district_cell={v.who for v in c.units if all(v.row.get(k)==u.row.get(k) for k in ("district","age","diagnosis"))}
            location_ok+=bool(row) and (len(district_cell)>=5 or all(
                not str(row.get(k) or "").strip() or str(row[k]).strip() in {"[WITHHELD]","[REDACTED]",u.row["state"]}
                for k in sensitive_fields))
        gate("Sensitive-record shield",min(age_ok,facility_ok,location_ok)==len(eligible),
             f"facility {facility_ok}, truthful age band >=20 {age_ok}, state-or-coarser {location_ok} / {len(eligible)}")
        rawrows={i:u.row for i,u in enumerate(c.units)}
        raw=arena_risk(c,rawrows,{i:str(u.row["aadhaar"]) for i,u in enumerate(c.units) if u.row.get("aadhaar")})
        risk=arena_risk(c,r.rows,r.ids)
        for name,v,base in zip(("A2/A3 registry probability","A4 pooled confidence >=0.5","A5 targeted success"),risk[:3],raw[:3]):
            ratio=v/base if base>0 else math.nan
            gate(name,math.isfinite(ratio) and ratio<1 and len(r.rows)==len(c.units),
                 f"released={v:.4f} raw={base:.4f} relative={ratio:.4f}; local gate: improvement")
        print(f"      A5 inferred global offset {risk[3]:+d} days; decoy matched={risk[4]}")
        offsets,consistent=shifts(c,r)
        known=[offsets[i] for i in range(3) if i in offsets]
        # A constant applied to all three anchors is fully recoverable.
        guard_pass=len(known)==3 and len(set(known))>1 and all(known)
        if len(known)<3:
            finding="INCONCLUSIVE (missing consistent anchors)"
        else:
            finding="100% resistant to one global delta" if guard_pass else "0% resistant"
        resistant=consistent and guard_pass
        gate("Global Shift Recovery Resistance",resistant,
             f"{finding}; {len(set(known))} different shifts among {len(known)}/3 anchors; keyed range and intervals valid={consistent}")
        inverted,seen=invertible(c,r)
        components[tag]=(sum(bool(v) for v in exposed.values())/c.n,
                         *(v/base if base else 1.0 for v,base in zip(risk[:3],raw[:3])),
                         inverted/seen if seen else None)
        gate("A6 synthetic inversion controls",inverted==0 and seen==c.n,
             f"{inverted}/{seen} people matched public weak transforms; {c.n} expected")
    xa,_=shifts(c,a);xb,_=shifts(c,b)
    common=sorted(xa.keys() & xb.keys())
    matched=[i for i in a.ids if i in b.ids]
    stable_id=sum(a.ids[i]==b.ids[i] for i in matched)
    stable_day=sum(xa[p]==xb[p] for p in common)
    rho,pval=corr_sample([xa[p] for p in common],[xb[p] for p in common])
    gate("A7 cross-release linkability",len(matched)==len(c.units) and len(common)==c.n and
         stable_id==stable_day==0 and pval is not None and pval>=.05,
         f"stable IDs {stable_id}/{len(matched)}, stable offsets {stable_day}/{len(common)}, Pearson r={rho}, permutation p={pval}")
    a7=max(stable_id/len(matched),stable_day/len(common)) if matched and common else None
    for tag,values in components.items():
        pairs=[(w,v) for w,v in zip((.2,.2,.2,.2,.1,.1),(*values,a7)) if v is not None]
        weighted=sum(w*min(1.,v) for w,v in pairs)/sum(w for w,_ in pairs)
        print(f"      {tag} synthetic aggregate attack risk {weighted:.1%} before utility coupling")
    print("A7 exact coincidences can occur with independent offsets; zero observed correlation cannot be proved.")
    ok=all(checks)
    print("\nOverall Verdict: ["+("PASSED TO THE MAXIMUM LIMIT" if ok else "FAILED WITH EXPLOITS")+"]")
    return 0 if ok else 1


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo",type=Path,required=True)
    ap.add_argument("--seed",type=int,default=31729)
    args=ap.parse_args()
    repo=args.repo.resolve()
    if not (repo/"main.py").is_file():ap.error("repository must contain main.py")
    try:
        with tempfile.TemporaryDirectory(prefix="secretwards-arena-") as tmp:
            return benchmark(repo,args.seed,Path(tmp))
    except (OSError,ValueError,RuntimeError) as err:
        print(f"Arena infrastructure failure ({type(err).__name__}).",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
