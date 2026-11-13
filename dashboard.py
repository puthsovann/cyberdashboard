#!/usr/bin/env python3
"""
CYBER DASHBOARD :11111 — v4
NVD CVEs + CISA KEV + ransomware.live/ransomfeed.it +
4 news RSS + Exploit-DB index (CVE->PoC mapping).

EDB strategy: the full files_exploits.csv is ~10MB and unsorted by date,
so it is fetched whole ONCE, parsed into a disk index (exploit_index.json),
and re-fetched only when the remote size grows. Sweeps stay fast.

Run:   python3 dashboard.py
Open:  http://localhost:11111
"""

import csv
import io
import json
import os
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import escape, unescape
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("PORT", 11111))  # Render injects $PORT
REFRESH_MAX_AGE = 15 * 60
FETCH_TIMEOUT = 25
UA = {"User-Agent": "CyberDashboard/1.0 (threat-intel aggregator)"}
DDG_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/124.0 Safari/537.36")
CVE_WINDOW = "last 7 days"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

HERE = os.path.dirname(os.path.abspath(__file__))
EDB_CSV_URL = ("https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
               "files_exploits.csv")
EDB_CSV = os.path.join(HERE, "files_exploits.csv")
EDB_INDEX = os.path.join(HERE, "exploit_index.json")
BREACH_CACHE = os.path.join(HERE, "breach_cache.json")
CVE_CACHE = os.path.join(HERE, "cve_cache.json")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
BREACH_AGE = 6 * 3600  # HIBP catalog changes slowly; refetch every 6h

DATA = {
    "cves": [], "kev": [], "news": [], "attacks": [],
    "gangs": [], "updated": None, "errors": [], "ai": [], "breach": [],
    "kh": [], "edb": {"ready": False, "count": 0, "latest": []},
}
DATA_LOCK = threading.Lock()

EDB = {"building": False, "ready": False, "size": None,
       "map": {}, "recs": {}, "latest": [], "error": None}
EDB_LOCK = threading.Lock()


def fetch_url(url, timeout=FETCH_TIMEOUT, headers=None):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
        return r.read()


def fetch_head_size(url):
    req = urllib.request.Request(url, headers=UA, method="HEAD")
    with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as r:
        return int(r.headers.get("Content-Length") or 0)


# ------------------------------------------------------------------ EDB

def _edb_row_ok(r):
    return (r.get("type") or "").lower() in (
        "dos", "webapps", "local", "remote", "shellcode")


def _edb_rec(r):
    return {"id": r.get("id", ""),
            "d": (r.get("description") or "")[:140],
            "date": (r.get("date_published") or "")[:10],
            "type": r.get("type", ""),
            "plat": r.get("platform", ""),
            "ver": (r.get("verified") == "1")}


def build_edb_index(text):
    """CSV text -> ({cve: [ids]}, {id: rec}, newest-first records)."""
    rdr = csv.DictReader(io.StringIO(text))
    mapping, recs, ordered = {}, {}, []
    for r in rdr:
        if not _edb_row_ok(r):
            continue
        rec = _edb_rec(r)
        if not rec["id"]:
            continue
        recs[rec["id"]] = rec
        ordered.append(rec)
        for cve in set(c.upper() for c in CVE_RE.findall(r.get("codes") or "")):
            mapping.setdefault(cve, []).append(rec["id"])
    ordered.sort(key=lambda e: e["date"], reverse=True)
    return mapping, recs, ordered


def save_edb_index(mapping, recs, latest, size):
    keep = latest[:4000]
    slim_map = {cve: ids for cve, ids in mapping.items()
                if cve in {r["id"] for r in keep} or True}  # keys cheap
    # drop mappings whose exploits are all older than the kept window
    kept_ids = {r["id"] for r in keep}
    slim_map = {cve: [i for i in ids if i in kept_ids]
                for cve, ids in mapping.items()}
    slim_map = {cve: ids for cve, ids in slim_map.items() if ids}
    slim_recs = {r["id"]: r for r in keep}
    payload = {"built": datetime.now(timezone.utc).isoformat(),
               "source_size": size, "latest": keep,
               "map": slim_map, "recs": slim_recs}
    with open(EDB_INDEX, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))
    return payload


def load_edb_index():
    with open(EDB_INDEX, encoding="utf-8") as f:
        return json.load(f)


def _edb_apply(mapping, recs, latest, size):
    with EDB_LOCK:
        EDB["map"], EDB["recs"], EDB["latest"] = mapping, recs, latest
        EDB["size"], EDB["ready"] = size, True
    with DATA_LOCK:
        DATA["edb"] = {"ready": True, "count": len(latest),
                       "latest": latest[:25]}


def _edb_download_full(target_size):
    """Resumable path: many Range legs, since peers reset long-lived
    transfers. Appends local file until it reaches target_size."""
    have = os.path.getsize(EDB_CSV) if os.path.exists(EDB_CSV) else 0
    if target_size and have >= target_size:
        return have
    for _ in range(14):
        if target_size and have >= target_size:
            break
        req = urllib.request.Request(
            EDB_CSV_URL, headers={**UA, "Range": f"bytes={have}-"})
        try:
            with urllib.request.urlopen(req, timeout=90,
                                        context=SSL_CTX) as r:
                chunk = r.read()
        except Exception:
            chunk = b""
        if not chunk:
            break
        with open(EDB_CSV, "ab" if have else "wb") as f:
            f.write(chunk)
        have += len(chunk)
    return os.path.getsize(EDB_CSV) if os.path.exists(EDB_CSV) else 0


def _edb_build_thread():
    with EDB_LOCK:
        if EDB["building"]:
            return
        EDB["building"] = True
    try:
        t0 = time.time()
        size = None
        try:
            size = fetch_head_size(EDB_CSV_URL)
        except Exception:
            pass
        complete = (os.path.exists(EDB_CSV) and
                    ((size is None and os.path.getsize(EDB_CSV) > 0) or
                     os.path.getsize(EDB_CSV) == size))
        if not complete:
            print(f"  [*] EDB: resumable fetch of full CSV "
                  f"({(size or 0) / 1e6:.1f} MB, one-time build)...",
                  flush=True)
            got = _edb_download_full(size or 0)
            if size and got != size:
                raise RuntimeError(f"CSV incomplete: got {got}/{size}")
        mapping, recs, latest = build_edb_index(
            open(EDB_CSV, encoding="utf-8", errors="replace").read())
        save_edb_index(mapping, recs, latest, size or os.path.getsize(EDB_CSV))
        _edb_apply(mapping, recs, latest, size or 0)
        with EDB_LOCK:
            EDB["error"] = None
        print(f"  [+] EDB index: {len(mapping)} CVEs mapped, "
              f"{len(latest)} exploits, {time.time() - t0:.0f}s",
              flush=True)
    except Exception as exc:
        with EDB_LOCK:
            EDB["error"] = str(exc)
        print(f"  [-] EDB build: {exc}", flush=True)
    finally:
        with EDB_LOCK:
            EDB["building"] = False


def edb_tick():
    """Fast path: disk index is current -> load & serve it. Otherwise
    kick the (heavy) builder in its own thread so sweeps never block."""
    try:
        if os.path.exists(EDB_INDEX):
            idx = load_edb_index()
            size = idx.get("source_size") or 0
            try:
                remote = fetch_head_size(EDB_CSV_URL)
            except Exception:
                remote = None

            def fresh(xsize):
                return (remote is None and xsize) or (remote == xsize)

            if idx.get("map") and fresh(size):
                with EDB_LOCK:
                    was_ready = EDB["ready"]
                if not was_ready:  # apply outside the lock — _edb_apply
                    _edb_apply(idx["map"], idx["recs"],  # takes it itself
                               idx.get("latest", []), size)
                    print(f"  [+] EDB index loaded from disk: "
                          f"{len(idx['map'])} CVEs mapped", flush=True)
                return
        with EDB_LOCK:
            if EDB["building"]:
                return
            if EDB["ready"]:
                return  # already built, size change checked next sweep
        threading.Thread(target=_edb_build_thread, daemon=True).start()
    except Exception as exc:
        with EDB_LOCK:
            EDB["error"] = str(exc)
        print(f"  [-] EDB index: {exc}", flush=True)


# --------------------------------------------------------- other sources

def _cve_load():
    """Last good CVE slice from disk — a cold boot is never blank."""
    try:
        with open(CVE_CACHE, encoding="utf-8") as f:
            return json.load(f).get("cves") or []
    except Exception:
        return []


def _cve_save(cves):
    try:
        with open(CVE_CACHE, "w", encoding="utf-8") as f:
            json.dump({"saved": datetime.now(timezone.utc).isoformat(),
                       "cves": cves[:120]}, f)
    except Exception:
        pass


def nvd_recent_cves(days=2):
    """Recent published CVEs (NVD 2.0, keyless) — adaptive window."""
    global CVE_WINDOW

    def query(d_from, start=0):
        first = (datetime.now(timezone.utc) - timedelta(days=d_from)
                 ).strftime("%Y-%m-%dT%H:%M:%S.000")
        end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?pubStartDate={first}&pubEndDate={end}"
               f"&resultsPerPage=600&startIndex={start}")
        hdr = {}
        key = os.environ.get("NVD_API_KEY")
        if key:
            hdr["apiKey"] = key
        return json.loads(fetch_url(url, headers=hdr, timeout=45
                                    ).decode("utf-8", "replace"))

    raw, total, span = None, 0, days
    ladder = [days] + [d for d in (3, 2, 1) if d < days]
    for span in ladder:
        try:
            raw = query(span)
        except Exception as exc:
            print(f"  [-] NVD {span}d window: {exc}", flush=True)
            continue
        total = raw.get("totalResults", 0)
        if total <= 600:
            break
    if raw is None:
        raise RuntimeError("NVD unreachable at every window")
    if total > 600:
        try:
            raw = query(1, start=max(total - 600, 0))
        except Exception as exc:
            print(f"  [-] NVD newest slice: {exc}", flush=True)
    CVE_WINDOW = ("24h (newest slice)" if total > 600
                  else f"last {span} days")

    out = []
    for v in raw.get("vulnerabilities", []):
        cve = v.get("cve", {})
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score, severity = None, "UNKNOWN"
        for metric in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30",
                       "cvssMetricV2"):
            m = cve.get("metrics", {}).get(metric)
            if m:
                cd = m[0].get("cvssData", {})
                score = cd.get("baseScore")
                severity = (cd.get("baseSeverity")
                            or m[0].get("baseSeverity", "UNKNOWN")).upper()
                break
        out.append({
            "id": cve.get("id", "?"),
            "description": desc,
            "score": score if score is not None else 0.0,
            "severity": severity,
            "published": (cve.get("published", "") or "")[:10],
        })
    out.sort(key=lambda c: c["published"], reverse=True)
    out = out[:80]
    _cve_save(out)
    return out


def cisa_kev():
    raw = json.loads(fetch_url(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ).decode("utf-8", "replace"))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=14)
              ).strftime("%Y-%m-%d")
    recent = [v for v in raw.get("vulnerabilities", [])
              if (v.get("dateAdded") or "") >= cutoff]
    if len(recent) < 10:
        recent = raw.get("vulnerabilities", [])[-25:]
    out = [{
        "id": v.get("cveID", "?"),
        "vendor": v.get("vendorProject", "?"),
        "product": v.get("product", "?"),
        "name": v.get("vulnerabilityName", ""),
        "date": v.get("dateAdded", ""),
        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
    } for v in recent]
    out.sort(key=lambda v: v["date"], reverse=True)  # newest added first
    return out


def _rf_norm(entries, gang_key, date_key):
    out = []
    for e in entries:
        out.append({
            "gang": (e.get(gang_key) or "unknown").casefold(),
            "victim": e.get("victim") or e.get("domain") or "unknown",
            "country": e.get("country") or "",
            "date": (e.get(date_key) or "")[:10],
            "url": e.get("url") or "",
        })
    return out


def attacks_ransomware():
    items = []
    try:
        raw = json.loads(fetch_url(
            "https://api.ransomware.live/v2/recentvictims"
        ).decode("utf-8", "replace"))
        items.extend(_rf_norm(raw[:120], "group", "discovered"))
    except Exception:
        pass
    try:
        raw = json.loads(fetch_url(
            "https://api.ransomfeed.it/posts?limit=100"
        ).decode("utf-8", "replace"))
        items.extend(_rf_norm(raw[:120], "gang", "date"))
    except Exception:
        pass
    seen, dedup = set(), []
    for e in items:
        k = (e["gang"], e["victim"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(e)
    dedup.sort(key=lambda e: e["date"], reverse=True)  # newest claims first
    return dedup


def _norm_date(raw):
    """Any feed date -> 'YYYY-MM-DD [HH:MM]' so lexicographic == temporal."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if re.match(r"^\d{4}-\d{2}-\d{2}", raw):
        return raw[:16].replace("T", " ")
    try:
        return parsedate_to_datetime(raw).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return raw[:16]


def parse_feed(xml_bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []
    atom = root.tag.startswith("{http://www.w3.org/2005/Atom")
    items = []
    if atom:
        NS = "{http://www.w3.org/2005/Atom}"
        for e in root.findall(NS + "entry")[:12]:
            def gt(tag):
                el = e.find(NS + tag)
                return (el.text or "").strip() if el is not None else ""
            link = ""
            le = e.find(NS + "link")
            if le is not None:
                link = le.get("href", "")
            items.append({"title": gt("title"), "link": link,
                          "date": _norm_date(gt("updated")
                                             or gt("published"))})
    else:
        for it in root.iter("item"):
            def gt(tag):
                el = it.find(tag)
                return (el.text or "").strip() if el is not None else ""
            items.append({"title": gt("title"), "link": gt("link"),
                          "date": _norm_date(gt("pubDate"))})
    return items[:12]


def hacker_news():
    return [{"source": "The Hacker News", **i}
            for i in parse_feed(fetch_url(
                "https://feeds.feedburner.com/TheHackersNews"))]


def bleeping():
    return [{"source": "BleepingComputer", **i}
            for i in parse_feed(fetch_url(
                "https://www.bleepingcomputer.com/feed/"))]


def krebs():
    return [{"source": "Krebs on Security", **i}
            for i in parse_feed(fetch_url(
                "https://krebsonsecurity.com/feed/"))]


def exploit_db():
    return [{"source": "Exploit-DB", **i}
            for i in parse_feed(fetch_url(
                "https://www.exploit-db.com/rss.xml"))]


# ---- AI wire ---------------------------------------------------------------

def _lane_of(title):
    """Classify an AI headline into a lane. Keyword-honest, no magic."""
    t = (title or "").lower()
    if any(w in t for w in (
            "prompt injection", "jailbreak", "attack on ai", "ai attack",
            "ai malware", "deepfake", "deep fake", "ai hack", "hacking ai",
            "ai botnet", "model theft", "ai phishing", "ai scam",
            "ai-assisted attack", "poisoning", "backdoor")):
        return "ATTACK"
    if any(w in t for w in (
            "security", "vulnerab", "breach", "exploit", "leak", "risk",
            "guardrail", "safety", "fraud", "abuse", "misuse", "bias",
            "regulat", "policy", "law", "ban")):
        return "SECURITY"
    if any(w in t for w in (
            "release", "released", "launched", "launch", "unveil",
            "announc", "introduc", "debuts", "debuted", "open-weights",
            "open source", "open-source", "weights", "benchmark",
            "outperform", "rolls out", "rollout", "ships", "v3", "v4",
            "gpt", "claude", "gemini", "llama", "deepseek", "mistral",
            "qwen", "model")):
        return "RELEASE"
    return "RESEARCH"


def ai_news():
    """AI lane: model releases, security, AI-directed attacks. Four
    keyless sources; each sub-feed fails soft."""
    items = []

    def add(src, xs):
        for i in xs:
            i = {**i, "source": src, "lane": _lane_of(i["title"])}
            items.append(i)

    try:
        add("VentureBeat AI", parse_feed(fetch_url(
            "https://venturebeat.com/category/ai/feed/")))
    except Exception:
        pass
    try:
        add("The Decoder", parse_feed(fetch_url(
            "https://www.the-decoder.com/feed/")))
    except Exception:
        pass
    try:
        add("MarkTechPost", parse_feed(fetch_url(
            "https://www.marktechpost.com/feed/")))
    except Exception:
        pass
    try:
        raw = json.loads(fetch_url(
            "https://www.reddit.com/r/MachineLearning/new.json?limit=14"
            "&raw_json=1").decode("utf-8", "replace"))
        rs = []
        for c in raw.get("data", {}).get("children", []):
            ch = c.get("data", {})
            if ch.get("stickied"):
                continue
            dt = datetime.fromtimestamp(
                ch.get("created_utc", 0), tz=timezone.utc
            ).strftime("%Y-%m-%d")
            rs.append({"title": ch.get("title", ""),
                       "link": "https://www.reddit.com" + ch.get("permalink", ""),
                       "date": dt})
        add("r/MachineLearning", rs[:10])
    except Exception:
        pass

    seen, ded = set(), []
    for i in items:
        k = i["title"].lower()[:72]
        if k in seen:
            continue
        seen.add(k)
        ded.append(i)
    ded.sort(key=lambda i: i.get("date", ""), reverse=True)
    return ded[:16]


# ---- data breaches ---------------------------------------------------------

B = {"building": False, "breaches": [], "fetched": 0.0}
B_LOCK = threading.Lock()


def _fmt_count(n):
    try:
        n = int(n)
    except Exception:
        return ""
    if n >= 1_000_000_000:
        return f"{n / 1e9:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1e6:.1f}M"
    if n >= 1_000:
        return f"{n / 1e3:.0f}K"
    return str(n)


def _extract_records(title):
    """Mine a record count out of a breach headline. Scale words only
    count when a victim noun backs them ('4.9 million customers'), so a
    '¥5.5 billion loss' never reads as records. Bare comma-grouped
    numbers of 100k+ stand alone."""
    t = title or ""
    victim = re.search(
        r"(record|user|customer|account|people|email|password|credential|"
        r"victim|individual|patient|employee|client|member|person|"
        r"subscriber|consumer|resident|student|userbase)", t, re.I)
    m = re.search(r"(\d[\d,]*\.?\d*)\s*(million|billion|thousand)", t, re.I)
    if m and victim:
        mult = {"million": 1e6, "billion": 1e9,
                "thousand": 1e3}[m.group(2).lower()]
        try:
            return int(float(m.group(1).replace(",", "")) * mult)
        except ValueError:
            return None
    m = re.search(r"\b\d{1,3}(?:,\d{3}){2,}\b", t)
    if m:
        return int(m.group(0).replace(",", ""))
    return None


def _breach_fetch():
    raw = json.loads(fetch_url(
        "https://haveibeenpwned.com/api/v3/breaches",
        timeout=150).decode("utf-8", "replace"))
    items = []
    for b in raw:
        items.append({
            "org": b.get("Name") or b.get("Title") or "?",
            "date": (b.get("BreachDate") or "")[:10],
            "added": b.get("AddedDate") or "",
            "records": b.get("PwnCount"),
            "classes": ", ".join(b.get("DataClasses") or [])[:90],
            "domain": (b.get("Domain") or "").lower(),
            "desc": (b.get("Description") or "")[:400],
            "link": ("https://haveibeenpwned.com/PwnedWebsites#"
                     + urllib.parse.quote(b.get("Name") or "")),
            "source": "HIBP",
        })
    items.sort(key=lambda x: x.get("added") or "", reverse=True)
    return items


def _breach_thread():
    with B_LOCK:
        if B["building"]:
            return
        B["building"] = True
    try:
        t0 = time.time()
        items = _breach_fetch()
        with B_LOCK:
            B["breaches"] = items
            B["fetched"] = time.time()
        with open(BREACH_CACHE, "w", encoding="utf-8") as f:
            json.dump({"fetched": B["fetched"], "breaches": items}, f)
        print(f"  [+] HIBP breaches cached: {len(items)} records, "
              f"{time.time() - t0:.0f}s", flush=True)
    except Exception as exc:
        print(f"  [-] HIBP breaches: {exc}", flush=True)
    finally:
        with B_LOCK:
            B["building"] = False


def breach_tick():
    """Load HIBP catalog from disk; refetch in a thread when stale."""
    try:
        if not B["breaches"] and os.path.exists(BREACH_CACHE):
            with open(BREACH_CACHE, encoding="utf-8") as f:
                c = json.load(f)
            with B_LOCK:
                B["breaches"] = c.get("breaches") or []
                B["fetched"] = c.get("fetched") or 0
            print(f"  [+] HIBP cache loaded: {len(B['breaches'])} breaches",
                  flush=True)
        with B_LOCK:
            stale = (time.time() - B["fetched"]) > BREACH_AGE
            building = B["building"]
        if stale and not building:
            threading.Thread(target=_breach_thread, daemon=True).start()
    except Exception as exc:
        print(f"  [-] breach tick: {exc}", flush=True)


def breach_feed():
    """Breach panel: HIBP catalog (cached) + DataBreaches.net wire.
    Sorted by when the intel surfaced — newest first."""
    items = []
    with B_LOCK:
        for b in B["breaches"][:10]:
            items.append({"kind": "catalog", "title": b["org"],
                          "classes": b.get("classes", ""),
                          "link": b["link"], "date": b.get("date", ""),
                          "records": b.get("records"),
                          "source": "HIBP catalog",
                          "sort": b.get("added") or b.get("date", "")})
    try:
        for i in parse_feed(fetch_url(
                "https://www.databreaches.net/feed/")):
            items.append({
                "kind": "report", "title": i["title"], "link": i["link"],
                "date": i["date"], "records": _extract_records(i["title"]),
                "classes": "", "source": "DataBreaches.net",
                "sort": i["date"],
            })
    except Exception:
        pass
    items.sort(key=lambda x: x.get("sort") or "", reverse=True)
    return items[:14]


# ------------------------------------------------------------- KH Watch
# Cambodia-facing exposure watch. Every lane is a public surface:
# Google/Bing news RSS, Reddit search JSON, Telegram public previews,
# fxtwitter's public mirror of a post, and the ransomware feeds already
# on this board. No Tor client and no paid API: leak-site claims reach
# this panel through the mirrors those feeds republish.

KH_TERMS = (
    # country, provinces, scripts
    "cambodia", "cambodian", "kampuchea", "khmer", "phnom penh",
    "sihanoukville", "siem reap", "battambang", "kampong cham",
    "kampong", "kandal", "preah sihanouk", "koh kong", "kratie",
    "takeo", "pursat", "svay rieng", "mondulkiri", "ratanakiri",
    ".gov.kh", ".com.kh", ".edu.kh", ".org.kh", ".net.kh",
    "柬埔寨", "高棉", "កម្ពុជា",
    # state
    "cambodia securities exchange", "national bank of cambodia",
    "ministry of interior", "ministry of commerce",
    "ministry of environment", "misti", "ministry of education",
    "ministry of health", "ministry of economy", "council of ministers",
    "national employment agency", "nea.gov.kh", "moe.gov.kh",
    "misti.gov.kh", "mptc", "telecom cambodia",
    # finance / fintech
    "aba bank", "acleda", "wing bank", "canadia bank", "j trust royal",
    "cambodia post bank", "vattanac bank", "ftb bank", "maybank cambodia",
    "sathapana", "amret", "hattha", "prasac", "chokchey",
    "bakong", "khqr", "pi pay", "aba pay",
    # telecom / isp / utilities
    "cellcard", "smart axiata", "metfone", "seatel", "cootel",
    "ezecom", "sabay", "electricite du cambodge",
    # conglomerates / retail / gaming
    "royal group", "chip mong", "prince group", "nagacorp", "nagaworld",
    "sokha", "borey", "aeon mall cambodia", "tk avenue",
    "angkor beer", "cambrew", "khmer beverages",
    # travel / services
    "cambodia airports", "angkor air", "sky angkor", "passapp",
    "nham24", "foodpanda cambodia",
    # education
    "royal university of phnom penh", "institute of technology of cambodia",
    "num cambodia",
    # media
    "khmer times", "phnom penh post", "vod cambodia", "cambojanews",
)

KH_LANES = ("RANSOM", "LEAK", "BREACH", "DARKWEB", "SOCIAL", "REPORT")

# A KH mention alone is not a signal — an independence-day parade is not
# intel. Require a compromise/exposure word too (unless the row is a
# watchlisted post or a ransomware/HIBP record, which are forced).
KH_SIGNAL_CJK = ("黑客", "入侵", "泄露", "勒索", "数据泄露", "网络攻击", "攻击")
KH_STRONG_RE = re.compile(
    r"\b(breach\w*|hack(?:ed|er|ers|ing)|ransom\w*|malware|trojan|"
    r"infostealer|spyware|botnet|ddos|exfil\w*|credential\w*|"
    r"password\w*|database|dark ?web|leak site|vulnerab\w*|"
    r"cve-\d{4}-\d+|phish\w*|threat actor|data (?:leak|breach|dump)|"
    r"records|rats?)\b", re.I)
KH_WEAK_RE = re.compile(r"\b(leak\w*|attack\w*|exploit\w*|exposed|"
                        r"hacktivist)\b", re.I)
KH_DATA_RE = re.compile(r"\b(data|database|records|credentials|passwords|"
                        r"users|customers|accounts|portal)\b", re.I)


def _kh_signal(text):
    """Strong breach word, or a weak verb backed by a data noun."""
    t = text or ""
    if KH_STRONG_RE.search(t):
        return True
    if any(w in t.lower() for w in KH_SIGNAL_CJK):
        return True
    return bool(KH_WEAK_RE.search(t) and KH_DATA_RE.search(t))

# Ambiguous on their own: correct for Cambodia, but also every other
# country's ministry. Only allowed through when the row is already
# Cambodia-scoped (news query, country field, .kh domain).
KH_GENERIC_TERMS = (
    "ministry of health", "ministry of commerce", "ministry of interior",
    "ministry of education", "ministry of economy", "council of ministers",
    "national employment agency",
)

KH_LANE_HINTS = (
    ("RANSOM", ("ransomware", "ransom", "lockbit", "akira", "clop",
                "leak site", "extort", "blackcat", "勒索")),
    ("LEAK", ("leak", "dump", "database", "db dump", "records",
              "exfil", "for sale", "sold", "combolist", "credentials",
              "passwords", "dataset", "data set", "泄露", "数据")),
    ("BREACH", ("breach", "compromis", "hack", "intrusion",
                "unauthorized", "exposed", "黑客", "入侵")),
    ("DARKWEB", ("dark web", "darkweb", "onion", "forum", "broker",
                 "initial access", "threat actor", "underground",
                 "scam", "fraud")),
)

KH_NEWS_Q = (
    ("Cambodia data breach", "en-US", "US", "US:en"),
    ("Cambodia leak hacker", "en-US", "US", "US:en"),
    ("Cambodia ransomware", "en-US", "US", "US:en"),
    ("Cambodia database exposed", "en-US", "US", "US:en"),
    ("Cambodia hacked", "en-US", "US", "US:en"),
    ("Cambodia cyber attack", "en-US", "US", "US:en"),
    ("Cambodian bank data breach", "en-US", "US", "US:en"),
    ("Cambodia scam compound data leak", "en-US", "US", "US:en"),
    ("柬埔寨 数据 泄露", "zh-CN", "CN", "CN:zh-Hans"),
    ("柬埔寨 黑客 入侵", "zh-CN", "CN", "CN:zh-Hans"),
    ("柬埔寨 网络攻击", "zh-CN", "CN", "CN:zh-Hans"),
    ("កម្ពុជា ទិន្នន័យ", "km", "KH", "KH:km"),
)

# Cambodian newsrooms that answer keylessly. Phnom Penh Post sits behind
# Cloudflare and Kiripost renders client-side, so both are skipped.
KH_FEEDS = (
    ("Khmer Times", "https://www.khmertimeskh.com/feed/"),
    ("VOD English", "https://vodenglish.news/feed/"),
    ("CamboJA", "https://cambojanews.com/feed/"),
)

KH_TG = tuple(c.strip() for c in os.environ.get(
    "KH_TELEGRAM_CHANNELS",
    "falconfeedsio,databreaches,leakbase,CyberSecurityTechnologies"
).split(",") if c.strip())

KH_SEED_POSTS = tuple(u.strip() for u in os.environ.get(
    "KH_WATCH_POSTS",
    "https://x.com/DailyDarkWeb/status/2120953398006837629,"
    "https://x.com/VECERTRadar/status/2118895424433987877"
).split(",") if u.strip())

# Accounts whose KH posts should be hunted by site-scoped index queries.
KH_X_ACCOUNTS = tuple(a.strip().lstrip("@") for a in os.environ.get(
    "KH_X_ACCOUNTS",
    "VECERTRadar,DailyDarkWeb,DarkWebInformer,CyberThreatLine,"
    "FalconFeedsio,HackManac,ThreatMon,ransomwatch"
).split(",") if a.strip())

# X has no keyless search API. This lane goes through the search index
# (DuckDuckGo lite), then resolves each indexed status URL through
# fxtwitter. The index throttles datacenter IPs, so queries rotate one
# per sweep, results persist on disk, and a 202 buys a 30-minute backoff.
KH_X_QUERIES = tuple(q.strip() for q in os.environ.get(
    "KH_X_QUERIES",
    "dark web cambodia,cambodia data leak,cambodia breach,"
    "cambodia ransomware,cambodia hacker"
).split(",") if q.strip())

X_SEARCH_CACHE = os.path.join(HERE, "x_search_cache.json")
X_SEARCH_BACKOFF = 30 * 60

# Reddit's own JSON/RSS endpoints 403 or 429 datacenter IPs, so this lane
# rides Arctic Shift's public Reddit archive instead: keyless, no auth,
# full-text search scoped to a subreddit. It times out under load, so
# results persist and a failure buys a 20-minute backoff.
REDDIT_CACHE = os.path.join(HERE, "reddit_cache.json")
REDDIT_BACKOFF = 10 * 60


KH_REDDIT_SUBS = tuple(s.strip() for s in os.environ.get(
    "KH_REDDIT_SUBS",
    # low-volume subs first: 100 recent posts there spans weeks, so a
    # Cambodia mention is actually findable by recency alone
    "DataBreach,ransomware,threatintel,blueteamsec,scambait,"
    "netsec,cybersecurity,darknet,privacy"
).split(",") if s.strip())

KH_REDDIT_Q = ("cambodia", "khmer")

# A subreddit post is not Cambodia-scoped context, so it must name a cyber
# mechanism itself. Without this, "breach of contract" and robbery stories
# from r/cambodia read as data breaches.
KH_CYBER_RE = re.compile(
    r"\b(hack\w*|ransom\w*|malware|trojan|infostealer|spyware|botnet|"
    r"ddos|exfil\w*|credential\w*|password\w*|database|dark ?web|"
    r"leak ?site|vulnerab\w*|cve-\d{4}-\d+|phish\w*|threat actor|"
    r"data (?:leak|breach|dump)|cyber\w*|scam\w* compound|"
    r"infosec|opsec)\b", re.I)


def _kh_hit_strict(text):
    """KH hit that ignores generic ministries/banks.

    The global ransomware feed is not Cambodia-scoped, so "Ministry of
    Health" alone put Malaysia's MoH in this panel. Only a uniquely
    Cambodian term (or the KH country field) may admit a row from it.
    """
    t = (text or "").lower()
    for term in KH_GENERIC_TERMS:
        t = t.replace(term, " ")
    return _kh_hit(t)


KH_TERM_RE = re.compile(
    r"(?<![a-z0-9])("
    + "|".join(re.escape(t) for t in KH_TERMS if "." not in t)
    + r")(?![a-z0-9])", re.I)
KH_TERM_RAW = tuple(t for t in KH_TERMS if "." in t)


def _kh_hit(text):
    """First KH term present in the text, or ''.

    Word boundaries matter: a bare substring check made "takeo" hit
    "account takeover" and put a French credential-stuffing list in a
    Cambodian breach panel.
    """
    t = (text or "").lower()
    m = KH_TERM_RE.search(t)
    if m:
        return m.group(1)
    for term in KH_TERM_RAW:
        if term in t:
            return term
    return ""


KH_CONFLICT_RE = re.compile(
    r"(tarnish|accus\w+|den(?:y|ies)|retaliat\w+|"
    r"strengthen\w* (?:cyber|defen\w+)|"
    r"cyber (?:conflict|escalation|warfare|war)|state-sponsored|"
    r"claims? (?:it|that)|military|border)", re.I)


def _kh_lane(title, source=""):
    t = (title or "").lower()
    if any(w in t for w in ("hacktivist", "cyber conflict",
                            "cyber escalation", "cyber warfare",
                            "state-sponsored", "tarnish")):
        return "REPORT"
    if KH_CONFLICT_RE.search(t) and "thailand" in t:
        return "REPORT"
    for lane, words in KH_LANE_HINTS:
        if any(w in t for w in words):
            return lane
    s = (source or "").lower()
    if any(w in s for w in ("x.com", "twitter", "telegram", "facebook",
                            "reddit")):
        return "SOCIAL"
    return "REPORT"


def _gnews(q, hl, gl, ceid):
    url = ("https://news.google.com/rss/search?q="
           + urllib.parse.quote_plus(q)
           + f"&hl={hl}&gl={gl}&ceid={ceid}")
    out = []
    for i in parse_feed(fetch_url(url, headers={"User-Agent": "Mozilla/5.0"})):
        title = re.sub(r"\s+-\s+[^-]{2,42}$", "", i["title"]).strip()
        out.append({**i, "title": title})
    return out


def _bing_news(q):
    url = ("https://www.bing.com/news/search?q="
           + urllib.parse.quote_plus(q) + "&format=RSS")
    return parse_feed(fetch_url(url, headers={"User-Agent": "Mozilla/5.0"}))


def _reddit_load():
    try:
        with open(REDDIT_CACHE, encoding="utf-8") as f:
            st = json.load(f)
        if isinstance(st, dict):
            st.setdefault("next", 0)
            st.setdefault("items", [])
            st.setdefault("blocked", 0)
            return st
    except Exception:
        pass
    return {"next": 0, "items": [], "blocked": 0}


def _reddit_save(st):
    try:
        with open(REDDIT_CACHE, "w", encoding="utf-8") as f:
            json.dump(st, f)
    except Exception:
        pass


def _arctic(sub, query=None, limit=100):
    """Arctic Shift: one subreddit, optional full-text query."""
    url = ("https://arctic-shift.photon-reddit.com/api/posts/search"
           "?subreddit=" + urllib.parse.quote(sub)
           + f"&limit={limit}&sort=desc")
    if query:
        url += "&query=" + urllib.parse.quote_plus(query)
    raw = json.loads(fetch_url(url, timeout=30).decode("utf-8", "replace"))
    if raw.get("error"):
        raise RuntimeError(str(raw["error"]))
    return raw.get("data") or []


def _reddit_kh():
    """r/cambodia every sweep (both queries), plus two rotating subs."""
    st = _reddit_load()
    now = time.time()
    if now < float(st.get("blocked") or 0):
        return st.get("items") or []
    subs = list(KH_REDDIT_SUBS)
    if not subs:
        return st.get("items") or []

    idx = int(st.get("next", 0))
    # One request per sweep, alternating: r/cambodia by recency (where a
    # Cambodian breach post actually lands) and a rotating discovery call
    # (full-text query, or recency from a low-volume sub). Arctic Shift
    # 422s on bursts and on large limits, so no two calls share a sweep.
    if idx % 2 == 0:
        plan = [("cambodia", None, 50)]
    else:
        pool = [("cambodia", q, 25) for q in
                ("breach", "hack", "leak", "ransomware", "data", "phishing")]
        pool += [(s, None, 50) for s in subs]
        plan = [pool[(idx // 2) % len(pool)]]

    fresh, failed, search_failed = [], None, False
    for sub, q, lim in plan:
        try:
            fresh.extend(_arctic(sub, q, lim))
        except Exception as exc:
            if q:
                search_failed = True
                print(f"  [-] reddit search r/{sub} '{q}': {exc} "
                      f"(paused 30m)", flush=True)
            else:
                failed = f"r/{sub}: {exc}"
                print(f"  [-] reddit {failed}", flush=True)
            break

    rows = []
    for p in fresh:
        if p.get("removed_by_category") or (p.get("author") in
                                            ("[deleted]", None)):
            continue
        title = re.sub(r"\s+", " ", p.get("title") or "").strip()
        body = re.sub(r"<[^>]+>", " ", p.get("selftext") or "")
        blob = title + " " + body
        sub = (p.get("subreddit") or "").lower()
        if not KH_CYBER_RE.search(blob):
            continue
        if sub != "cambodia" and not _kh_hit(blob):
            continue
        ts = p.get("created_utc") or 0
        rows.append({
            "title": title,
            "link": "https://www.reddit.com" + (p.get("permalink") or ""),
            "date": datetime.fromtimestamp(
                ts, timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "source": "reddit/r/" + (p.get("subreddit") or "?"),
            "body": body[:500],
        })

    merged = {i.get("link"): i for i in (st.get("items") or [])
              if i.get("link")}
    for r in rows:
        if r.get("link"):
            merged[r["link"]] = r
    items = sorted(merged.values(),
                   key=lambda x: x.get("date") or "", reverse=True)[:120]
    st.update({"next": idx + 1, "items": items,
               "blocked": now + REDDIT_BACKOFF if failed else 0,
               "qdown": (now + 30 * 60) if search_failed else 0})
    _reddit_save(st)
    print(f"  [+] reddit: {len(fresh)} fetched, {len(rows)} KH-relevant, "
          f"{len(items)} cached"
          f"{' (backoff)' if failed else ''}"
          f"{' (search paused)' if search_failed else ''}", flush=True)
    return items


def _telegram_kh(chan):
    html = fetch_url(f"https://t.me/s/{chan}", timeout=20, headers={
        "User-Agent": "Mozilla/5.0"}).decode("utf-8", "replace")
    out = []
    for blk in re.split(r'<div class="tgme_widget_message_wrap', html)[1:]:
        m = re.search(
            r'class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
            blk, re.S)
        if not m:
            continue
        body = unescape(re.sub(
            r"<[^>]+>", " ", re.sub(r"<br\s*/?>", "\n", m.group(1))))
        body = re.sub(r"[ \t]+", " ", body).strip()
        if not body:
            continue
        dm = re.search(r'<time[^>]*datetime="([^"]+)"', blk)
        pm = re.search(r'data-post="([^"]+)"', blk)
        out.append({
            "title": body.split("\n")[0][:180],
            "body": body[:600],
            "link": ("https://t.me/" + pm.group(1)) if pm
                    else f"https://t.me/s/{chan}",
            "date": _norm_date(dm.group(1)) if dm else "",
            "source": f"Telegram/{chan}",
        })
    return out


def _x_post(url):
    m = re.search(r"(?:x|twitter)\.com/([^/]+)/status/(\d+)", url or "")
    if not m:
        return []
    user, sid = m.group(1), m.group(2)
    raw = json.loads(fetch_url(
        f"https://api.fxtwitter.com/{user}/status/{sid}",
        headers={"User-Agent": "Mozilla/5.0"}).decode("utf-8", "replace"))
    tw = raw.get("tweet") or {}
    text = (tw.get("text") or "").strip()
    if not text:
        return []
    return [{
        "title": re.sub(r"\s+", " ", text.split("\n")[0])[:180],
        "body": text[:800],
        "link": tw.get("url") or url,
        "date": _norm_date(tw.get("created_at") or ""),
        "source": "x.com/" + ((tw.get("author") or {}).get("screen_name")
                              or user),
        "force": True,
    }]


def _x_search():
    tok = os.environ.get("X_BEARER_TOKEN")
    if not tok:
        return []
    q = ("(cambodia OR khmer OR 柬埔寨) "
         "(breach OR leak OR hacked OR ransomware OR database) -is:retweet")
    url = ("https://api.x.com/2/tweets/search/recent?max_results=25"
           "&tweet.fields=created_at,author_id&query="
           + urllib.parse.quote(q))
    raw = json.loads(fetch_url(url, headers={
        "Authorization": "Bearer " + tok}).decode("utf-8", "replace"))
    out = []
    for t in raw.get("data") or []:
        out.append({
            "title": re.sub(r"\s+", " ", (t.get("text") or ""))[:180],
            "body": t.get("text") or "",
            "link": f"https://x.com/i/web/status/{t.get('id')}",
            "date": _norm_date(t.get("created_at") or ""),
            "source": "x.com",
        })
    return out


def _xsearch_load():
    try:
        with open(X_SEARCH_CACHE, encoding="utf-8") as f:
            st = json.load(f)
        if isinstance(st, dict):
            st.setdefault("next", 0)
            st.setdefault("items", [])
            st.setdefault("blocked", 0)
            return st
    except Exception:
        pass
    return {"next": 0, "items": [], "blocked": 0}


def _xsearch_save(st):
    try:
        with open(X_SEARCH_CACHE, "w", encoding="utf-8") as f:
            json.dump(st, f)
    except Exception:
        pass


def _ddg_x(query, limit=6):
    """DuckDuckGo lite -> indexed x.com status URLs. Raises when throttled."""
    term = (query if query.lower().startswith("site:")
            else "site:x.com " + query)
    q = urllib.parse.quote_plus(term)
    html = fetch_url("https://lite.duckduckgo.com/lite/?q=" + q,
                     timeout=25, headers={"User-Agent": DDG_UA}
                     ).decode("utf-8", "replace")
    if "result-link" not in html:
        raise RuntimeError("no result rows (throttled or empty)")
    hits, seen = [], set()
    for m in re.finditer(
            r"<a[^>]+href=['\"]([^'\"]+)['\"][^>]*"
            r"class=['\"]result-link['\"][^>]*>(.*?)</a>", html, re.S):
        href = m.group(1)
        dm = re.search(r"uddg=([^&]+)", href)
        if dm:
            href = urllib.parse.unquote(dm.group(1))
        tm = re.search(r"(?:x|twitter)\.com/([^/]+)/status/(\d+)", href)
        if not tm:
            continue
        sid = tm.group(2)
        if sid in seen:
            continue
        seen.add(sid)
        hits.append({
            "url": f"https://x.com/{tm.group(1)}/status/{sid}",
            "title": unescape(re.sub(r"<[^>]+>", "", m.group(2))).strip(),
        })
        if len(hits) >= limit:
            break
    return hits


def _x_queries():
    """Keyword queries plus one site-scoped query per watched account."""
    qs = list(KH_X_QUERIES)
    qs += [f"site:x.com/{a} cambodia" for a in KH_X_ACCOUNTS]
    return qs


def _x_search_ddg():
    """Rotate one query per sweep, resolve hits, keep the last good set."""
    st = _xsearch_load()
    now = time.time()
    if now < float(st.get("blocked") or 0):
        return st.get("items") or []
    qs = _x_queries()
    if not qs:
        return st.get("items") or []
    q = qs[int(st.get("next", 0)) % len(qs)]
    try:
        hits = _ddg_x(q)
    except Exception as exc:
        print(f"  [-] KH/x search '{q}': {exc} (backoff 30m)", flush=True)
        st["blocked"] = now + X_SEARCH_BACKOFF
        st["next"] = int(st.get("next", 0)) + 1
        _xsearch_save(st)
        return st.get("items") or []

    resolved, stubs = [], []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = [(h, pool.submit(_x_post, h["url"])) for h in hits]
        for h, fut in futs:
            try:
                got = fut.result(timeout=25) or []
            except Exception:
                got = []
            if got:
                resolved.extend(got)
            else:
                stubs.append({"title": h["title"], "link": h["url"],
                              "date": "", "source": "x.com",
                              "body": h["title"]})

    merged = {i.get("link"): i for i in (st.get("items") or [])
              if i.get("link")}
    for r in resolved + stubs:
        if r.get("link"):
            merged[r["link"]] = r
    items = sorted(merged.values(),
                   key=lambda x: x.get("date") or "", reverse=True)[:120]
    st.update({"next": int(st.get("next", 0)) + 1, "items": items,
               "blocked": 0})
    _xsearch_save(st)
    print(f"  [+] KH/x search '{q}': {len(hits)} indexed, "
          f"{len(resolved)} resolved, {len(items)} cached", flush=True)
    return items


def watch_post(url):
    """Pin one X post into KH Watch immediately (GET /watch?url=...)."""
    try:
        rows = _x_post(url)
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}
    if not rows:
        return {"status": "unresolved", "url": url}
    row = rows[0]
    st = _xsearch_load()
    merged = {i.get("link"): i for i in (st.get("items") or [])
              if i.get("link")}
    merged[row["link"]] = row
    st["items"] = sorted(merged.values(),
                         key=lambda x: x.get("date") or "",
                         reverse=True)[:80]
    _xsearch_save(st)
    with DATA_LOCK:
        cur = list(DATA.get("kh") or [])
        if not any((i.get("link") or "") == row["link"] for i in cur):
            title = row.get("title") or ""
            cur.append({
                "title": title, "link": row["link"],
                "date": row.get("date") or "",
                "source": row.get("source") or "x.com",
                "lane": _kh_lane(title, row.get("source") or ""),
                "term": _kh_hit(title) or "watchlist",
            })
            cur.sort(key=lambda x: x.get("date") or "", reverse=True)
            DATA["kh"] = cur[:60]
    return {"status": "pinned", "title": row.get("title"),
            "date": row.get("date"), "link": row["link"]}


def _fb_pages():
    """Optional: Facebook Page posts via Graph API (needs a token)."""
    tok = os.environ.get("FB_ACCESS_TOKEN")
    pages = [p.strip() for p in os.environ.get("KH_FB_PAGES", "").split(",")
             if p.strip()]
    if not (tok and pages):
        return []
    out = []
    for pid in pages:
        url = (f"https://graph.facebook.com/v19.0/"
               f"{urllib.parse.quote(pid)}/posts"
               f"?fields=message,created_time,permalink_url&limit=25"
               f"&access_token={urllib.parse.quote(tok)}")
        raw = json.loads(fetch_url(url).decode("utf-8", "replace"))
        for p in raw.get("data") or []:
            msg = p.get("message") or ""
            if not msg:
                continue
            out.append({
                "title": re.sub(r"\s+", " ", msg.split("\n")[0])[:180],
                "body": msg[:600],
                "link": p.get("permalink_url") or "",
                "date": _norm_date(p.get("created_time") or ""),
                "source": f"facebook/{pid}",
            })
    return out


def _kh_feed(name, url):
    """A Cambodian newsroom: no KH term needed, but a breach word is."""
    out = []
    for i in parse_feed(fetch_url(url, timeout=25,
                                  headers={"User-Agent": DDG_UA})):
        blob = i.get("title") or ""
        if _kh_signal(blob):
            out.append({**i, "source": name, "force": True})
    return out


KH_VICTIMS = {"at": 0.0, "items": []}


def _rf_country_kh():
    """ransomware.live country index for KH (1 req/min, so cache 1h)."""
    if KH_VICTIMS["items"] and time.time() - KH_VICTIMS["at"] < 3600:
        return list(KH_VICTIMS["items"])
    raw = json.loads(fetch_url(
        "https://api.ransomware.live/v2/countryvictims/KH",
        timeout=25).decode("utf-8", "replace"))
    if isinstance(raw, dict):  # {"message": "1 per 1 minute"} under throttle
        raw = raw.get("victims") or []
    out = []
    for e in raw:
        out.append({
            "gang": (e.get("group_name") or e.get("group")
                     or "unknown").casefold(),
            "victim": (e.get("post_title") or e.get("victim")
                       or e.get("domain") or e.get("website") or "unknown"),
            "country": e.get("country") or "KH",
            "date": (e.get("discovered") or e.get("attackdate") or "")[:10],
            "url": (e.get("post_url") or e.get("claim_url")
                    or e.get("url") or ""),
            "activity": e.get("activity") or "",
            "site": e.get("website") or "",
        })
    if out:
        KH_VICTIMS.update({"at": time.time(), "items": out})
    return out


def kh_watch(attacks=None, breaches=None):
    """Merge every KH-facing public lane into one newest-first feed."""
    attacks, breaches = attacks or [], breaches or []
    items, seen = [], set()

    def add(title, link, date, source, hay="", force=False, lane=None):
        title = re.sub(r"\s+", " ", (title or "")).strip()
        if not title:
            return
        blob = title + " " + (hay or "")
        hit = _kh_hit(blob)
        if not hit and not force:
            return
        if not force and not _kh_signal(blob):
            return
        key = re.sub(r"[^a-z0-9]+", "", title.lower())[:70]
        if not key or key in seen:
            return
        seen.add(key)
        items.append({
            "title": title[:220], "link": link or "",
            "date": (date or "")[:16], "source": source or "wire",
            "lane": lane or _kh_lane(title, source),
            "term": hit or "watchlist",
        })

    jobs = []
    for q, hl, gl, ceid in KH_NEWS_Q:
        jobs.append(("Google News",
                     lambda q=q, hl=hl, gl=gl, ceid=ceid:
                     _gnews(q, hl, gl, ceid)))
    jobs.append(("Bing News", lambda: _bing_news("Cambodia data breach")))
    jobs.append(("Bing News", lambda: _bing_news("Cambodia hacked")))
    for name, feed in KH_FEEDS:
        jobs.append((name, lambda n=name, f=feed: _kh_feed(n, f)))
    if os.environ.get("KH_REDDIT", "1") != "0":
        jobs.append(("Reddit", _reddit_kh))
    for chan in KH_TG:
        jobs.append((f"Telegram/{chan}", lambda c=chan: _telegram_kh(c)))
    for u in KH_SEED_POSTS:
        jobs.append(("x.com", lambda u=u: _x_post(u)))
    jobs.append(("x.com", _x_search))
    jobs.append(("x.com search", _x_search_ddg))
    jobs.append(("facebook", _fb_pages))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [(src, pool.submit(fn)) for src, fn in jobs]
        for src, fut in futs:
            try:
                rows = fut.result(timeout=45) or []
            except Exception as exc:
                print(f"  [-] KH/{src}: {exc}", flush=True)
                continue
            for r in rows:
                add(r.get("title"), r.get("link"), r.get("date"),
                    r.get("source") or src, r.get("body") or "",
                    r.get("force", False), r.get("lane"))

    try:
        kh_victims = _rf_country_kh()
        print(f"  [+] KH/ransom country: {len(kh_victims)} KH victims",
              flush=True)
    except Exception as exc:
        print(f"  [-] KH/ransom country: {exc}", flush=True)
        kh_victims = []

    for a in attacks + kh_victims:
        hay = " ".join(str(a.get(k) or "") for k in
                       ("victim", "country", "gang", "activity"))
        if (str(a.get("country") or "").upper() in ("KH", "KHM", "CAMBODIA")
                or _kh_hit_strict(hay)):
            add(f"{a.get('gang', '?')} claims {a.get('victim', '?')}",
                a.get("url") or "", a.get("date") or "",
                "ransomware.live", hay=hay, force=True, lane="RANSOM")

    with B_LOCK:
        catalog = list(B.get("breaches") or [])
    for b in list(breaches or []) + catalog:
        hay = " ".join(str(b.get(k) or "") for k in
                       ("org", "title", "domain", "desc", "classes"))
        if _kh_hit(hay):
            src = ("HIBP" if b.get("source") == "HIBP"
                   or b.get("kind") == "catalog" else "DataBreaches.net")
            add(b.get("org") or b.get("title") or "", b.get("link") or "",
                b.get("date") or "", src, hay=hay, lane="BREACH")

    order = {lane: i for i, lane in enumerate(KH_LANES)}
    items.sort(key=lambda x: (x["date"], -order.get(x["lane"], 9)),
               reverse=True)
    return items[:120]


# ------------------------------------------------------------------ engine

SWEEP = {"running": False, "last": 0.0}
SWEEP_LOCK = threading.Lock()


def _sweep_guard():
    with SWEEP_LOCK:
        if SWEEP["running"]:
            return False
        SWEEP["running"] = True
        return True


def _sweep_release():
    with SWEEP_LOCK:
        SWEEP["running"] = False
        SWEEP["last"] = time.time()


def trigger_refresh():
    """Kick one sweep in the background. False if one is already running."""
    if not _sweep_guard():
        return False

    def _run():
        try:
            refresh_once()
        except Exception as exc:
            print(f"[-] sweep crash: {exc}", flush=True)
        finally:
            _sweep_release()

    threading.Thread(target=_run, daemon=True).start()
    return True


def refresh_once():
    errors, cves, kev, news, attacks = [], [], [], [], []
    ai, breach = [], []
    print("[*] refresh sweep starting...", flush=True)
    breach_tick()  # load cached HIBP before the panel is built

    with DATA_LOCK:  # previous good state, kept when a source fails
        prev = {k: (list(v) if isinstance(v, list) else v)
                for k, v in DATA.items()}
    key_of = {"NVD CVEs": "cves", "CISA KEV": "kev",
              "Ransomware": "attacks", "AI Wire": "ai",
              "Data Breach": "breach"}

    jobs = (
        ("NVD CVEs", nvd_recent_cves), ("CISA KEV", cisa_kev),
        ("Ransomware", attacks_ransomware),
        ("TheHackerNews", hacker_news), ("BleepingComputer", bleeping),
        ("Krebs", krebs), ("ExploitDB", exploit_db), ("AI Wire", ai_news),
        ("Data Breach", breach_feed),
    )
    for name, fn in jobs:
        time.sleep(0.3)
        try:
            r = fn()
            if name == "NVD CVEs":
                cves = r
            elif name == "CISA KEV":
                kev = r
            elif name == "Ransomware":
                attacks = r
            elif name == "AI Wire":
                ai = r
            elif name == "Data Breach":
                breach = r
            else:
                news.extend(r)
            print(f"  [+] {name}: {len(r)} items", flush=True)
        except Exception as exc:
            errors.append(f"{name}: {exc} (kept last good data)")
            print(f"  [-] {name}: {exc} — keeping previous data", flush=True)
            k = key_of.get(name)
            if k == "cves" and not cves:
                cves = prev.get("cves") or _cve_load() or []
            elif k == "kev" and not kev:
                kev = prev.get("kev") or []
            elif k == "attacks" and not attacks:
                attacks = prev.get("attacks") or []
            elif k == "ai" and not ai:
                ai = prev.get("ai") or []
            elif k == "breach" and not breach:
                breach = prev.get("breach") or []
            elif not news:
                news = prev.get("news") or []

    try:
        kh = kh_watch(attacks, breach)
        print(f"  [+] KH Watch: {len(kh)} cambodia signals", flush=True)
    except Exception as exc:
        kh = prev.get("kh") or []
        errors.append(f"KH Watch: {exc} (kept last good data)")
        print(f"  [-] KH Watch: {exc} — keeping previous data", flush=True)

    with DATA_LOCK:
        DATA["cves"] = cves
        DATA["kev"] = kev
        DATA["news"] = news
        DATA["attacks"] = attacks[:20]
        DATA["ai"] = ai
        DATA["breach"] = breach
        DATA["kh"] = kh
        DATA["updated"] = datetime.now(
            timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M ICT")
        DATA["errors"] = errors

    counter = Counter(a["gang"] for a in attacks
                      if a["gang"] not in ("unknown", "not found"))
    gangs = [{"gang": g, "count": n} for g, n in counter.most_common(8)]
    with DATA_LOCK:
        DATA["gangs"] = gangs

    edb_tick()
    print(f"[*] sweep done: {len(cves)} cves, {len(kev)} kev, "
          f"{len(attacks)} victims, {len(ai)} ai, "
          f"{len(breach)} breach, {len(kh)} kh, {len(news)} news",
          flush=True)


def refresh_loop():
    while True:
        if _sweep_guard():
            try:
                refresh_once()
            except Exception as exc:
                print(f"[-] sweep crash: {exc}", flush=True)
            finally:
                _sweep_release()
        time.sleep(REFRESH_MAX_AGE)


# ------------------------------------------------------------------ skin

CSS = """
:root{
  --bg:#04060d; --sur1:#0b111f; --sur2:#0f1830; --sur3:#0d1526;
  --line:#1a2745; --line2:#263a6b; --line3:#33487f;
  --text:#dce8ff; --dim:#839cc9; --faint:#5e6d8f;
  --red:#ff3b5c; --rose:#ff5f9e; --orange:#ff9430; --amber:#ffb020;
  --yellow:#ffd83d; --green:#34d399; --teal:#2dd4bf; --cyan:#22d2ee;
  --violet:#a78bfa; --sky:#38bdf8; --lime:#a3e635;
  --mono:'JetBrains Mono','Cascadia Code','SF Mono',Menlo,Consolas,monospace;
  --sans:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
html{color-scheme:dark}
body{
  background:
    radial-gradient(1100px 480px at 78% -12%, rgba(34,210,238,.075), transparent 62%),
    radial-gradient(900px 420px at 8% -14%, rgba(255,59,92,.07), transparent 60%),
    radial-gradient(700px 380px at 45% 118%, rgba(167,139,250,.05), transparent 65%),
    var(--bg);
  color:var(--text); min-height:100vh;
  font-family:var(--sans); font-size:15px; line-height:1.55;
  padding:20px 26px 26px; max-width:1600px; margin:auto;
}
a{color:inherit}
.top{display:flex;align-items:center;justify-content:space-between;
  gap:18px;padding:4px 2px 18px}
.brand{display:flex;align-items:center;gap:15px}
.sigil{width:47px;height:47px;border-radius:12px;display:grid;place-items:center;
  font-size:1.45rem;color:var(--cyan);
  background:linear-gradient(140deg,rgba(255,59,92,.18),rgba(34,210,238,.16));
  border:1px solid var(--line2);
  box-shadow:0 0 0 1px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,255,255,.06)}
.sigil span{filter:drop-shadow(0 0 7px rgba(34,210,238,.55))}
h1{font-size:1.34rem;letter-spacing:.5px;font-weight:800;font-family:var(--mono)}
h1 b{color:var(--cyan);font-weight:800}
h1 .dot{color:var(--red)}
.sub{color:var(--dim);font-size:.7rem;margin-top:2px;letter-spacing:1.1px;
  text-transform:uppercase;font-family:var(--mono)}
.pillrow{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.pill{background:rgba(13,21,38,.85);border:1px solid var(--line2);
  border-radius:999px;padding:7px 14px;font-size:.68rem;color:var(--dim);
  font-family:var(--mono);letter-spacing:.4px;white-space:nowrap}
.pill b{color:var(--text);font-weight:700}
.pill.live{color:var(--green);border-color:rgba(52,211,153,.45);
  background:rgba(52,211,153,.07)}
.pill.live i{display:inline-block;width:7px;height:7px;border-radius:50%;
  background:var(--green);margin-right:7px;vertical-align:0;
  box-shadow:0 0 8px rgba(52,211,153,.8);animation:pulse 2s infinite}
.refresh-btn{font-family:var(--mono);font-size:.68rem;color:var(--dim);
  cursor:pointer;transition:color .15s,border-color .15s,box-shadow .15s}
.refresh-btn:hover{color:var(--cyan);border-color:var(--cyan);
  box-shadow:0 0 12px rgba(34,210,238,.15)}
.refresh-btn.busy{opacity:.65;cursor:wait;color:var(--amber);
  border-color:var(--amber);animation:pulse 1.4s infinite}
.ticker{height:2px;border-radius:2px;margin-bottom:20px;
  background:linear-gradient(90deg,var(--red),var(--orange) 25%,var(--yellow)
  45%,var(--green) 62%,var(--cyan) 80%,var(--violet));opacity:.65}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:12px;margin-bottom:14px}
.kpi{position:relative;background:linear-gradient(175deg,var(--sur2),var(--sur1));
  border:1px solid var(--line);border-radius:13px;padding:15px 17px 13px;
  overflow:hidden;transition:transform .18s,border-color .18s}
.kpi:hover{transform:translateY(-2px);border-color:var(--line3)}
.kpi .lab{font-size:.66rem;color:var(--dim);text-transform:uppercase;
  letter-spacing:1.4px;font-family:var(--mono)}
.kpi .num{font-size:2rem;font-weight:800;line-height:1.15;margin-top:5px;
  font-family:var(--mono);letter-spacing:-.5px}
.kpi .fx{font-size:.66rem;color:var(--dim);margin-top:3px;font-family:var(--mono)}
.kpi::after{content:'';position:absolute;left:0;right:0;bottom:0;height:3px}
.kpi.k-red::after{background:linear-gradient(90deg,var(--red),transparent 88%)}
.kpi.k-rose::after{background:linear-gradient(90deg,var(--rose),transparent 88%)}
.kpi.k-amber::after{background:linear-gradient(90deg,var(--amber),transparent 88%)}
.kpi.k-violet::after{background:linear-gradient(90deg,var(--violet),transparent 88%)}
.kpi.k-orange::after{background:linear-gradient(90deg,var(--orange),transparent 88%)}
.kpi.k-teal::after{background:linear-gradient(90deg,var(--teal),transparent 88%)}
.kpi.k-sky::after{background:linear-gradient(90deg,var(--sky),transparent 88%)}
.kpi.k-green::after{background:linear-gradient(90deg,var(--green),transparent 88%)}
.kpi.k-lime::after{background:linear-gradient(90deg,var(--lime),transparent 88%)}
.c-red{color:var(--red)}.c-rose{color:var(--rose)}.c-amber{color:var(--amber)}
.c-violet{color:var(--violet)}.c-orange{color:var(--orange)}
.c-teal{color:var(--teal)}.c-sky{color:var(--sky)}.c-cyan{color:var(--cyan)}
.c-green{color:var(--green)}.c-dim{color:var(--dim)}
.c-lime{color:var(--lime)}
.mixwrap{display:flex;align-items:center;gap:14px;margin-bottom:14px;
  background:rgba(13,21,38,.6);border:1px solid var(--line);
  border-radius:10px;padding:9px 16px}
.mixlab{font-size:.62rem;color:var(--dim);letter-spacing:1.6px;flex-shrink:0;
  font-family:var(--mono)}
.mix{flex:1;height:10px;border-radius:5px;overflow:hidden;display:flex;
  background:var(--sur3)}
.seg{height:100%}
.mixleg{display:flex;gap:11px;font-size:.62rem;color:var(--dim);
  font-family:var(--mono);flex-wrap:wrap}
.mixleg b{color:var(--text)}
.sw{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:5px;
  vertical-align:-1px}
.board{display:grid;grid-template-columns:repeat(12,1fr);gap:15px}
.panel{position:relative;display:flex;flex-direction:column;
  background:linear-gradient(178deg,var(--sur2) 0%,var(--sur3) 90%);
  border:1px solid var(--line);border-radius:15px;padding:0 0 8px;
  overflow:hidden;transition:border-color .2s}
.panel:hover{border-color:var(--line2)}
.s7{grid-column:span 7}.s5{grid-column:span 5}.s8{grid-column:span 8}
.s4{grid-column:span 4}.s6{grid-column:span 6}.s12{grid-column:span 12}
.ph{display:flex;align-items:center;gap:10px;padding:13px 18px 0}
.ph .ic{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;
  font-size:.9rem;flex-shrink:0}
.ph h2{font-size:.74rem;letter-spacing:2.2px;text-transform:uppercase;
  color:var(--text);font-weight:800;font-family:var(--mono)}
.ph h2 small{color:var(--dim);font-weight:400;letter-spacing:.6px;
  text-transform:none;font-size:.72rem}
.ph .count{margin-left:auto;background:rgba(255,255,255,.05);
  border:1px solid var(--line2);color:var(--dim);border-radius:999px;
  padding:3px 10px;font-size:.63rem;font-family:var(--mono);letter-spacing:.5px}
.ulu{list-style:none;overflow-y:auto;padding:6px 14px 6px;flex:1;margin-top:6px}
.ph + .ulu{border-top:1px solid var(--line);margin-top:11px}
.p-cve .ph .ic{color:var(--cyan);background:rgba(34,210,238,.11)}
.p-cve::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--cyan),transparent 70%)}
.p-kev .ph .ic{color:var(--red);background:rgba(255,59,92,.12)}
.p-kev::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--red),transparent 70%)}
.p-edb .ph .ic{color:var(--green);background:rgba(52,211,153,.11)}
.p-edb::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--green),transparent 70%)}
.p-gang .ph .ic{color:var(--orange);background:rgba(255,148,48,.12)}
.p-gang::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--orange),transparent 70%)}
.p-vic .ph .ic{color:var(--teal);background:rgba(45,212,191,.12)}
.p-vic::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--teal),transparent 70%)}
.p-news .ph .ic{color:var(--sky);background:rgba(56,189,248,.11)}
.p-news::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--sky),transparent 70%)}
.p-ai .ph .ic{color:var(--lime);background:rgba(163,230,53,.11)}
.p-ai::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--lime),transparent 70%)}
.p-breach .ph .ic{color:var(--amber);background:rgba(255,176,32,.12)}
.p-breach::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--amber),transparent 70%)}
.p-kh .ph .ic{color:var(--rose);background:rgba(255,95,158,.12)}
.p-kh::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--rose),var(--red) 42%,transparent 80%)}
.khctl input{min-width:240px}
.khlane{display:inline-block;font-family:var(--mono);font-size:.6rem;
  letter-spacing:.9px;padding:1px 6px;border-radius:4px;margin-right:7px;
  border:1px solid transparent;vertical-align:1px}
.kh-RANSOM{color:var(--rose);background:rgba(255,95,158,.12);
  border-color:rgba(255,95,158,.45)}
.kh-LEAK{color:var(--red);background:rgba(255,59,92,.12);
  border-color:rgba(255,59,92,.45)}
.kh-BREACH{color:var(--orange);background:rgba(255,148,48,.12);
  border-color:rgba(255,148,48,.45)}
.kh-DARKWEB{color:var(--violet);background:rgba(167,139,250,.12);
  border-color:rgba(167,139,250,.45)}
.kh-SOCIAL{color:var(--cyan);background:rgba(34,210,238,.11);
  border-color:rgba(34,210,238,.4)}
.kh-REPORT{color:var(--dim);background:rgba(131,156,201,.1);
  border-color:rgba(131,156,201,.35)}
.khsub{font-size:.64rem;color:var(--dim);margin-top:3px;
  font-family:var(--mono)}
.khnote{font-size:.66rem;color:var(--faint);padding:8px 18px 2px;
  font-family:var(--mono);line-height:1.5}
.p-gloss .ph .ic{color:var(--violet);background:rgba(167,139,250,.12)}
/* glossary button + hover card */
.gloss-wrap{position:relative;display:inline-block}
.gloss-wrap summary{cursor:pointer;list-style:none}
.gloss-wrap summary::-webkit-details-marker{display:none}
.gloss-btn{user-select:none;transition:color .15s,border-color .15s}
.gloss-btn:hover,.gloss-wrap[open] .gloss-btn{color:var(--violet);
  border-color:var(--violet);background:rgba(167,139,250,.08)}
.gloss-pop{position:absolute;right:0;top:100%;width:640px;max-width:88vw;
  max-height:440px;overflow-y:auto;padding:16px 20px;z-index:300;
  background:linear-gradient(178deg,var(--sur2),var(--sur3));
  border:1px solid var(--line2);border-radius:14px;
  box-shadow:0 18px 60px rgba(0,0,0,.6);
  opacity:0;visibility:hidden;transform:translateY(-6px);
  transition:opacity .16s,transform .16s,visibility .16s}
.gloss-pop::before{content:'';position:absolute;left:0;right:0;top:-14px;
  height:14px}  /* hover bridge — no dead gap */
.gloss-wrap:hover .gloss-pop,.gloss-wrap[open] .gloss-pop{
  opacity:1;visibility:visible;transform:none}
.gloss-list{columns:2;column-gap:26px;list-style:none;margin:0}
.gloss-list li{break-inside:avoid;padding:6px 2px;font-size:.78rem;
  border-bottom:1px dashed rgba(26,39,69,.6)}
.gloss-list li:last-child{border-bottom:none}
.gterm{display:inline-block;min-width:74px;color:var(--violet);font-weight:800;
  font-family:var(--mono);font-size:.72rem;letter-spacing:.8px;
  padding-right:10px;vertical-align:top}
.gdef{color:var(--dim);font-size:.75rem;line-height:1.55}
@media (max-width:960px){.gloss-list{columns:1}.gloss-pop{width:88vw}}
.p-cve .ulu{max-height:64vh}
.panel:not(.p-cve):not(.p-edb) .ulu{max-height:40vh}
.p-edb .ulu{max-height:40vh}
.p-news .ulu{max-height:34vh}
.p-kh .ulu{max-height:56vh}
.ulu li{padding:10.5px 7px;font-size:.85rem;line-height:1.55;cursor:default;
  border-bottom:1px solid rgba(26,39,69,.5);border-radius:7px;
  transition:background .14s,transform .14s;border-left:2px solid transparent}
.ulu li:hover{background:rgba(38,58,107,.13);transform:translateX(2px)}
.ulu li:last-child{border-bottom:none}
.src{color:var(--dim);font-size:.66rem}
.date{color:var(--dim);font-size:.68rem;float:right;font-family:var(--mono);
  margin-left:10px}
.sev{display:inline-block;padding:3px 10px;border-radius:5px;font-size:.66rem;
  font-weight:800;letter-spacing:1.2px;margin-right:9px;font-family:var(--mono)}
.sev-CRITICAL{background:rgba(255,59,92,.15);color:var(--red);
  border:1px solid rgba(255,59,92,.65);box-shadow:0 0 12px rgba(255,59,92,.14)}
.sev-HIGH{background:rgba(255,148,48,.14);color:var(--orange);
  border:1px solid rgba(255,148,48,.6)}
.sev-MEDIUM{background:rgba(255,216,61,.12);color:var(--yellow);
  border:1px solid rgba(255,216,61,.5)}
.sev-LOW{background:rgba(52,211,153,.12);color:var(--green);
  border:1px solid rgba(52,211,153,.45)}
.sev-UNKNOWN{background:rgba(104,119,158,.1);color:var(--dim);
  border:1px solid rgba(104,119,158,.35)}
.cveid{color:var(--cyan);font-weight:700;font-size:.78rem;font-family:var(--mono)}
.cveid a{color:inherit;text-decoration:none}
.cveid a:hover{text-decoration:underline;text-decoration-color:var(--cyan)}
.desc{color:var(--dim);font-size:.78rem;margin-top:5px;display:-webkit-box;
  -webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.score{float:right;color:var(--dim);font-size:.68rem;font-family:var(--mono)}
.ktag{color:var(--red);font-size:.58rem;font-weight:800;letter-spacing:1.5px;
  font-family:var(--mono)}
.rans{display:inline-block;color:var(--rose);font-size:.58rem;font-weight:800;
  letter-spacing:1.3px;padding:2px 7px;border-radius:5px;
  background:rgba(255,95,158,.1);border:1px solid rgba(255,95,158,.4);
  font-family:var(--mono)}
.vend{color:var(--text);font-size:.78rem;font-weight:600}
.desc2{color:var(--dim);font-size:.76rem}
.edb-badge{display:inline-block;color:var(--green);font-size:.6rem;
  font-weight:800;letter-spacing:1px;padding:2.5px 9px;border-radius:5px;
  background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.5);
  font-family:var(--mono);text-decoration:none;cursor:pointer;
  transition:all .15s}
.edb-badge:hover{background:rgba(52,211,153,.2);
  box-shadow:0 0 10px rgba(52,211,153,.3)}
.edb-badge i{font-style:normal;color:var(--dim);font-weight:400}
.gangrow{display:flex;align-items:center;gap:10px;padding:7.5px 6px}
.gchip{display:inline-block;padding:3px 10px;border-radius:6px;font-size:.66rem;
  font-weight:700;font-family:var(--mono);letter-spacing:.4px;flex-shrink:0;
  border:1px solid}
.gbar{height:9px;border-radius:5px;min-width:5px;opacity:.9;
  background:linear-gradient(90deg,rgba(255,148,48,.85),rgba(255,59,92,.85))}
.gcount{color:var(--dim);font-size:.66rem;margin-left:auto;font-family:var(--mono)}
.vgang{font-family:var(--mono);font-size:.64rem;font-weight:700;letter-spacing:.8px}
.vrow{color:var(--teal)}
.vurl{color:var(--teal);text-decoration:none;font-size:.71rem}
.vurl:hover{text-decoration:underline}
.vc{color:var(--faint);font-size:.62rem;font-family:var(--mono)}
.nsrc{display:inline-block;font-size:.64rem;color:var(--dim);margin-top:3px;
  font-family:var(--mono);letter-spacing:.6px;text-transform:uppercase}
.aitag{display:inline-block;font-size:.6rem;font-weight:800;letter-spacing:1.2px;
  padding:2px 8px;border-radius:4px;font-family:var(--mono);margin-right:7px;
  text-transform:uppercase}
.aitag-RELEASE{color:var(--green);background:rgba(52,211,153,.1);
  border:1px solid rgba(52,211,153,.4)}
.aitag-SECURITY{color:var(--violet);background:rgba(167,139,250,.1);
  border:1px solid rgba(167,139,250,.4)}
.aitag-ATTACK{color:var(--red);background:rgba(255,59,92,.12);
  border:1px solid rgba(255,59,92,.5)}
.aitag-RESEARCH{color:var(--faint);background:rgba(86,109,143,.12);
  border:1px solid rgba(86,109,143,.35)}
.brec{display:inline-block;color:var(--amber);font-size:.62rem;font-weight:800;
  letter-spacing:1px;padding:2px 8px;border-radius:4px;
  background:rgba(255,176,32,.1);border:1px solid rgba(255,176,32,.45);
  font-family:var(--mono);margin-right:7px}
.brow .bname{color:var(--text);font-weight:600;font-size:.8rem}
.brow .bclass{color:var(--dim);font-size:.7rem;margin-top:2px}
.edbrow .d{color:var(--text);font-size:.76rem;font-weight:600}
.edbrow .m{color:var(--dim);font-size:.68rem;font-family:var(--mono)}
.etag{display:inline-block;font-size:.62rem;color:var(--green);padding:1px 7px;
  border-radius:4px;background:rgba(52,211,153,.08);
  border:1px solid rgba(52,211,153,.3);font-family:var(--mono);margin-right:5px}
.plctl{display:flex;gap:7px;padding:9px 16px 0;flex-wrap:wrap;align-items:center}
.plctl input{flex:1;min-width:200px;background:rgba(4,6,13,.6);
  border:1px solid var(--line2);color:var(--text);border-radius:8px;
  padding:8px 12px;font-size:.76rem;outline:none;font-family:var(--mono);
  transition:border .15s,box-shadow .15s}
.plctl input::placeholder{color:var(--faint)}
.plctl input:focus{border-color:var(--cyan);
  box-shadow:0 0 0 3px rgba(34,210,238,.13)}
.chip{background:rgba(4,6,13,.5);border:1px solid var(--line2);
  color:var(--dim);border-radius:999px;padding:7px 13px;font-size:.63rem;
  letter-spacing:1px;cursor:pointer;font-family:var(--mono);transition:all .15s}
.chip:hover{color:var(--text);border-color:var(--cyan)}
.chip.active{color:var(--cyan);border-color:var(--cyan);
  background:rgba(34,210,238,.09);box-shadow:0 0 10px rgba(34,210,238,.12)}
.chip.exp.active{color:var(--green);border-color:var(--green);
  background:rgba(52,211,153,.09);box-shadow:0 0 10px rgba(52,211,153,.12)}
.errorbox{background:rgba(255,59,92,.07);border:1px dashed rgba(255,59,92,.45);
  border-radius:11px;padding:10px 15px;font-size:.7rem;color:var(--orange);
  margin-bottom:14px;font-family:var(--mono)}
.empty{color:var(--faint);font-size:.72rem;padding:12px 4px;font-style:italic}
.footer{text-align:center;color:var(--faint);font-size:.62rem;line-height:2.1;
  margin-top:24px;padding-top:16px;border-top:1px solid var(--line);
  font-family:var(--mono);letter-spacing:.6px}
.footer b{color:var(--dim);font-weight:600}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:var(--cyan)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@media (max-width:1150px){
  .s7,.s5,.s8,.s4,.s6,.s12{grid-column:span 12}
  .p-cve .ulu,.panel:not(.p-cve):not(.p-edb) .ulu{max-height:46vh}
}
"""

JS = """
const clock=document.getElementById('clock');
if(clock){const tick=()=>{const d=new Date(Date.now()+7*3600e3);
 clock.textContent=d.toISOString().slice(0,19).replace('T',' ')+' ICT'};
 tick();setInterval(tick,1000);}
const items=document.querySelectorAll('#cves>li');
let sevf='all',expf='any',q='';
const apply=()=>{items.forEach(li=>{
  const sev=li.dataset.sev||'';const txt=(li.dataset.q||'');
  const ex=li.dataset.exp==='1';
  const ok=(sevf==='all'||sev===sevf)&&txt.includes(q)&&
    (expf==='any'||(expf==='yes'&&ex)||(expf==='no'&&!ex));
  li.style.display=ok?'':'none';});};
document.querySelectorAll('.chip[data-v]').forEach(c=>{
  c.addEventListener('click',()=>{
    const fam=c.dataset.fam;
    document.querySelectorAll(`.chip[data-fam="${fam}"]`)
      .forEach(x=>x.classList.remove('active'));
    c.classList.add('active');
    if(fam==='sev')sevf=c.dataset.v;
    if(fam==='exp')expf=c.dataset.v;
    apply();});});
const search=document.getElementById('q');
if(search){search.addEventListener('input',()=>{
  q=search.value.toLowerCase();apply();});}
const rb=document.getElementById('refresh');
if(rb){rb.addEventListener('click',async()=>{
  if(rb.classList.contains('busy'))return;
  rb.classList.add('busy');
  try{await fetch('/refresh',{cache:'no-store'});}catch(e){}
  const t0=Date.now();
  const poll=async()=>{
    try{const d=await(await fetch('/api/dashboard',{cache:'no-store'})).json();
      if(!d.sweep_running){location.reload();return;}
    }catch(e){}
    if(Date.now()-t0<240000)setTimeout(poll,3000);
    else{rb.classList.remove('busy');}
  };
  setTimeout(poll,3000);
});}
const khItems=document.querySelectorAll('#kh>li');
let khLane='ALL';
const khApply=()=>{
  const el=document.getElementById('khq');
  const q=(el?el.value:'').toLowerCase();
  khItems.forEach(li=>{
    const ok=(khLane==='ALL'||li.dataset.lane===khLane)&&
      (li.dataset.q||'').includes(q);
    li.style.display=ok?'':'none';});};
document.querySelectorAll('.chip[data-kh]').forEach(c=>{
  c.addEventListener('click',()=>{
    document.querySelectorAll('.chip[data-kh]').forEach(
      x=>x.classList.remove('active'));
    c.classList.add('active');khLane=c.dataset.kh;khApply();});});
const khq=document.getElementById('khq');
if(khq){khq.addEventListener('input',khApply);}
"""

HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYBER DASHBOARD</title>
<style>__CSS__</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <div class="sigil"><span>&#9674;</span></div>
    <div>
      <h1>CYBER<b>DASHBOARD</b></h1>
      <div class="sub">threat intel console &mdash; cve &#183; kev &#183; exploits &#183; ransomware &#183; news</div>
    </div>
  </div>
  <div class="pillrow">
    <span class="pill live"><i></i>LIVE</span>
    <button class="pill refresh-btn" id="refresh"
      title="force an immediate feed sweep">&#8635; refresh</button>
    <span class="pill">clock <b id="clock">&mdash;</b></span>
    <span class="pill">swept <b>__UPDATED__</b></span>
    <span class="pill"><a href="/api/dashboard">/api/dashboard</a></span>
    <details class="gloss-wrap"><summary class="pill gloss-btn">
      &#128214; glossary</summary>
      <div class="gloss-pop">__GLOSS_POP__</div>
    </details>
  </div>
</header>
<div class="ticker"></div>
__ERROR_BOX__
<section class="kpis">__KPIS__</section>
<div class="mixwrap">
  <span class="mixlab">SEVERITY MIX</span>
  <div class="mix">__MIXBAR__</div>
  <div class="mixleg">__MIXLEG__</div>
</div>
<main class="board">__PANELS__</main>
<footer class="footer">
  <b>sources</b> &mdash; NVD 2.0 &middot; CISA KEV &middot; Exploit-DB index &middot; ransomware.live &middot; ransomfeed.it
  &middot; The Hacker News &middot; BleepingComputer &middot; Krebs on Security &middot; VentureBeat AI &middot; The Decoder &middot; MarkTechPost &middot; r/MachineLearning &middot; HIBP &middot; DataBreaches.net<br>
  <b>KH Watch</b> &mdash; Google News &middot; Bing News &middot; Reddit &middot; Telegram public mirrors &middot; fxtwitter &middot; ransomware feeds &middot; HIBP
  zero dependencies &middot; python stdlib only &middot; reloads every 60s &middot; feeds roll every 15 min
</footer>
<script>__JS__</script>
</body>
</html>"""


def _gang_hue(name):
    return sum(ord(ch) for ch in name) % 360, 75, 62


def render():
    with DATA_LOCK:
        d = {k: (list(v) if isinstance(v, list) else v)
             for k, v in DATA.items()}
    with EDB_LOCK:
        edb_map = dict(EDB["map"])
        edb_recs = dict(EDB["recs"])
        edb_ready = EDB["ready"]
        edb_latest = list(EDB["latest"])
        edb_err = EDB["error"]
        edb_building = EDB["building"]

    cves, kev, attacks = d["cves"], d["kev"], d["attacks"]
    gangs, news, ai = d["gangs"], d["news"], d["ai"]
    breach = d["breach"]
    kh = d.get("kh") or []
    updated = d["updated"] or "booting..."
    errors = d["errors"]

    n_crit = sum(1 for c in cves if c["severity"] == "CRITICAL")
    n_high = sum(1 for c in cves if c["severity"] == "HIGH")
    n_med = sum(1 for c in cves if c["severity"] == "MEDIUM")
    n_low = sum(1 for c in cves if c["severity"] == "LOW")
    n_other = len(cves) - n_crit - n_high - n_med - n_low
    n_edb = sum(1 for c in cves if edb_map.get(c["id"]))

    def kpi(cls, color, label, num, fx):
        return (f"<div class='kpi k-{cls}'>"
                f"<div class='lab'>{label}</div>"
                f"<div class='num c-{color}'>{num}</div>"
                f"<div class='fx'>{fx}</div></div>")

    kpis = "".join([
        kpi("red", "red", "KEV exploited", len(kev), "cisa catalog"),
        kpi("rose", "rose", "Critical CVEs", n_crit, "in window"),
        kpi("amber", "amber", "High CVEs", n_high, "in window"),
        kpi("green", "green", "EDB PoC", n_edb,
            "of these CVEs indexed"),
        kpi("lime", "lime", "AI Wire", len(ai), "laned headlines"),
        kpi("amber", "amber", "Breaches", len(breach), "hibp · wire"),
        kpi("rose", "rose", "KH signals", len(kh), "cambodia watch"),
        kpi("orange", "orange", "Gangs active", len(gangs), "24h"),
        kpi("teal", "teal", "New victims", len(attacks), "claimed"),
        kpi("sky", "sky", "Headlines", len(news), "crawled"),
    ])

    tot = len(cves) or 1
    mixbar = ""
    for color, n in (("red", n_crit), ("orange", n_high),
                     ("yellow", n_med), ("green", n_low),
                     ("faint", n_other)):
        if n:
            mixbar += (f"<div class='seg' style='width:{n / tot * 100:.1f}%;"
                       f"background:var(--{color})'></div>")
    mixbar = mixbar or "<div class='seg' style='width:100%'></div>"
    mixleg = "".join(
        f"<span><i class='sw' style='background:var(--{c})'></i>{n}</span> "
        for c, n in (("red", n_crit), ("orange", n_high),
                     ("yellow", n_med), ("green", n_low)))
    mixleg += ("<span><i class='sw' style='background:var(--faint)'></i>"
               f"other {n_other}</span>")

    # ---- KH Watch ----------------------------------------------
    KH_TIP = {
        "RANSOM": "leak-site victim claim",
        "LEAK": "database / dump offered or published",
        "BREACH": "compromise claimed or confirmed",
        "DARKWEB": "dark-web / forum chatter",
        "SOCIAL": "public social post",
        "REPORT": "press / wire coverage",
    }
    kh_counts = Counter(k["lane"] for k in kh)
    kh_ctl = ("<div class='plctl khctl'>"
              "<input id='khq' type='text' placeholder='filter KH signals "
              "&mdash; victim / actor / keyword'>"
              + "".join(
                  f"<button class='chip"
                  f"{' active' if lane == 'ALL' else ''}' "
                  f"data-kh='{lane}'>{lane} <b>"
                  f"{len(kh) if lane == 'ALL' else kh_counts.get(lane, 0)}"
                  f"</b></button>"
                  for lane in ("ALL",) + KH_LANES)
              + "</div>")

    kh_html = ""
    for k in kh:
        q = (k["title"] + " " + k["source"]).lower()
        title_html = (
            f"<a href='{escape(k['link'])}' target='_blank' rel='noopener'>"
            f"{escape(k['title'])}</a>" if k["link"]
            else f"<span>{escape(k['title'])}</span>")
        kh_html += (
            f"<li data-lane='{escape(k['lane'])}' "
            f"data-q='{escape(q, quote=True)}'>"
            f"<span class='date'>{escape(k['date'])}</span>"
            f"<span class='khlane kh-{escape(k['lane'])}' "
            f"title='{escape(KH_TIP.get(k['lane'], ''), quote=True)}'>"
            f"{escape(k['lane'])}</span>"
            f"{title_html}"
            f"<div class='khsub'>[{escape(k['source'])}]"
            f" &middot; match: {escape(k['term'])}</div></li>")
    kh_html = kh_html or (
        "<li class='empty'>No Cambodia signals yet &mdash; the first sweep "
        "builds them (Google/Bing news, Reddit, Telegram mirrors, "
        "fxtwitter, ransomware feeds).</li>")
    xq = (urllib.parse.quote(KH_X_QUERIES[0]) if KH_X_QUERIES
          else "dark%20web%20cambodia")
    kh_note = ("<div class='khnote'>public OSINT only &middot; no Tor "
               "client &middot; leak-site claims arrive through the "
               "ransomware feeds and public Telegram mirrors &middot; "
               "actor claims are unverified by definition &middot; "
               f"<a href='https://x.com/search?q={xq}&src=typed_query&f=top' "
               "target='_blank' rel='noopener'>open this search on X "
               "&nearr;</a></div>")

    # ---- panels ------------------------------------------------
    kev_html = ""
    for k in kev:
        rw = ("<div class='rans'>&#9878; RANSOMWARE</div>"
              if k["ransomware"] == "Known" else "")
        hits = edb_map.get(k["id"]) if edb_ready else None
        edbtag = ""
        if hits:
            rid = hits[0]
            edbtag = (f"<a class='edb-badge' title='Exploit-DB "
                      f"proof-of-concept exploit' "
                      f"href='https://www.exploit-db.com/exploits/{escape(rid)}' "
                      f"target='_blank'>&#9876; EDB POC <i>×{len(hits)}</i></a>")
        kev_html += (f"<li class='kevline'>"
                     f"<span class='date'>{escape(k['date'])}</span>"
                     f"<span class='ktag' title='CISA Known Exploited "
                     f"Vulnerabilities'>KEV</span> "
                     f"<span class='cveid'><a "
                     f"href='https://nvd.nist.gov/vuln/detail/{escape(k['id'])}'"
                     f" target='_blank'>{escape(k['id'])}</a></span>"
                     f"<div class='vend'>{escape(k['vendor'])} · "
                     f"{escape(k['product'])}</div>"
                     f"<div class='desc2'>{escape(k['name'])}</div>"
                     f"{rw}{edbtag}</li>")
    kev_html = kev_html or "<li class='empty'>No KEV data yet.</li>"

    ai_html = ""
    LANE_TIP = {
        "RELEASE": "new models, products, launches",
        "SECURITY": "AI safety, vulns, policy, defence",
        "ATTACK": "AI-targeted / AI-enabled attacks",
        "RESEARCH": "papers, experiments, analysis",
    }
    for i in ai:
        tip = LANE_TIP.get(i["lane"], "")
        ai_html += (f"<li><span class='date'>{escape(i['date'])}</span>"
                    f"<span class='aitag aitag-{escape(i['lane'])}' "
                    f"title='{tip}'>{escape(i['lane'])}</span>"
                    f"<a href='{escape(i['link'])}' target='_blank' "
                    f"rel='noopener'>{escape(i['title'])}</a><br>"
                    f"<span class='nsrc'>[{escape(i['source'])}]</span></li>")
    ai_html = ai_html or ("<li class='empty'>No AI headlines yet.</li>")

    breach_html = ""
    for b in breach:
        rec = (f"<span class='brec' title='accounts / persons exposed in "
               f"this breach'>{_fmt_count(b['records'])} RECORDS</span>"
               if b.get("records") else "")
        sub = b.get("classes") or b.get("source") or ""
        breach_html += (f"<li class='brow'>"
                        f"<span class='date'>{escape(b['date'])}</span>"
                        f"{rec}"
                        f"<a class='bname' href='{escape(b['link'])}' "
                        f"target='_blank' rel='noopener'>"
                        f"{escape(b['title'])}</a>"
                        f"<div class='bclass'>[{escape(b['source'])}] "
                        f"{escape(sub)}</div></li>")
    breach_html = breach_html or ("<li class='empty'>No breach intel yet "
                                  "(HIBP catalog loading…)</li>")

    GLOSSARY = [
        ("CVE", "Common Vulnerabilities &amp; Exposures — unique public ID "
                "for a disclosed security flaw, e.g. CVE-2026-120276."),
        ("CVSS", "Common Vulnerability Scoring System — 0–10 severity. "
                 "Critical ≥9.0 · High 7–8.9 · Medium 4–6.9 · Low &lt;4."),
        ("KEV", "CISA's Known Exploited Vulnerabilities catalog — flaws with "
                "confirmed in-the-wild exploitation. The RANSOMWARE tag means "
                "known ransomware-campaign use."),
        ("NVD", "NIST National Vulnerability Database — the enriched CVE feed "
                "behind the Recent CVEs panel, including CVSS scores."),
        ("CISA", "US Cybersecurity &amp; Infrastructure Security Agency — "
                 "publishes the KEV catalog and incident advisories."),
        ("EDB", "Exploit-DB — public archive of working exploits. An "
                "<b>EDB POC</b> badge links an exploit matched to that CVE "
                "via its exploit index."),
        ("PoC", "Proof of Concept — runnable exploit code that demonstrates "
                "a vulnerability is real and weaponisable."),
        ("HIBP", "Have I Been Pwned — breach catalog listing organisation, "
                 "breach date, accounts exposed and data classes."),
        ("RECORDS", "Accounts / persons exposed in a breach, mined from HIBP "
                    "counts or headline figures (only when a victim noun "
                    "backs the number)."),
        ("ICT", "Indochina Time, UTC+7 — Cambodia local time. All clocks and "
                "the &lsquo;swept&rsquo; stamp are ICT."),
        ("RSS", "Really Simple Syndication — standard XML news-feed format; "
                "every wire source on this board publishes one."),
        ("API", "Application Programming Interface — here, "
                "<a href='/api/dashboard'>/api/dashboard</a> returns this "
                "board's data as raw JSON."),
        ("RELEASE", "AI lane: new models, products, launches and benchmarks."),
        ("SECURITY", "AI lane: model safety, vulnerabilities, policy, "
                     "defence and regulation."),
        ("ATTACK", "AI lane: AI-targeted or AI-enabled attacks — prompt "
                   "injection, jailbreaks, deepfakes, model theft."),
        ("RESEARCH", "AI lane: papers, experiments and industry analysis."),
    ]
    gloss_html = ("<ul class='gloss-list'>"
                  + "".join(f"<li><span class='gterm'>{t}</span>"
                            f"<span class='gdef'>{d}</span></li>"
                            for t, d in GLOSSARY)
                  + "</ul>")

    cve_rows = []
    for c in cves[:80]:
        sev, cid = c["severity"], c["id"]
        score = f"{c['score']:.1f}" if c.get("score") else "--"
        hits = edb_map.get(cid) if edb_ready else None
        ex = "1" if hits else "0"
        edb = ""
        if hits:
            rid = hits[0]
            victims = len(hits)
            edb = (f"<a class='edb-badge' title='Exploit-DB "
                   f"proof-of-concept exploit' "
                   f"href='https://www.exploit-db.com/exploits/{escape(rid)}' "
                   f"target='_blank'>&#9876; EXPLOIT <i>×{victims}</i></a> ")
        q = f"{cid} {c['description']}".replace('"', "'").lower()
        cve_rows.append(
            f"<li data-sev='{escape(sev)}' data-exp='{ex}' "
            f"data-q='{escape(q)}'>"
            f"<span class='sev sev-{escape(sev)}'>{escape(sev)}</span>"
            f"<span class='cveid'><a href='https://nvd.nist.gov/vuln/detail/"
            f"{escape(cid)}' target='_blank'>{escape(cid)}</a></span>"
            f"<span class='score' title='Common Vulnerability Scoring "
            f"System — 0 bad, 10 catastrophic'>CVSS {score} · "
            f"{escape(c['published'])}</span>"
            f"<div class='desc'>{escape((c['description'] or '')[:230])}</div>"
            f"{edb}</li>")
    cve_rows = cve_rows or ["<li class='empty'>No NVD data yet.</li>"]
    cves_html = "".join(cve_rows)

    edb_html = ""
    for r in edb_latest[:25]:
        etags = "".join(f"<span class='etag'>{escape(r['type'])}</span>"
                        f"<span class='etag'>{escape(r['plat'] or '-')}</span>")
        v = "&#10003; verified" if r.get("ver") else "unverified"
        edb_html += (f"<li class='edbrow'>"
                     f"<span class='date'>{escape(r['date'])} · {v}</span>"
                     f"<span class='cveid'><a "
                     f"href='https://www.exploit-db.com/exploits/"
                     f"{escape(r['id'])}' target='_blank'>"
                     f"&#9876; EDB-{escape(r['id'])}</a></span><br>"
                     f"<span class='d'>{escape(r['d'])}</span><br>"
                     f"{etags}</li>")
    edb_html = edb_html or (
        "<li class='empty'>EDB build failed: "
        + escape(edb_err, quote=False)
        + "<br>fix: commit files_exploits.csv into the repo, "
          "or retry via &#8635; refresh</li>"
        if edb_err else
        ("<li class='empty'>Indexing Exploit-DB… building (10MB, "
         "one-time per deploy)</li>" if edb_building else
         "<li class='empty'>Waiting for Exploit-DB index…</li>"))

    news_html = ""
    for n in news:
        news_html += (f"<li><span class='date'>{escape(n['date'])}</span>"
                      f"<a href='{escape(n['link'])}' target='_blank' "
                      f"rel='noopener'>{escape(n['title'])}</a><br>"
                      f"<span class='nsrc'>[{escape(n['source'])}]</span></li>")
    news_html = news_html or "<li class='empty'>Loading news…</li>"

    gang_html = ""
    maxg = max((g["count"] for g in gangs), default=1) or 1
    for g in gangs:
        h, s, l = _gang_hue(g["gang"])
        chip_style = (f"background:hsla({h},{s}%,{l}%,.13);"
                      f"border-color:hsla({h},80%,65%,.5);"
                      f"color:hsl({h},90%,74%)")
        w = max(g["count"] / maxg * 100, 2.5)
        gang_html += (f"<li class='gangrow'>"
                      f"<span class='gchip' style='{chip_style}'>"
                      f"{escape(g['gang'])}</span>"
                      f"<span class='gbar' style='width:{w:.0f}%'></span>"
                      f"<span class='gcount'>×{g['count']}</span></li>")
    gang_html = gang_html or "<li class='empty'>No gang signals yet.</li>"

    attacks_html = ""
    for a in attacks[:20]:
        h, s, l = _gang_hue(a["gang"])
        gstyle = (f"color:hsl({h},90%,72%);"
                  f"background:hsla({h},75%,62%,.12);"
                  f"padding:2px 7px;border-radius:5px;"
                  f"border:1px solid hsla({h},80%,60%,.4)")
        vic = (f"<a class='vurl' href='{escape(a['url'])}' target='_blank'>"
               f"{escape(a['victim'])}</a>" if a["url"]
               else f"<span class='vrow'>{escape(a['victim'])}</span>")
        attacks_html += (f"<li><span class='date'>{escape(a['date'])}</span>"
                         f"<span class='vgang' style='{gstyle}'>"
                         f"{escape(a['gang'].upper())}</span>"
                         f"<span class='vc'>&rarr;</span> {vic} "
                         f"<span class='vc'>[{escape(a['country'])}]</span></li>")
    attacks_html = attacks_html or ("<li class='empty'>No victim claims yet.</li>")

    error_box = ""
    if errors:
        error_box = ("<div class='errorbox'><b>feed errors:</b><br>"
                     + "<br>".join(escape(e, quote=False) for e in errors)
                     + "</div>")

    def panel(cls, icon, title, sub, count, body, extra="", ul_id=""):
        ul_attr = f" id='{ul_id}'" if ul_id else ""
        return (f"<section class='panel {cls}'><div class='ph'>"
                f"<div class='ic'>{icon}</div><h2>{title}"
                + (f" <small>{sub}</small>" if sub else "")
                + f"</h2><span class='count'>{count}</span></div>"
                + extra + f"<ul class='ulu'{ul_attr}>{body}</ul></section>")

    cve_ctl = ("<div class='plctl'><input id='q' type='text' "
               "placeholder='filter &mdash; id / product / keyword'>&nbsp;"
               "<button class='chip active' data-fam='sev' data-v='all'>"
               "ALL</button>"
               "<button class='chip' data-fam='sev' data-v='CRITICAL'>"
               "CRIT</button>"
               "<button class='chip' data-fam='sev' data-v='HIGH'>HIGH</button>"
               "<button class='chip' data-fam='sev' data-v='MEDIUM'>MED</button>"
               "<button class='chip' data-fam='exp' data-v='any'>ANY EXP</button>"
               "<button class='chip exp' data-fam='exp' data-v='yes'>"
               "+ EDB POC</button></div>")

    panels = (
        panel("p-kh s12", "&#127472;&#127469;", "KH Watch",
              "cambodia · leak · breach · darkweb · social", len(kh),
              kh_html, kh_ctl + kh_note, ul_id="kh")
        + panel("p-kev s4", "&#9888;", "Known Exploited", "CISA KEV", len(kev),
              kev_html)
        + panel("p-cve s8", "&#128273;", "Recent CVEs", f"NVD · {CVE_WINDOW}",
                len(cves), cves_html, cve_ctl, ul_id="cves")
        + panel("p-edb s6", "&#9876;", "Exploit-DB", "latest public exploits",
                len(edb_latest), edb_html)
        + panel("p-ai s6", "&#129302;", "AI Wire", "releases · security · "
                "attacks", len(ai), ai_html)
        + panel("p-vic s7", "&#128296;", "Ransomware Victims", "live claims",
                len(attacks), attacks_html)
        + panel("p-gang s5", "&#128101;", "Active Gangs", "24h leaderboard",
                len(gangs), gang_html)
        + panel("p-breach s5", "&#128274;", "Data Breaches",
                "hibp catalog · live wire", len(breach), breach_html)
        + panel("p-news s7", "&#128240;", "Security News", "wire", len(news),
                news_html)
    )

    return (HTML_HEAD
            .replace("__CSS__", CSS.strip())
            .replace("__UPDATED__", escape(updated, quote=False))
            .replace("__ERROR_BOX__", error_box)
            .replace("__KPIS__", kpis)
            .replace("__MIXBAR__", mixbar)
            .replace("__MIXLEG__", mixleg)
            .replace("__GLOSS_POP__", gloss_html)
            .replace("__PANELS__", panels)
            .replace("__JS__", JS.strip()))


# ------------------------------------------------------------------ server

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/dashboard":
            with DATA_LOCK:
                snap = {k: (list(v) if isinstance(v, list) else v)
                        for k, v in DATA.items()}
                snap["edb_map_ready"] = EDB["ready"]
                snap["sweep_running"] = SWEEP["running"]
                snap["edb_state"] = {"building": EDB["building"],
                                     "ready": EDB["ready"],
                                     "error": EDB["error"],
                                     "size": EDB["size"]}
                body = json.dumps(snap, default=str).encode()
            ct, code = "application/json", 200
        elif self.path == "/refresh":
            ok = trigger_refresh()
            body = json.dumps({
                "status": "started" if ok else "busy",
                "running": SWEEP["running"],
                "updated": DATA["updated"],
            }).encode()
            ct, code = "application/json", 200
        elif self.path.startswith("/watch"):
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            res = watch_post((qs.get("url") or [""])[0])
            body = json.dumps(res, default=str).encode()
            ct, code = "application/json", 200
        elif self.path in ("/", "/index.html"):
            body = render().encode()
            ct, code = "text/html; charset=utf-8", 200
        else:
            body, ct, code = b"not found", "text/plain", 404
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    print(r"""
  ____ _   _    _    ____   ____ ___  _   _  ____
 / ___| | | |  / \  |  _ \ | __ ) _ \| | | |/ ___|
| |   | |_| | / _ \ | | | ||  _ \| | | | | | \___ \
| |___|  _  |/ ___ \| |_| || |_) | |_| | |_| |___) |
 \____|_| |_/_/   \_\____/ |____/ \___/ \___/|____/

     Threat Intel Console v4
""", flush=True)
    with DATA_LOCK:
        cached = _cve_load()
        if cached:
            DATA["cves"] = cached
            print(f"[*] CVE cache loaded: {len(cached)} rows", flush=True)
    threading.Thread(target=refresh_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[*] Serving on http://localhost:{PORT} "
          f"(host 0.0.0.0, $PORT={os.environ.get('PORT', 'unset')})",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] shutting down", flush=True)
        srv.shutdown()


if __name__ == "__main__":
    main()
