# ☠ CYBERDASHBOARD

**A zero-dependency threat-intel console.** One Python file, stdlib only — no pip, no npm, no build step. Points at nine public, keyless feeds and fuses them into a single live board.

```bash
python3 dashboard.py
open http://localhost:11111
```

> Model grafted from [cybermonit.com/cve](https://cybermonit.com/cve)'s data thesis: detections · exploits · breaches · ransomware ops · AI wire — one ops screen.

---

## Panels

| Panel | Source | What you get |
|---|---|---|
| **KH Watch** | Google News · Bing News · Khmer Times · VOD English · CamboJA · Telegram public mirrors · fxtwitter · ransomware.live (KH) · Reddit · HIBP | Cambodia-facing exposure feed, lane-tagged **RANSOM / LEAK / BREACH / DARKWEB / SOCIAL / REPORT**, filterable |
| **Recent CVEs** | NVD 2.0 API | Newest 80 CVEs, severity-scored, filterable, linked to NVD |
| **Known Exploited** | CISA KEV | Actively-exploited vulns, ransomware-use flag, EDB PoC badges |
| **Exploit-DB** | exploit-database CSV | Latest public exploits + CVE↔PoC mapping across the board |
| **AI Wire** | VentureBeat AI · The Decoder · MarkTechPost · r/MachineLearning | Headlines lane-tagged **RELEASE / SECURITY / ATTACK / RESEARCH** |
| **Ransomware Victims** | ransomware.live · ransomfeed.it | Live claim feed, deduped across both sources |
| **Active Gangs** | same feeds | 24h leaderboard with merged counts |
| **Data Breaches** | HIBP catalog · DataBreaches.net | Breach records with exposed-account badges |
| **Security News** | The Hacker News · BleepingComputer · Krebs · Exploit-DB | Date-sorted wire |
| **Severity Mix** | computed | Critical/High/Medium/Low ratio bar across the top |

## Features

- **Live clock in UTC+7 (ICT)** and an `↻ refresh` button — forces an immediate sweep with a lock guard (never double-runs)
- **Filter box + chips** on the CVE panel: substring on id/description × severity × exploit-availability, combinable
- **KH Watch** — Cambodia exposure panel. Matches KH/Khmer/柬埔寨 terms plus local banks, telcos, ministries, provinces and `.kh` domains across public news RSS (Google News, Bing News, Khmer Times, VOD English, CamboJA), Telegram previews, Reddit (opt-in), fxtwitter post mirrors, `ransomware.live/v2/countryvictims/KH` and the full HIBP catalog. Matching is word-boundary anchored, because substring matching put a French credential-stuffing list in this panel via "account ta**keo**ver". Two-tier gate: a strong signal (`breach`, `hacked`, `ransomware`, `database`, `CVE-…`) admits on its own; a weak verb (`leak`, `attack`, `exposed`) needs a data noun beside it. Generic ministries are excluded from non-Cambodia-scoped feeds so Malaysia's MoH never wears a KH flag. Cyber-conflict stories are forced to REPORT
- **X search bridge** — X's search page is login-gated and its syndication endpoint 429s, so the lane goes through the search index (DuckDuckGo lite) for `site:x.com` queries, then resolves each indexed status URL through fxtwitter. Queries rotate one per sweep — five keyword queries plus one `site:x.com/<account>` query per watched account — results persist in `x_search_cache.json`, and a 202 throttle buys a 30-minute backoff instead of hammering. Set `X_BEARER_TOKEN` for guaranteed live search
- **Reddit lane** — `reddit.com`'s JSON and RSS endpoints answer 403/429 to datacenter IPs, so the lane rides **Arctic Shift**'s public archive instead: keyless, no auth, no rate-limit agreement. One recency pull of r/cambodia per sweep (where a Cambodian breach post would actually land), plus one rotating task — either a full-text query inside r/cambodia or a recency pull from a low-volume sub (`DataBreach`, `ransomware`, `threatintel`, `blueteamsec`, `scambait`, `netsec`, `cybersecurity`, `darknet`, `privacy`). Calls are spaced 60s because Arctic Shift 422s ("slow down") on bursts; results persist in `reddit_cache.json`. A failed *search* only pauses searches for 30 minutes — it never takes down the recency path. Subreddit rows must name a cyber mechanism themselves, so "breach of contract" in r/cambodia does not read as a data breach
- **Pin any post** — `GET /watch?url=<x-status-url>` resolves one tweet through fxtwitter and drops it straight into KH Watch and the cache, no sweep required
- **Hover glossary** — small pill in the header, two-column card with every abbreviation decoded
- **Everything sorted newest-first**, dates normalized across Atom/RSS/JSON sources
- **Retain-last-good** — a failing feed keeps its previous data and banners the error instead of blanking the panel
- **Adaptive NVD windowing** — the full 7-day NVD pull is ~5MB and crawls on slow links; the fetcher shrinks 7d→3d→2d→1d until the result set fits one page, then keeps the newest slice
- **Disk caches** — Exploit-DB index (~5s rebuild from a local CSV) and HIBP catalog (6h TTL) survive restarts
- **JSON API** on top: `/api/dashboard`, `/refresh`

## Quickstart

Requirements: Python 3.9+ (no packages).

```bash
git clone <your-repo> && cd cyberdashboard
python3 dashboard.py
# → http://localhost:11111
```

### Optional: bootstrap the Exploit-DB index locally

The full `files_exploits.csv` (~10MB) is fetched once in a background thread on first boot; the index is then rebuilt from disk in seconds. To skip the first download — or to guarantee it works on hosts whose egress IPs get throttled (e.g. free Render) — drop the CSV next to the script:

```bash
curl -L "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" \
  -o files_exploits.csv
```

The server checks for a local, size-matching copy before any network call.

### Optional: NVD API key

Anonymous NVD access is limited to ~5 requests / 30s per IP. On shared egress (PaaS free tiers), set:

```bash
NVD_API_KEY=your-key python3 dashboard.py
# Render: Settings → Environment → add NVD_API_KEY
```

Free key: <https://nvd.nist.gov/developers/request-an-api-key>

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | `11111` | Listen port (Render injects this automatically) |
| `NVD_API_KEY` | — | Sent as `apiKey` header to NVD |
| `KH_WATCH_POSTS` | DailyDarkWeb seed post | Comma-separated X/Twitter post URLs pinned into KH Watch, resolved through fxtwitter |
| `KH_TELEGRAM_CHANNELS` | `falconfeedsio,databreaches,leakbase,CyberSecurityTechnologies` | Public Telegram channels scraped via `t.me/s/<channel>` previews |
| `KH_REDDIT` | on | Set `0` to disable the Reddit lane (Arctic Shift archive; no key needed) |
| `KH_REDDIT_SUBS` | `DataBreach,ransomware,threatintel,blueteamsec,scambait,netsec,cybersecurity,darknet,privacy` | Subs rotated for recency pulls; r/cambodia is always pulled |
| `KH_X_QUERIES` | `dark web cambodia, cambodia data leak, cambodia breach, cambodia ransomware, cambodia hacker` | Search-index queries for the X lane; one rotates per sweep |
| `KH_X_ACCOUNTS` | `VECERTRadar,DailyDarkWeb,DarkWebInformer,CyberThreatLine,FalconFeedsio,HackManac,ThreatMon,ransomwatch` | Accounts hunted with a `site:x.com/<account> cambodia` query each rotation |
| `KH_FEEDS` | Khmer Times · VOD English · CamboJA | In-code tuple of Cambodian newsroom RSS feeds (Phnom Penh Post is Cloudflare-gated, Kiripost is client-rendered) |
| `X_BEARER_TOKEN` | — | Optional X API v2 recent-search for the KH lane (the only guaranteed-live path) |
| `FB_ACCESS_TOKEN` | — | Optional Graph API token for Facebook Page monitoring |
| `KH_FB_PAGES` | — | Comma-separated Facebook Page ids/names to poll when a token is set |

Other knobs live at the top of `dashboard.py`: `REFRESH_MAX_AGE` (900s sweep cadence), `FETCH_TIMEOUT` (25s/source), `BREACH_AGE` (6h HIBP TTL).

## HTTP API

| Endpoint | Response |
|---|---|
| `GET /` | The board |
| `GET /api/dashboard` | Full JSON: `cves`, `kev`, `edb`, `attacks`, `gangs`, `ai`, `breach`, `kh`, `news`, `updated`, `errors`, `sweep_running`, `edb_state` |
| `GET /refresh` | `{"status":"started"}` or `{"status":"busy"}` — kicks one guarded background sweep |
| `GET /watch?url=<tweet>` | Resolves one X post and pins it into KH Watch: `{"status":"pinned","title":…,"date":…,"link":…}` |

## Deploy on Render

1. Push this directory as a repo (see below)
2. Render → **New → Web Service** → connect repo
3. Runtime **Python** · Build `echo "no build needed"` · Start `python dashboard.py` · Health path `/`
4. Add `NVD_API_KEY` env for quota immunity (optional but recommended on free tier)

Optional blueprint — `render.yaml`:

```yaml
services:
  - type: web
    name: cyberdashboard
    runtime: python
    plan: free
    buildCommand: echo "no build needed"
    startCommand: python dashboard.py
    healthCheckPath: /
    autoDeploy: true
```

Free-tier note: instances sleep after ~15 min idle; the first hit afterwards takes ~40s to re-sweep.

## Push to GitHub

```bash
git init
printf '__pycache__/\nfiles_exploits.csv\nexploit_index.json\nbreach_cache.json\ncve_cache.json\n.DS_Store\n' > .gitignore
git add .
git commit -m "cyberdashboard: zero-dep threat intel console"
gh repo create cyberdashboard --public --source=. --remote=origin --push
```

`x_search_cache.json` and `reddit_cache.json` are deliberately **not** ignored — they ship warm so Render's cold boot has rows before the first throttle-free sweep.

## Layout

```
cyberdashboard/
├── dashboard.py          # the whole app (server + fetchers + render)
├── files_exploits.csv    # optional bootstrap copy (gitignored)
├── exploit_index.json    # generated EDB index (gitignored)
├── breach_cache.json     # generated HIBP cache (gitignored)
├── cve_cache.json        # last-good CVE slice, cold-boot fallback (gitignored)
├── x_search_cache.json   # warm X search rows (committed on purpose)
├── reddit_cache.json     # warm Reddit rows (committed on purpose)
└── README.md
```

## Design notes

- **No dependencies** is a feature: `http.server` + `urllib` + `xml.etree` + `json`. Any Python box can run it.
- **Every source fails soft.** Feeds are fetched independently; a dead feed banners an error and keeps the last good rows.
- **Freshness is verified against source.** The CVE panel's top row matches NVD's newest `published` timestamp (checked 2026-11-03: `CVE-2026-120830`, 00:17 UTC — reproduced exactly).
- **Date normalization matters.** Atom `updated`, RSS `pubDate`, and JSON epoch all collapse to `YYYY-MM-DD [HH:MM]` so lexicographic sort == temporal sort.

## Boundaries

Read-only aggregation of public feeds. No accounts, no tracking, no outbound writes. Keep the feeds' terms in mind if you deploy publicly; they're all free-access endpoints.

---

*Built with stdlib, spite, and respect for the wire.*
