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

Other knobs live at the top of `dashboard.py`: `REFRESH_MAX_AGE` (900s sweep cadence), `FETCH_TIMEOUT` (25s/source), `BREACH_AGE` (6h HIBP TTL).

## HTTP API

| Endpoint | Response |
|---|---|
| `GET /` | The board |
| `GET /api/dashboard` | Full JSON: `cves`, `kev`, `edb`, `attacks`, `gangs`, `ai`, `breach`, `news`, `updated`, `errors`, `sweep_running`, `edb_state` |
| `GET /refresh` | `{"status":"started"}` or `{"status":"busy"}` — kicks one guarded background sweep |

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
printf '__pycache__/\nfiles_exploits.csv\nexploit_index.json\nbreach_cache.json\n.DS_Store\n' > .gitignore
git add .
git commit -m "cyberdashboard: zero-dep threat intel console"
gh repo create cyberdashboard --public --source=. --remote=origin --push
```

## Layout

```
cyberdashboard/
├── dashboard.py          # the whole app (server + fetchers + render)
├── files_exploits.csv    # optional bootstrap copy (gitignored)
├── exploit_index.json    # generated EDB index (gitignored)
├── breach_cache.json     # generated HIBP cache (gitignored)
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
