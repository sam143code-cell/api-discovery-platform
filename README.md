# API Discovery Platform

Production-grade API discovery and security evaluation platform.
Covers: external scan, source code, logs, traffic, gateways, OWASP, classification, reporting.

---

## Step-by-Step Setup

### Step 1 — Python 3.9+
```powershell
python --version
```

### Step 2 — Virtual environment
```powershell
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # Linux/Mac
```

### Step 3 — Install dependencies
```powershell
pip install aiohttp requests beautifulsoup4 lxml pyyaml playwright reportlab python-docx
```

Optional (install only what you need):
```powershell
pip install pyshark scapy        # PCAP + live traffic analysis
pip install boto3                # AWS API Gateway interrogation
pip install semgrep              # Source code security scanning
```

### Step 4 — Install Playwright browser
```powershell
python -m playwright install chromium
```

### Step 5 — Download wordlists
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" -OutFile "wordlists\api-endpoints.txt"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt" -OutFile "wordlists\raft-large.txt"
Invoke-WebRequest -Uri "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2026_02_27.txt" -OutFile "wordlists\assetnote-api.txt"

# Merge all
Get-Content wordlists\api_paths.txt, wordlists\api-endpoints.txt, wordlists\assetnote-api.txt, wordlists\raft-large.txt | Sort-Object -Unique | Set-Content wordlists\combined.txt
```

### Step 6 — Configure inputs
Edit `config.yaml` — set client name, engagement name, output directory.

Put client inputs in the `inputs/` folder:
```
inputs/
  domains.txt          ← one domain per line
  repos.txt            ← GitHub/GitLab repo URLs (optional)
  gateway_exports/     ← Kong/Apigee/OpenAPI exports (optional)
  openapi_specs/       ← existing OpenAPI/Swagger specs (optional)
  logs/                ← WAF/CDN/gateway/server logs (optional)
  pcap/                ← PCAP files (optional)
  baseline.json        ← approved API registry (optional)
```

---

## Running Scans

### Quick test — single domain, passive mode
```powershell
python main.py --domain http://rest.vulnweb.com --mode passive
```

### Standard engagement scan
```powershell
python main.py
```

### Active OWASP testing (non-prod only)
```powershell
python main.py --mode active
```

### Skip specific phases
```powershell
python main.py --disable-phase owasp traffic_analysis source_scan
```

### Custom config file
```powershell
python main.py --config cibil_config.yaml
```

---

## Output Files

All outputs go to the `output/` directory (configurable in config.yaml):

| File | Description |
|------|-------------|
| `api_discovery_full.json` | Complete machine-readable inventory |
| `shadow_rogue_register.json` | Shadow & Rogue API register |
| `executive_report.pdf` | CISO-ready PDF report |
| `api_discovery_report.docx` | Word document for client delivery |

---

## File Structure

```
api_discovery_platform/
├── main.py                              ← run this
├── config.yaml                          ← all settings
├── requirements.txt
├── README.md
│
├── store/
│   ├── schema.py                        ← APIEntry data model
│   └── store.py                         ← central thread-safe store
│
├── pipeline/
│   ├── p01_external_scan/scanner.py     ← web crawl, JS, brute force, GraphQL, subdomains
│   ├── p02_source_scan/scanner.py       ← GitHub repos, semgrep, secret scanning
│   ├── p03_log_analysis/scanner.py      ← auto-detect + parse all log formats
│   ├── p04_traffic_analysis/scanner.py  ← PCAP parser + live agent
│   ├── p05_gateway_query/scanner.py     ← Kong, AWS, Apigee, Azure, Nginx, K8s
│   ├── p06_classifier/classifier.py     ← Valid/Shadow/New/Rogue engine
│   ├── p07_owasp/scanner.py            ← OWASP API Top 10 passive + active
│   ├── p08_enrichment/enricher.py       ← auth, sensitivity, CVE, risk score
│   └── p09_reporter/reporter.py         ← JSON + PDF + Word reports
│
├── inputs/                              ← client-provided data goes here
│   ├── domains.txt
│   ├── repos.txt
│   ├── baseline.json
│   ├── gateway_exports/
│   ├── openapi_specs/
│   ├── logs/
│   └── pcap/
│
├── wordlists/
│   ├── api_paths.txt                    ← bundled
│   └── combined.txt                     ← merged (create in step 5)
│
└── output/                              ← all reports written here
```

---

## Detection Coverage

| Source | What it finds | Requires |
|--------|--------------|----------|
| External web scan | Public APIs, JS-loaded routes, subdomains | Domain name |
| Source code scan | Route definitions, hardcoded endpoints, secrets | Repo access |
| Log analysis | Every API ever called, consumer IDs, auth types | Log files |
| Traffic analysis | Internal service-to-service APIs, HTTPS with key | PCAP or live agent |
| Gateway query | Registered routes, service ownership | Gateway credentials |
| OWASP assessment | Auth issues, misconfig, BOLA, SSRF, rate limits | Active endpoints |

## Classification Logic

| Classification | Condition |
|----------------|-----------|
| **Valid** | Found in gateway export OR OpenAPI spec OR baseline registry |
| **Shadow** | Exists in traffic/code/scan but NOT in any authorized source |
| **New** | In authorized sources but appeared after `new_api_since` date |
| **Rogue** | Matches rogue patterns (debug, admin, internal) AND not authorized |

## Log Formats Supported

Auto-detected: nginx/Apache CLF, JSON flat, Kong JSON, AWS ALB, W3C IIS, Cloudflare JSON.
Fallback: tries all parsers. If unknown format, prints format hint.

## TLS Handling (Live Agent)

| Mode | How | Best for |
|------|-----|---------|
| `mirror` | Receives decrypted copy from LB | F5, nginx, HAProxy mirror port |
| `keylog` | NSS key log file decryption | When LB exports TLS keys |
| `http_only` | Plain HTTP only | Dev/internal unencrypted traffic |
