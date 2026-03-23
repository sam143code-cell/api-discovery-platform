"""
pipeline/p02_source_scan/scanner.py
All previous fixes preserved. New addition:
  - Enhanced _extract_outbound_deps: captures ALL absolute URL calls (axios/fetch to http/https)
    not just known third-party hosts — produces rich outbound API inventory
  - _detect_outbound_auth: detects auth method used in outbound call
  - _classify_outbound_url: returns integration name, category, exposure, risk
  - Deduplication now by (host + path_prefix) — distinguishes multiple APIs on same server
  - store.outbound_api_inventory assigned in run() as first-class section for reporter
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path

# ── Route extraction patterns ────────────────────────────────────────────────

ROUTE_PATTERNS = {
    "python": [
        r'@(?:app|router|blueprint)\.(get|post|put|delete|patch|route)\(["\']([^"\']+)["\']',
        r'(?:app|router)\.add_route\(["\'](\w+)["\'],\s*["\']([^"\']+)["\']',
        r'path\(["\']([^"\']+)["\']',
        r'url\(["\']([^"\']+)["\']',
    ],
    "javascript": [
        r'[a-zA-Z_$][a-zA-Z0-9_$]*\.(get|post|put|delete|patch)\s*\(\s*["\']([/][^"\']+)["\']',
        r'axios\.(get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']',
        r'fetch\s*\(\s*[`"\']([/][^`"\'?#]+)[`"\'][^)]*method\s*:\s*[`"\'](GET|POST|PUT|DELETE|PATCH)[`"\']',
        r'fetch\s*\(\s*[`"\']([/][^`"\'?#]+)[`"\']',
        r'path\s*:\s*["\']([/][^"\']+)["\']',
    ],
    "go": [
        r'(?:r|mux|router)\.(GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\(["\']([^"\']+)["\']',
        r'http\.Handle\(["\']([^"\']+)["\']',
    ],
    "java": [
        r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(["\']([^"\']+)["\']',
        r'@Path\(["\']([^"\']+)["\']',
    ],
    "ruby": [
        r'(?:get|post|put|delete|patch)\s+["\']([^"\']+)["\']',
        r'resources\s+:(\w+)',
    ],
}

LANG_EXT = {
    ".py": "python", ".js": "javascript", ".ts": "javascript",
    ".jsx": "javascript", ".tsx": "javascript", ".mjs": "javascript",
    ".go": "go", ".java": "java", ".rb": "ruby",
}

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", "target", ".idea",
    "coverage", ".nyc_output", "logs", "tmp",
}

# ── Noise filters ─────────────────────────────────────────────────────────────

NON_API_EXTENSIONS = {
    ".h5", ".pkl", ".pt", ".pth", ".onnx",
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".css", ".woff", ".woff2", ".ttf",
    ".map", ".min.js",
}

NON_API_PATH_PATTERNS = [
    re.compile(r'^/models/', re.I),
    re.compile(r'\.(h5|pkl|pt|onnx|pb|tflite)$', re.I),
    re.compile(r'^/https?://', re.I),
    re.compile(r'^\.\.[/\\]'),
    re.compile(r'^[a-zA-Z]:[/\\]'),
    re.compile(r'^/[a-zA-Z]:[/\\]'),
]

MIDDLEWARE_NOISE = {"/use", "/:id", "/:zoneId", "/*", "/", ""}

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

# ── Outbound API patterns ─────────────────────────────────────────────────────

# CDN / static asset hosts — skip these
CDN_NOISE_HOSTS = {
    "fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net", "unpkg.com", "stackpath.bootstrapcdn.com",
    "code.jquery.com", "ajax.googleapis.com", "maxcdn.bootstrapcdn.com",
    "cdn.datatables.net", "use.fontawesome.com",
}

# Patterns that detect outbound HTTP calls with method context
OUTBOUND_CALL_PATTERNS = [
    # axios.get/post/etc('https://...')
    re.compile(
        r'axios\.(get|post|put|delete|patch)\s*\(\s*[`"\']?(https?://[^`"\')\s,]+)[`"\']?',
        re.I
    ),
    # fetch('https://...')
    re.compile(
        r'fetch\s*\(\s*[`"\']?(https?://[^`"\')\s,]+)[`"\']?',
        re.I
    ),
    # axios({ url: 'https://...' })
    re.compile(
        r'url\s*:\s*[`"\']?(https?://[^`"\')\s,]+)[`"\']?',
        re.I
    ),
    # http.get / https.get (Node built-in)
    re.compile(
        r'https?\.(get|post|request)\s*\(\s*[`"\']?(https?://[^`"\')\s,]+)[`"\']?',
        re.I
    ),
    # got / request / superagent
    re.compile(
        r'(?:got|request|superagent)\s*[\.(]\s*(?:get|post|put|delete|patch)?\s*\(\s*[`"\']?(https?://[^`"\')\s,]+)[`"\']?',
        re.I
    ),
]

# Known integration catalog: (hostname_pattern, name, category, exposure)
KNOWN_INTEGRATIONS = [
    (re.compile(r"virustotal",      re.I), "VirusTotal",             "Threat Intelligence",    "External"),
    (re.compile(r"shodan",          re.I), "Shodan",                 "Threat Intelligence",    "External"),
    (re.compile(r"nvd\.nist",       re.I), "NVD / NIST",             "Vulnerability Database", "External"),
    (re.compile(r"cve\.mitre",      re.I), "CVE MITRE",              "Vulnerability Database", "External"),
    (re.compile(r"github\.com",     re.I), "GitHub",                 "Source Control",         "External"),
    (re.compile(r"amazonaws",       re.I), "AWS",                    "Cloud Provider",         "External"),
    (re.compile(r"googleapis",      re.I), "Google APIs",            "Cloud Provider",         "External"),
    (re.compile(r"azure|microsoft", re.I), "Azure / Microsoft",      "Cloud Provider",         "External"),
    (re.compile(r"cloudflare",      re.I), "Cloudflare",             "CDN / Security",         "External"),
    (re.compile(r"manageengine|servicedesk|itsm", re.I), "ManageEngine ITSM", "ITSM Integration", "Internal"),
    (re.compile(r"threatgraph|threat[\._-]graph", re.I), "Threat Graph API", "Threat Intelligence", "External"),
    (re.compile(r"\bldap\b",        re.I), "LDAP / Active Directory","Identity Provider",      "Internal"),
    (re.compile(r"kafka",           re.I), "Apache Kafka",           "Message Broker",         "Internal"),
    (re.compile(r"rabbitmq",        re.I), "RabbitMQ",               "Message Broker",         "Internal"),
    (re.compile(r"elasticsearch|opensearch", re.I), "Elasticsearch", "Search Engine",          "Internal"),
    (re.compile(r"redis",           re.I), "Redis",                  "Cache Layer",            "Internal"),
    (re.compile(r"sendgrid",        re.I), "SendGrid",               "Email Service",          "External"),
    (re.compile(r"smtp|nodemailer", re.I), "SMTP Email",             "Email Service",          "Internal"),
    (re.compile(r"twilio",          re.I), "Twilio",                 "SMS / Telephony",        "External"),
    (re.compile(r"stripe",          re.I), "Stripe",                 "Payment Gateway",        "External"),
    (re.compile(r"paypal",          re.I), "PayPal",                 "Payment Gateway",        "External"),
    (re.compile(r"firebase",        re.I), "Firebase",               "Cloud Database",         "External"),
    (re.compile(r"mongodb\.com|atlas", re.I), "MongoDB Atlas",       "Cloud Database",         "External"),
    (re.compile(r"zoho",            re.I), "Zoho",                   "Business SaaS",          "External"),
    (re.compile(r"servicenow",      re.I), "ServiceNow",             "ITSM Integration",       "External"),
    (re.compile(r"jira|atlassian",  re.I), "Jira / Atlassian",       "Project Management",     "External"),
    (re.compile(r"slack\.com",      re.I), "Slack",                  "Collaboration",          "External"),
    (re.compile(r"graph\.microsoft|teams\.microsoft", re.I), "Microsoft Graph", "Collaboration", "External"),
    (re.compile(r"pagerduty",       re.I), "PagerDuty",              "Incident Management",    "External"),
    (re.compile(r"splunk",          re.I), "Splunk",                 "SIEM",                   "Internal"),
]

# ── Secret patterns ───────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "api_key"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "secret_key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "password"),
    (r'(?i)(token|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "token"),
    (r'(?i)(bearer\s+)([A-Za-z0-9_\-\.]{20,})', "bearer_token"),
    (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', "aws_key"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "private_key"),
]

# ── Framework detection ───────────────────────────────────────────────────────

FRAMEWORK_INDICATORS = {
    "express":  [r"require\(['\"]express['\"]", r"from ['\"]express['\"]", r"express\(\)"],
    "fastapi":  [r"from fastapi", r"FastAPI\(\)"],
    "django":   [r"from django", r"urlpatterns"],
    "flask":    [r"from flask", r"Flask\(__name__\)"],
    "spring":   [r"@SpringBootApplication", r"@RestController"],
    "nestjs":   [r"@Module\(", r"@Controller\("],
    "koa":      [r"require\(['\"]koa['\"]", r"new Koa\(\)"],
    "hapi":     [r"require\(['\"]@hapi/hapi['\"]"],
}

MANIFEST_FILES = {
    "package.json", "package-lock.json",
    "requirements.txt", "pipfile",
    "pom.xml", "build.gradle",
    "go.mod", "gemfile",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_noise(endpoint: str, method: str) -> bool:
    if not endpoint or len(endpoint) < 2:
        return True
    if endpoint in MIDDLEWARE_NOISE:
        return True
    for pat in NON_API_PATH_PATTERNS:
        if pat.search(endpoint):
            return True
    path_lower = endpoint.lower().split("?")[0]
    for ext in NON_API_EXTENSIONS:
        if path_lower.endswith(ext):
            return True
    if not endpoint.startswith("/") and not endpoint.startswith("http"):
        return True
    return False


def _extract_path_params(path: str) -> List[Dict]:
    params = []
    for match in re.finditer(r':([a-zA-Z_][a-zA-Z0-9_]*)\??', path):
        params.append({"name": match.group(1), "in": "path", "type": "string",
                       "required": not path[match.end()-1:match.end()] == "?"})
    for match in re.finditer(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}', path):
        params.append({"name": match.group(1), "in": "path", "type": "string", "required": True})
    return params


def _extract_api_version(path: str) -> Optional[str]:
    m = re.search(r'/v(\d+)(?:/|$)', path, re.I)
    return f"v{m.group(1)}" if m else None


def _infer_module_from_path(file_path: str, endpoint: str) -> str:
    fp = file_path.lower().replace("\\", "/")
    ep = endpoint.lower()
    module_map = [
        (["vulnerability/count", "vulnetcount", "vulcountby", "vulpatchcount",
          "ransomwarenet", "exploitdb", "cvss3", "epss", "cwecount", "kevcount"], "Vulnerability Management - Counts"),
        (["vulnerability/list", "vultotallist", "kevvullist", "uniquevullist",
          "cwelist", "cvss3list", "epsslist", "vulnpatchlist", "ransomwarelist"], "Vulnerability Management - Lists"),
        (["login", "auth", "logout", "otp", "verify", "confirm", "register"], "Authentication & Session"),
        (["upload", "uploadcsv", "uploadasset", "uploadhuman", "clearuploaded", "previewcsv",
          "approveReject", "scannerResult"], "Data Upload & Ingestion"),
        (["menu", "permission", "role", "access"], "Access Control & RBAC"),
        (["crq", "businessrisk", "riskadjusted", "scoi"], "Cyber Risk Quantification"),
        (["cia", "cia-for", "confidentiality", "integrity", "availability"], "CIA Triad Assessment"),
        (["hardware", "software", "database", "humanresource", "api-cia"], "Asset CIA Mapping"),
        (["comp-risk", "comp-threat", "comp-asset", "comp-attack"], "Comparative Analysis"),
        (["trending", "active-threat", "active-malware", "active-vul", "threat-demo",
          "attack-path", "malware", "indicator", "intrusion"], "Threat Intelligence"),
        (["report-count", "report-list", "generate-report"], "Reporting"),
        (["acrs", "wcr", "resilency", "ccei", "cpre", "organizational-score"], "Risk Scoring"),
        (["scannedhosts", "autodiscovery", "autodiscover", "zoneswitch", "scannedhostdetails"], "Host Discovery & Scanning"),
        (["request", "sendrequest", "sendbulk", "incident", "escalate", "getassets",
          "getsites", "getgroups", "gettechnicians"], "ITSM Integration"),
        (["groups", "rules", "nodes", "directives", "techniques", "compliance", "global-compliance"], "SIEM / Detection Rules"),
        (["search-attack", "search-cve", "search-ipaddress", "search-defence",
          "searchcveid", "searchhostip", "searchpatch", "cve-id",
          "attack-technique", "defense-technique"], "Search & Lookup"),
        (["risk-acceptance", "ip-risk-approval", "vulnerability-title-risk"], "Risk Acceptance"),
        (["ldap", "activedirectory", "adlist", "ad-dashboard"], "Active Directory Integration"),
        (["manageengine", "itsm"], "ManageEngine ITSM"),
        (["threatgraph", "threat-graph"], "Threat Graph"),
        (["sbom", "models/"], "SBOM & AI/ML Components"),
        (["media", "static", "assets"], "Static Assets"),
        (["probes", "scan", "sources"], "Scanner Core API"),
        (["user", "register"], "User Management"),
    ]
    combined = fp + " " + ep
    for keywords, module in module_map:
        for kw in keywords:
            if kw in combined:
                return module
    return "Uncategorized"


def _detect_framework(content_samples: List[str]) -> str:
    combined = " ".join(content_samples[:10])
    for fw, patterns in FRAMEWORK_INDICATORS.items():
        for pat in patterns:
            if re.search(pat, combined, re.I):
                return fw
    return "unknown"


# ── Package manifest parsers ──────────────────────────────────────────────────

def _parse_package_json(content: str) -> List[Dict]:
    deps = []
    try:
        data = json.loads(content)
        for dep_type in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(dep_type, {}).items():
                clean_ver = re.sub(r'^[\^~>=<]', '', str(version)).strip()
                deps.append({"name": name, "version": clean_ver, "type": dep_type, "ecosystem": "npm"})
    except Exception:
        pass
    return deps


def _parse_requirements_txt(content: str) -> List[Dict]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(?:[><=!]+\s*([^\s,;]+))?', line)
        if m:
            deps.append({"name": m.group(1), "version": m.group(2) or "unknown",
                         "type": "dependencies", "ecosystem": "pypi"})
    return deps


def _parse_pom_xml(content: str) -> List[Dict]:
    deps = []
    for block in re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL):
        group    = re.search(r'<groupId>(.*?)</groupId>', block)
        artifact = re.search(r'<artifactId>(.*?)</artifactId>', block)
        version  = re.search(r'<version>(.*?)</version>', block)
        if artifact:
            name = f"{group.group(1)}:{artifact.group(1)}" if group else artifact.group(1)
            deps.append({"name": name, "version": version.group(1) if version else "unknown",
                         "type": "dependencies", "ecosystem": "maven"})
    return deps


def _parse_go_mod(content: str) -> List[Dict]:
    deps = []
    for m in re.finditer(r'^\s+([a-z][^\s]+)\s+v([^\s]+)', content, re.MULTILINE):
        deps.append({"name": m.group(1), "version": m.group(2),
                     "type": "dependencies", "ecosystem": "go"})
    return deps


def _parse_manifest(filename: str, content: str) -> List[Dict]:
    fname = os.path.basename(filename).lower()
    if fname == "package.json":     return _parse_package_json(content)
    if fname == "requirements.txt": return _parse_requirements_txt(content)
    if fname == "pom.xml":          return _parse_pom_xml(content)
    if fname == "go.mod":           return _parse_go_mod(content)
    return []


# ── Outbound classification helpers ──────────────────────────────────────────

def _classify_outbound_url(url: str) -> Tuple[str, str, str, str]:
    """Returns (integration_name, category, exposure, risk) for a given absolute URL."""
    url_lower = url.lower()
    for pattern, name, category, exposure in KNOWN_INTEGRATIONS:
        if pattern.search(url_lower):
            risk = "HIGH" if exposure == "External" else "MEDIUM"
            return name, category, exposure, risk
    # Heuristic: internal IP
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    is_internal = any(host.startswith(p) for p in
                      ["10.", "192.168.", "172.", "localhost", "127."])
    if is_internal:
        return "Internal Service", "Internal Microservice", "Internal", "MEDIUM"
    return "External Service", "External API", "External", "HIGH"


def _detect_outbound_auth(content: str, url: str, match_start: int) -> str:
    """Detect how authentication is provided for this outbound call."""
    window = content[max(0, match_start - 300): min(len(content), match_start + 300)]
    if re.search(r'process\.env\.|os\.environ|getenv|config\[', window):
        return "env_variable"
    if re.search(r'(?i)bearer|authorization.*header|auth.*header', window):
        return "bearer_token"
    if re.search(r'(?i)basic\s+auth|btoa|base64.*password', window):
        return "basic_auth"
    if re.search(r'["\'][A-Za-z0-9_\-]{20,}["\']', window):
        if re.search(r'(?i)(api[_-]?key|token|secret|auth|apikey)', window):
            return "hardcoded_key"
    if not re.search(r'(?i)(key|token|secret|auth|password|credential)', window):
        return "none"
    return "unknown"


def _outbound_recommendation(integration: str, exposure: str, auth_method: str) -> str:
    parts = []
    if auth_method == "hardcoded_key":
        parts.append(f"CRITICAL: Rotate hardcoded API key for {integration} immediately — move to secrets manager.")
    elif auth_method == "none":
        parts.append(f"No authentication on outbound call to {integration} — verify if intentional.")
    else:
        parts.append(f"Rotate credentials for {integration} on a regular schedule.")
    if exposure == "External":
        parts.append("Validate all responses. Implement circuit breaker and timeout policies.")
    else:
        parts.append(f"Ensure {integration} connection uses TLS. Use service account with least-privilege.")
    return " ".join(parts)


# ── Main Scanner class ────────────────────────────────────────────────────────

class SourceScanner:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg   = cfg
        self.secrets_found:          List[Dict] = []
        self.outbound_deps:          List[Dict] = []   # legacy simple list (backward compat)
        self.outbound_api_inventory: List[Dict] = []   # NEW: rich outbound inventory
        self.package_dependencies:   List[Dict] = []
        self.tech_stack: Dict = {
            "language":  "javascript",
            "runtime":   "Node.js",
            "framework": "unknown",
            "detected_integrations": [],
        }
        self._base_path_map:   Dict[str, str] = {}
        self._content_samples: List[str]      = []
        self._outbound_seen:   Set[str]        = set()  # dedup by host+path_prefix

    async def run(self):
        repos_file = self.cfg.get("repos_file", "inputs/repos.txt")
        repos = []
        if os.path.exists(repos_file):
            with open(repos_file) as f:
                repos = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        for repo_url in repos:
            await self._scan_repo(repo_url)

        self.store.tech_stack            = self.tech_stack
        self.store.outbound_deps         = self.outbound_deps
        self.store.outbound_api_inventory = self.outbound_api_inventory   # NEW
        self.store.secrets_found         = self.secrets_found
        self.store.package_dependencies  = self.package_dependencies

    async def _scan_repo(self, repo_url: str):
        import asyncio
        is_temp    = False
        local_path = repo_url

        if repo_url.startswith("http") or repo_url.startswith("git@"):
            print(f"    Cloning: {repo_url}")
            tmp = tempfile.mkdtemp()
            is_temp = True
            try:
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, tmp],
                    capture_output=True, timeout=120
                )
                if result.returncode != 0:
                    print(f"    Clone failed: {repo_url}")
                    return
                local_path = tmp
            except Exception as e:
                print(f"    Clone error: {e}")
                if is_temp:
                    shutil.rmtree(tmp, ignore_errors=True)
                return

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._prescan_router_mounts, local_path)
            await loop.run_in_executor(None, self._scan_manifests, local_path)
            await loop.run_in_executor(None, self._scan_directory, local_path, repo_url)
            if self.cfg.get("run_semgrep", True):
                await loop.run_in_executor(None, self._run_semgrep, local_path)
            if self.cfg.get("run_secret_scan", True):
                await loop.run_in_executor(None, self._scan_secrets, local_path, repo_url)
        finally:
            if is_temp:
                shutil.rmtree(local_path, ignore_errors=True)

    def _prescan_router_mounts(self, root_path: str):
        var_to_base: Dict[str, str] = {}
        var_to_file: Dict[str, str] = {}

        use_pat = re.compile(
            r'[a-zA-Z_$][a-zA-Z0-9_$]*\s*\.\s*use\s*\(\s*["\']([/][^"\']*)["\']'
            r'\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$]*)',
            re.MULTILINE
        )
        req_pat = re.compile(
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*["\']([^"\']+)["\']',
            re.MULTILINE
        )
        imp_pat = re.compile(
            r'import\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s+from\s+["\']([^"\']+)["\']',
            re.MULTILINE
        )

        for dirpath, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if Path(fname).suffix.lower() not in (".js", ".ts", ".mjs"):
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if len(self._content_samples) < 15:
                        self._content_samples.append(content[:2000])
                    for m in use_pat.finditer(content):
                        base_path  = m.group(1).rstrip("/")
                        router_var = m.group(2)
                        if base_path and base_path != "/":
                            var_to_base[router_var] = base_path
                    for m in req_pat.finditer(content):
                        var_name    = m.group(1)
                        import_path = m.group(2)
                        stem        = Path(import_path).stem.lower()
                        var_to_file[var_name] = stem
                        parts = import_path.replace("\\", "/").split("/")
                        if len(parts) >= 2:
                            var_to_file[var_name + "__dir"] = parts[-2].lower()
                    for m in imp_pat.finditer(content):
                        var_name    = m.group(1)
                        import_path = m.group(2)
                        var_to_file[var_name] = Path(import_path).stem.lower()
                except Exception:
                    pass

        for var_name, base_path in var_to_base.items():
            if var_name in var_to_file:
                self._base_path_map[var_to_file[var_name]] = base_path
            dir_key = var_name + "__dir"
            if dir_key in var_to_file:
                self._base_path_map[var_to_file[dir_key]] = base_path
            self._base_path_map[var_name.lower()] = base_path

        if self._base_path_map:
            print(f"    Router mount map resolved: {len(self._base_path_map)} entries")
            for stem, base in list(self._base_path_map.items())[:10]:
                print(f"      {stem} → {base}")
        else:
            print("    Router mount map: EMPTY — base path prefix will not be applied")
            print("      (no app.use('/path', router) patterns found across any JS file)")

        if self._content_samples:
            fw = _detect_framework(self._content_samples)
            if fw != "unknown":
                self.tech_stack["framework"] = fw

    def _get_base_path(self, fpath: str) -> str:
        path_parts = Path(fpath).parts
        for i in range(len(path_parts) - 1, -1, -1):
            part = path_parts[i].lower()
            stem = Path(part).stem.lower()
            if stem in self._base_path_map:
                return self._base_path_map[stem]
            if part in self._base_path_map:
                return self._base_path_map[part]
        return ""

    def _scan_manifests(self, root_path: str):
        for dirpath, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if fname.lower() not in MANIFEST_FILES:
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    parsed = _parse_manifest(fname, content)
                    if parsed:
                        self.package_dependencies.extend(parsed)
                        print(f"    Manifest: {os.path.relpath(fpath)} → {len(parsed)} deps")
                except Exception:
                    pass
        seen   = set()
        unique = []
        for dep in self.package_dependencies:
            key = f"{dep['name']}:{dep['version']}"
            if key not in seen:
                seen.add(key)
                unique.append(dep)
        self.package_dependencies = unique
        print(f"    Package deps total: {len(self.package_dependencies)} unique packages parsed")

    def _scan_directory(self, path: str, repo_url: str):
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext   = Path(fname).suffix.lower()
                lang  = LANG_EXT.get(ext)
                if not lang:
                    continue
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    self._extract_routes(content, lang, fpath, repo_url)
                    self._extract_outbound_deps(content, fpath, repo_url)
                except Exception:
                    pass

    def _extract_routes(self, content: str, lang: str, filepath: str, repo_url: str):
        import asyncio
        patterns  = ROUTE_PATTERNS.get(lang, [])
        base_path = self._get_base_path(filepath)

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                groups = [g for g in match.groups() if g is not None]
                if not groups:
                    continue

                method_group = None
                path_group   = None
                for g in groups:
                    g_upper = g.upper()
                    if g_upper in HTTP_METHODS:
                        if method_group is None:
                            method_group = g_upper
                    elif g.startswith("/") or g.startswith("http"):
                        if path_group is None:
                            path_group = g

                if path_group is None:
                    non_method = [g for g in groups if g.upper() not in HTTP_METHODS]
                    if non_method:
                        path_group = non_method[0]
                    else:
                        continue

                endpoint = path_group
                method   = method_group if method_group else "UNKNOWN"

                if method == "UNKNOWN":
                    surrounding = content[max(0, match.start() - 5): match.start() + 10]
                    if "fetch(" in surrounding:
                        method = "GET"

                if not endpoint:
                    continue
                if not endpoint.startswith("/") and not endpoint.startswith("http"):
                    endpoint = "/" + endpoint

                if _is_noise(endpoint, method):
                    continue
                # Absolute URLs are outbound calls — skip from inbound inventory
                if endpoint.startswith("http"):
                    continue

                if base_path and not endpoint.startswith(base_path):
                    full_endpoint = base_path.rstrip("/") + "/" + endpoint.lstrip("/")
                else:
                    full_endpoint = endpoint
                full_endpoint = re.sub(r'/+', '/', full_endpoint)

                line_no     = content[:match.start()].count("\n") + 1
                rel_path    = os.path.relpath(filepath)
                params      = _extract_path_params(full_endpoint)
                api_version = _extract_api_version(full_endpoint)
                module      = _infer_module_from_path(rel_path, full_endpoint)

                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(
                        self.store.upsert(
                            full_endpoint, method, "source_code_scan",
                            evidence={"file": rel_path, "line": line_no,
                                      "repo": repo_url, "language": lang},
                            tags=["source_code"],
                            parameters=params,
                            functional_module=module,
                            api_version=api_version,
                        )
                    )
                finally:
                    loop.close()

    def _extract_outbound_deps(self, content: str, filepath: str, repo_url: str):
        """
        Rich outbound API inventory extraction.
        Captures ALL absolute URL API calls with method, auth method, integration classification.
        Deduplication by (host + path_prefix) — distinct APIs on same server are separate entries.
        """
        from urllib.parse import urlparse
        rel_path = os.path.relpath(filepath)

        for pat in OUTBOUND_CALL_PATTERNS:
            for match in pat.finditer(content):
                groups = [g for g in match.groups() if g is not None]
                if not groups:
                    continue

                url    = None
                method = "UNKNOWN"
                for g in groups:
                    if g.upper() in HTTP_METHODS:
                        method = g.upper()
                    elif g.startswith("http"):
                        url = re.split(r'[`"\')\s]', g)[0].strip()

                if not url or len(url) < 10:
                    continue

                # Parse host and path prefix for deduplication
                parsed      = urlparse(url)
                host        = parsed.netloc or ""
                path        = parsed.path or "/"
                path_parts  = [p for p in path.split("/") if p]
                path_prefix = "/" + "/".join(path_parts[:2]) if path_parts else "/"

                if not host:
                    continue

                # Skip CDN / static noise
                if host.lower() in CDN_NOISE_HOSTS:
                    continue
                if any(n in host.lower() for n in
                       ["fonts.google", "cdnjs", "jsdelivr", "unpkg", "bootstrap.css",
                        "jquery.com", "fontawesome"]):
                    continue

                # Dedup by host + path_prefix
                dedup_key = f"{host}{path_prefix}"
                if dedup_key in self._outbound_seen:
                    # Already have this endpoint — just add source file
                    for entry in self.outbound_api_inventory:
                        if entry.get("_dedup_key") == dedup_key:
                            if rel_path not in entry["source_files"]:
                                entry["source_files"].append(rel_path)
                            break
                    continue
                self._outbound_seen.add(dedup_key)

                # Classify and enrich
                integration_name, category, exposure, risk = _classify_outbound_url(url)
                auth_method = _detect_outbound_auth(content, url, match.start())

                # Upgrade risk if hardcoded key found
                if auth_method == "hardcoded_key":
                    risk = "HIGH"

                line_no = content[:match.start()].count("\n") + 1

                entry = {
                    "url":             url[:200],
                    "host":            host,
                    "path_prefix":     path_prefix,
                    "method":          method,
                    "integration":     integration_name,
                    "category":        category,
                    "exposure":        exposure,
                    "risk":            risk,
                    "auth_method":     auth_method,
                    "owasp_reference": "API10 — Unsafe Consumption of Third-Party APIs",
                    "source_files":    [rel_path],
                    "line":            line_no,
                    "repo":            repo_url,
                    "recommendation":  _outbound_recommendation(integration_name, exposure, auth_method),
                    "_dedup_key":      dedup_key,  # internal — stripped before output in reporter
                }
                self.outbound_api_inventory.append(entry)

                # Legacy outbound_deps for backward compat
                if integration_name not in {d.get("integration") for d in self.outbound_deps}:
                    self.outbound_deps.append({
                        "integration":      integration_name,
                        "host":             host,
                        "sample_url":       url[:120],
                        "source_file":      rel_path,
                        "line":             line_no,
                        "repo":             repo_url,
                        "integration_type": category.lower().replace(" ", "_"),
                    })

                # Update tech stack integrations
                rel_lower = rel_path.lower()
                if "manageengine" in rel_lower and "ManageEngine ITSM" not in self.tech_stack["detected_integrations"]:
                    self.tech_stack["detected_integrations"].append("ManageEngine ITSM")
                if "ldap" in rel_lower and "LDAP/Active Directory" not in self.tech_stack["detected_integrations"]:
                    self.tech_stack["detected_integrations"].append("LDAP/Active Directory")
                if "threatgraph" in rel_lower and "Threat Graph API" not in self.tech_stack["detected_integrations"]:
                    self.tech_stack["detected_integrations"].append("Threat Graph API")
                if "gcp" in rel_lower and "Google Cloud Platform" not in self.tech_stack["detected_integrations"]:
                    self.tech_stack["detected_integrations"].append("Google Cloud Platform")

    def _run_semgrep(self, path: str):
        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config", "auto",
                 "--json", "--quiet", "--no-git-ignore",
                 "--max-memory", "2000", path],
                capture_output=True, text=True, timeout=300
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for finding in data.get("results", []):
                    import asyncio
                    rule_id  = finding.get("check_id", "")
                    message  = finding.get("extra", {}).get("message", "")
                    fpath    = finding.get("path", "")
                    line     = finding.get("start", {}).get("line", 0)
                    severity = finding.get("extra", {}).get("severity", "INFO")
                    if not any(kw in rule_id.lower() for kw in [
                        "route", "endpoint", "api", "auth", "sql", "xss", "inject",
                        "ssrf", "cors", "jwt", "secret", "hardcode"
                    ]):
                        continue
                    loop = asyncio.new_event_loop()
                    try:
                        loop.run_until_complete(
                            self.store.upsert(
                                fpath or "source_finding", "N/A", "semgrep",
                                tags=["security_finding", "semgrep"],
                                evidence={"rule_id": rule_id, "message": message,
                                          "file": fpath, "line": line, "severity": severity},
                            )
                        )
                    finally:
                        loop.close()
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _scan_secrets(self, path: str, repo_url: str):
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in {".png", ".jpg", ".gif", ".zip", ".pdf", ".exe",
                           ".bin", ".h5", ".pkl", ".pt", ".onnx"}:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    for pattern, secret_type in SECRET_PATTERNS:
                        for match in re.finditer(pattern, content):
                            line_no = content[:match.start()].count("\n") + 1
                            rel     = os.path.relpath(fpath)
                            preview = match.group(0)[:80] + "..."
                            finding = {
                                "type":           secret_type,
                                "file":           rel,
                                "line":           line_no,
                                "repo":           repo_url,
                                "match_preview":  preview,
                                "severity":       "CRITICAL",
                                "recommendation": self._secret_recommendation(secret_type),
                            }
                            key = f"{rel}:{line_no}:{secret_type}"
                            if not any(f"{s['file']}:{s['line']}:{s['type']}" == key
                                       for s in self.secrets_found):
                                self.secrets_found.append(finding)

                            rel_lower = rel.lower()
                            if "manageengine" in rel_lower and "ManageEngine ITSM" not in self.tech_stack["detected_integrations"]:
                                self.tech_stack["detected_integrations"].append("ManageEngine ITSM")
                            if "ldap" in rel_lower and "LDAP/Active Directory" not in self.tech_stack["detected_integrations"]:
                                self.tech_stack["detected_integrations"].append("LDAP/Active Directory")
                            if "gcp" in rel_lower and "Google Cloud Platform" not in self.tech_stack["detected_integrations"]:
                                self.tech_stack["detected_integrations"].append("Google Cloud Platform")
                            if "threatgraph" in rel_lower and "Threat Graph API" not in self.tech_stack["detected_integrations"]:
                                self.tech_stack["detected_integrations"].append("Threat Graph API")
                except Exception:
                    pass

        files_affected = len({s['file'] for s in self.secrets_found})
        outbound_count = len(self.outbound_api_inventory)
        print(f"    Secrets scan: {len(self.secrets_found)} secrets found across {files_affected} files")
        print(f"    Outbound APIs discovered: {outbound_count} unique outbound endpoints")
        print(f"    Tech stack: {self.tech_stack['framework']} / {self.tech_stack['runtime']}")

    def _secret_recommendation(self, secret_type: str) -> str:
        recs = {
            "api_key":      "Rotate API key immediately. Store in secrets manager (Vault, AWS Secrets Manager, Azure Key Vault). Never commit to source control.",
            "secret_key":   "Rotate secret key. Use environment variables or secrets manager. Add to .gitignore.",
            "password":     "Rotate password. Use environment variables. Implement credential scanning in CI/CD pipeline.",
            "token":        "Revoke token immediately. Generate new token. Use short-lived tokens with expiry.",
            "bearer_token": "Revoke bearer token. Use OAuth2/OIDC flows with token rotation. Never hardcode tokens.",
            "aws_key":      "Revoke AWS access key. Create new key with minimum required permissions. Use IAM roles where possible.",
            "private_key":  "Revoke and regenerate key pair. Never commit private keys to source control. Use secrets manager.",
        }
        return recs.get(secret_type, "Rotate credential immediately and move to secure secrets management.")