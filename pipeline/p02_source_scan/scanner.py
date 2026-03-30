import os
import re
import json
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse

_JS_TS_EXTENSIONS  = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_PYTHON_EXTENSIONS = {".py"}
_JAVA_EXTENSIONS   = {".java", ".kt"}
_DOTNET_EXTENSIONS = {".cs"}
_ALL_SOURCE_EXTS   = _JS_TS_EXTENSIONS | _PYTHON_EXTENSIONS | _JAVA_EXTENSIONS | _DOTNET_EXTENSIONS

_MANIFEST_FILES = {
    "package.json", "requirements.txt", "pom.xml", "go.mod",
    "*.csproj", "packages.config", "build.gradle", "build.gradle.kts",
    "Pipfile", "pyproject.toml", "setup.cfg",
}

_NOISE_PREFIXES     = ("../", "./node_modules/", "/node_modules/")
_MODEL_EXT_RE       = re.compile(r'\.(h5|pkl|pt|pth|onnx|pb|tflite|model|bin)$', re.I)
_VALID_PATH_RE      = re.compile(r'^[/a-zA-Z0-9_\-.:{}()*?\[\]]+$')
_MALFORMED_URL_RE   = re.compile(r'^/(https?://)')
_MIDDLEWARE_NAME_RE = re.compile(r'^/?(use|next|req|res|done|err|app|router|express)$', re.I)

_SECRET_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', re.I), "api_key"),
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', re.I), "password"),
    (re.compile(r'(?:secret|client[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9_\-+/]{16,})["\']', re.I), "secret"),
    (re.compile(r'(?:bearer|token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I), "bearer_token"),
    (re.compile(r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', re.I), "aws_access_key"),
    (re.compile(r'(?:private[_-]?key|privatekey)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=]{32,})["\']', re.I), "private_key"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', re.I), "pem_private_key"),
]

_HTTP_VERBS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

_JS_ROUTER_MOUNT_RE = re.compile(
    r'(?:app|router)\s*\.\s*use\s*\(\s*["\']([/][^"\']*)["\']',
    re.I,
)

_JS_ROUTE_RE = re.compile(
    r'(?:router|app|server)\s*\.\s*(get|post|put|delete|patch|options|head|all)\s*\('
    r'\s*["\`]([^"\'`\n]+)["\`]',
    re.I,
)

_JS_OUTBOUND_RE = re.compile(
    r'(?:axios|fetch|got|superagent|request|http|https|needle)\s*'
    r'(?:\.\s*(?:get|post|put|delete|patch|request))?\s*\(\s*["\`]?(https?://[^\s"\'`\),]+)',
    re.I,
)

_TS_NEST_CONTROLLER_RE = re.compile(
    r'@Controller\s*\(\s*["\']([^"\']*)["\']',
    re.I,
)

_TS_NEST_ROUTE_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch|Options|Head)\s*\(\s*(?:["\']([^"\']*)["\'])?\s*\)',
    re.I,
)

_TS_NEST_HTTP_CODE_RE = re.compile(
    r'@HttpCode\s*\(\s*(\d+)\s*\)',
    re.I,
)

_PY_FLASK_ROUTE_RE = re.compile(
    r'@(?:\w+\.)?route\s*\(\s*["\']([^"\']+)["\']'
    r'(?:[^)]*methods\s*=\s*\[([^\]]*)\])?',
    re.I,
)

_PY_FLASK_METHOD_DECORATOR_RE = re.compile(
    r'@(?:\w+)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)

_PY_FASTAPI_ROUTE_RE = re.compile(
    r'@(?:router|app)\.(get|post|put|delete|patch|options|head|websocket)\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)

_PY_DJANGO_URL_RE = re.compile(
    r'(?:path|re_path|url)\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)

_PY_OUTBOUND_RE = re.compile(
    r'(?:requests|httpx|aiohttp|urllib\.request|http\.client)\s*'
    r'(?:\.\s*(?:get|post|put|delete|patch|request))?\s*\(\s*["\']?(https?://[^\s"\'`,\)]+)',
    re.I,
)

_PY_OUTBOUND_VAR_RE = re.compile(
    r'(?:BASE_URL|API_URL|SERVICE_URL|ENDPOINT_URL|HOST_URL)\s*[=:]\s*["\']?(https?://[^\s"\'`,]+)',
    re.I,
)

_JAVA_SPRING_CLASS_MAPPING_RE = re.compile(
    r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\{]([^"}\)]+)["\}]',
    re.I,
)

_JAVA_SPRING_METHOD_RE = re.compile(
    r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)'
    r'\s*\(\s*(?:value\s*=\s*)?(?:["\{]([^"}\)]*)["\}])?',
    re.I,
)

_JAVA_JAXRS_CLASS_RE = re.compile(
    r'@Path\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)

_JAVA_JAXRS_METHOD_RE = re.compile(
    r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)',
)

_JAVA_JAXRS_PATH_RE = re.compile(
    r'@Path\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)

_JAVA_MICRONAUT_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch|Options|Head)\s*\(\s*(?:value\s*=\s*)?["\']([^"\']*)["\']',
    re.I,
)

_JAVA_QUARKUS_RE = _JAVA_JAXRS_METHOD_RE

_JAVA_OUTBOUND_RE = re.compile(
    r'(?:RestTemplate|WebClient|OkHttpClient|HttpClient|CloseableHttpClient|Feign)'
    r'.*?["\']?(https?://[^\s"\'`,\)]+)',
    re.I,
)

_JAVA_URL_CONST_RE = re.compile(
    r'(?:BASE_URL|API_URL|SERVICE_URL|ENDPOINT|HOST)\s*=\s*["\']?(https?://[^\s"\'`;]+)',
    re.I,
)

_DOTNET_CONTROLLER_ROUTE_RE = re.compile(
    r'\[Route\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)

_DOTNET_HTTP_METHOD_RE = re.compile(
    r'\[(Http(?:Get|Post|Put|Delete|Patch|Options|Head))\s*(?:\(\s*["\']([^"\']*)["\'])?\]',
    re.I,
)

_DOTNET_MINIMAL_API_RE = re.compile(
    r'app\s*\.\s*Map(Get|Post|Put|Delete|Patch|Options|Head)\s*\(\s*["\']([^"\']+)["\']',
    re.I,
)

_DOTNET_LEGACY_ROUTE_RE = re.compile(
    r'routes\s*\.\s*MapRoute\s*\([^)]*url\s*:\s*["\']([^"\']+)["\']',
    re.I,
)

_DOTNET_OUTBOUND_RE = re.compile(
    r'(?:HttpClient|WebClient|RestSharp|HttpWebRequest|IHttpClientFactory)'
    r'.*?["\']?(https?://[^\s"\'`,;\)]+)',
    re.I,
)

_DOTNET_URL_CONST_RE = re.compile(
    r'(?:BaseUrl|ApiUrl|ServiceUrl|EndpointUrl|HostUrl|BASE_URL|API_URL)\s*=\s*["\']?(https?://[^\s"\'`;]+)',
    re.I,
)

_DOTNET_APPSETTINGS_URL_RE = re.compile(
    r'"(?:BaseUrl|ApiUrl|ServiceUrl|EndpointUrl|Url|Host)"\s*:\s*"(https?://[^\s"]+)"',
    re.I,
)

_OUTBOUND_KNOWN_INTEGRATIONS = [
    (re.compile(r"virustotal",                      re.I), "VirusTotal",            "threat_intelligence", "External"),
    (re.compile(r"shodan",                          re.I), "Shodan",                "threat_intelligence", "External"),
    (re.compile(r"nvd\.nist\.gov|nvdapi",           re.I), "NVD / NIST",            "cve_database",        "External"),
    (re.compile(r"cve\.mitre",                      re.I), "MITRE CVE",             "cve_database",        "External"),
    (re.compile(r"pagerduty",                       re.I), "PagerDuty",             "incident_management", "External"),
    (re.compile(r"jira|atlassian",                  re.I), "Jira / Atlassian",      "issue_tracking",      "Internal"),
    (re.compile(r"servicenow",                      re.I), "ServiceNow",            "itsm",                "Internal"),
    (re.compile(r"manageengine|servicedesk",        re.I), "ManageEngine",          "itsm",                "Internal"),
    (re.compile(r"splunk",                          re.I), "Splunk",                "siem",                "Internal"),
    (re.compile(r"elastic|elasticsearch",           re.I), "Elasticsearch",         "data_store",          "Internal"),
    (re.compile(r"kafka|rabbitmq|amqp",             re.I), "Message Broker",        "async_messaging",     "Internal"),
    (re.compile(r"redis",                           re.I), "Redis",                 "cache",               "Internal"),
    (re.compile(r"ldap|activedirectory|active.dir", re.I), "LDAP / Active Dir",     "identity_provider",   "Internal"),
    (re.compile(r"okta",                            re.I), "Okta",                  "identity_provider",   "External"),
    (re.compile(r"auth0",                           re.I), "Auth0",                 "identity_provider",   "External"),
    (re.compile(r"sendgrid|mailgun|ses\.amazonaws", re.I), "Email Service",         "notification",        "External"),
    (re.compile(r"twilio|nexmo|vonage",             re.I), "SMS / Voice Service",   "notification",        "External"),
    (re.compile(r"stripe|braintree|paypal",         re.I), "Payment Gateway",       "payment",             "External"),
    (re.compile(r"s3\.amazonaws|amazonaws\.com",   re.I), "AWS S3 / API",          "cloud_storage",       "External"),
    (re.compile(r"googleapis\.com",                re.I), "Google Cloud / API",    "cloud_provider",      "External"),
    (re.compile(r"azure\.com|microsoftonline",     re.I), "Azure / Microsoft API", "cloud_provider",      "External"),
    (re.compile(r"slack\.com",                     re.I), "Slack",                 "notification",        "External"),
    (re.compile(r"github\.com|api\.github",        re.I), "GitHub",                "source_control",      "External"),
    (re.compile(r"grafana",                        re.I), "Grafana",               "monitoring",          "Internal"),
    (re.compile(r"prometheus",                     re.I), "Prometheus",            "monitoring",          "Internal"),
]

def _classify_outbound(url: str) -> Tuple[str, str, str, str]:
    for pattern, name, category, exposure in _OUTBOUND_KNOWN_INTEGRATIONS:
        if pattern.search(url):
            return name, category, exposure, "known_integration"
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    private_re = re.compile(
        r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|localhost|0\.0\.0\.0)',
    )
    if private_re.match(host):
        return host, "internal_service", "Internal", "generic"
    return host or url, "external_api", "External", "generic"

def _detect_auth_in_outbound(context_line: str) -> str:
    line = context_line.lower()
    if re.search(r'process\.env|os\.environ|getenv|config\[|settings\.|appsettings', line):
        return "env_variable"
    if re.search(r'bearer\s+["\']?[A-Za-z0-9_\-\.]{20,}', line):
        return "hardcoded_key"
    if re.search(r'api[_-]?key\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']', line):
        return "hardcoded_key"
    if re.search(r'authorization.*bearer', line):
        return "bearer_token"
    if re.search(r'authorization.*basic', line):
        return "basic_auth"
    if re.search(r'x-api-key|apikey|api_key', line):
        return "api_key_header"
    return "unknown"

def _is_noise_path(path: str) -> bool:
    if not path or len(path) < 2:
        return True
    if any(path.startswith(pfx) for pfx in _NOISE_PREFIXES):
        return True
    if _MODEL_EXT_RE.search(path):
        return True
    if _MALFORMED_URL_RE.match(path):
        return True
    if _MIDDLEWARE_NAME_RE.match(path):
        return True
    if not _VALID_PATH_RE.match(path):
        return True
    return False

def _normalize_route(path: str, base: str = "") -> str:
    if not path.startswith("/") and not path.startswith("http"):
        path = "/" + path
    if base and base != "/" and not path.startswith(base):
        path = base.rstrip("/") + "/" + path.lstrip("/")
    path = re.sub(r"/{2,}", "/", path)
    return path

def _infer_module_from_path(file_path: str, endpoint: str) -> str:
    combined = (file_path + " " + endpoint).lower()
    rules = [
        (r"auth|login|logout|session|token|oauth|sso|saml|oidc|register|signup",    "Authentication & Session"),
        (r"user|account|profile|member|people|person",                               "User Management"),
        (r"admin|manage|management|backoffice|back-office",                          "Administration"),
        (r"upload|import|ingest|intake|file|attachment|media|asset",                 "Data Upload & Ingestion"),
        (r"search|lookup|query|find|filter|discover",                                "Search & Lookup"),
        (r"report|export|download|generate|render|pdf|csv|xlsx",                     "Reporting & Export"),
        (r"notify|notification|alert|message|email|sms|webhook",                     "Notifications"),
        (r"payment|billing|invoice|order|transaction|checkout|cart|subscription",    "Payments & Commerce"),
        (r"health|ping|status|probe|liveness|readiness|metrics",                     "Health & Monitoring"),
        (r"config|setting|preference|setup|option|parameter|env",                    "Configuration"),
        (r"log|audit|event|history|activity|trace",                                  "Audit & Logging"),
        (r"device|sensor|iot|telemetry|asset|inventory|host|server",                 "Asset & Device Management"),
        (r"risk|score|rating|threat|vulnerability|vuln|cve|cve|finding",             "Risk & Vulnerability"),
        (r"integration|webhook|sync|connect|bridge|proxy|gateway|relay",             "Integration & Gateway"),
        (r"workflow|pipeline|job|task|queue|worker|schedule|cron",                   "Workflow & Jobs"),
        (r"dashboard|home|index|overview|summary|widget",                            "Dashboard"),
        (r"analytics|metric|stat|trend|chart|graph|insight",                         "Analytics"),
        (r"public|open|docs|swagger|openapi|spec",                                   "Public / Documentation"),
        (r"internal|private|debug|actuator|trace|heapdump",                          "Internal / Diagnostic"),
        (r"cloud|storage|bucket|blob|s3|gcs|azure",                                  "Cloud & Storage"),
    ]
    for pattern, module in rules:
        if re.search(pattern, combined):
            return module
    return "Uncategorized"

class SourceScanner:
    def __init__(self, store, cfg: dict):
        self.store    = store
        self.cfg      = cfg
        self.src_cfg  = cfg.get("source_scan", {})
        self.repo_dirs: List[str] = []

        repos_file = cfg.get("inputs", {}).get("repos_file", "inputs/repos.txt")
        if os.path.exists(repos_file):
            with open(repos_file) as f:
                self.repo_dirs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

        inline = self.src_cfg.get("repo_paths", [])
        if inline:
            self.repo_dirs += inline

        self._base_path_map: Dict[str, str] = {}

    async def run(self):
        if not self.repo_dirs:
            print("    No repository paths configured — skipping source scan")
            return

        for repo in self.repo_dirs:
            if not os.path.isdir(repo):
                print(f"    Repo not found: {repo}")
                continue
            print(f"    Scanning: {repo}")
            self._prescan_router_mounts(repo)
            self._scan_package_manifests(repo)
            await self._scan_source_files(repo)

        total = self.store.count().get("total", 0)
        secrets_count  = len(getattr(self.store, "secrets_found", []))
        outbound_count = len(getattr(self.store, "outbound_api_inventory", []))
        print(f"    Source scan complete: {total} endpoints, "
              f"{secrets_count} secrets, {outbound_count} outbound APIs")

    def _prescan_router_mounts(self, repo_dir: str):
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__", "dist", "build", ".venv", "venv")]
            for fname in files:
                if not any(fname.endswith(ext) for ext in _JS_TS_EXTENSIONS):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    content = self._read_file(fpath)
                except Exception:
                    continue
                for m in _JS_ROUTER_MOUNT_RE.finditer(content):
                    base = m.group(1)
                    rel  = os.path.relpath(fpath, repo_dir)
                    self._base_path_map[rel] = base

    def _scan_package_manifests(self, repo_dir: str):
        deps: List[Dict] = getattr(self.store, "package_dependencies", [])

        package_json_path = os.path.join(repo_dir, "package.json")
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                framework = "unknown"
                runtime   = "node"
                tech_stack_updates = {"runtime": runtime, "ecosystem": "npm"}

                all_deps = {}
                all_deps.update(data.get("dependencies", {}))
                all_deps.update(data.get("devDependencies", {}))

                for pkg, ver in all_deps.items():
                    ver_clean = re.sub(r'^[^0-9]*', '', str(ver))
                    deps.append({"name": pkg, "version": ver_clean, "ecosystem": "npm"})
                    if pkg in ("express", "@nestjs/core", "fastify", "koa", "hapi"):
                        framework = pkg

                tech_stack_updates["framework"] = framework
                if not hasattr(self.store, "tech_stack") or not self.store.tech_stack:
                    self.store.tech_stack = tech_stack_updates
                else:
                    self.store.tech_stack.update(tech_stack_updates)
                print(f"    package.json: {len(all_deps)} packages")
            except Exception as exc:
                print(f"    package.json parse error: {exc}")

        pom_path = os.path.join(repo_dir, "pom.xml")
        if os.path.exists(pom_path):
            try:
                content = self._read_file(pom_path)
                dep_blocks = re.findall(
                    r'<dependency>.*?</dependency>', content, re.DOTALL
                )
                for block in dep_blocks:
                    artifact = re.search(r'<artifactId>([^<]+)</artifactId>', block)
                    version  = re.search(r'<version>([^<]+)</version>', block)
                    if artifact:
                        deps.append({
                            "name":      artifact.group(1).strip(),
                            "version":   version.group(1).strip() if version else "unknown",
                            "ecosystem": "maven",
                        })
                if not hasattr(self.store, "tech_stack") or not self.store.tech_stack:
                    self.store.tech_stack = {"runtime": "jvm", "ecosystem": "maven", "framework": "unknown"}
                print(f"    pom.xml: {len(dep_blocks)} dependencies")
            except Exception as exc:
                print(f"    pom.xml parse error: {exc}")

        for gradle_name in ("build.gradle", "build.gradle.kts"):
            gradle_path = os.path.join(repo_dir, gradle_name)
            if os.path.exists(gradle_path):
                try:
                    content = self._read_file(gradle_path)
                    for m in re.finditer(
                        r'(?:implementation|compile|api|runtimeOnly)\s*["\']([^:]+):([^:]+):([^"\']+)["\']',
                        content
                    ):
                        deps.append({
                            "name":      m.group(2).strip(),
                            "version":   m.group(3).strip(),
                            "ecosystem": "gradle",
                        })
                    if not hasattr(self.store, "tech_stack") or not self.store.tech_stack:
                        self.store.tech_stack = {"runtime": "jvm", "ecosystem": "gradle", "framework": "unknown"}
                except Exception as exc:
                    print(f"    {gradle_name} parse error: {exc}")

        for req_name in ("requirements.txt", "Pipfile", "pyproject.toml", "setup.cfg"):
            req_path = os.path.join(repo_dir, req_name)
            if os.path.exists(req_path):
                try:
                    content = self._read_file(req_path)
                    if req_name == "requirements.txt":
                        for line in content.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(?:[=<>!~]+\s*([^\s,;#]+))?', line)
                            if m:
                                deps.append({
                                    "name":      m.group(1).lower(),
                                    "version":   (m.group(2) or "unknown").strip(),
                                    "ecosystem": "pypi",
                                })
                    elif req_name == "pyproject.toml":
                        for m in re.finditer(
                            r'"([A-Za-z0-9_\-\.]+)\s*(?:[=<>!~]+\s*([^"]+))?"\s*,?', content
                        ):
                            deps.append({
                                "name":      m.group(1).lower(),
                                "version":   (m.group(2) or "unknown").strip(),
                                "ecosystem": "pypi",
                            })
                    if not hasattr(self.store, "tech_stack") or not self.store.tech_stack:
                        self.store.tech_stack = {"runtime": "python", "ecosystem": "pypi", "framework": "unknown"}
                    print(f"    {req_name}: parsed")
                except Exception as exc:
                    print(f"    {req_name} parse error: {exc}")

        for csproj_root, _, csproj_files in os.walk(repo_dir):
            for fname in csproj_files:
                if fname.endswith(".csproj"):
                    csproj_path = os.path.join(csproj_root, fname)
                    try:
                        content = self._read_file(csproj_path)
                        for m in re.finditer(
                            r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
                            content, re.I
                        ):
                            deps.append({
                                "name":      m.group(1).lower(),
                                "version":   m.group(2).strip(),
                                "ecosystem": "nuget",
                            })
                        if not hasattr(self.store, "tech_stack") or not self.store.tech_stack:
                            self.store.tech_stack = {"runtime": "dotnet", "ecosystem": "nuget", "framework": "aspnetcore"}
                    except Exception as exc:
                        print(f"    {fname} parse error: {exc}")

        packages_config_path = os.path.join(repo_dir, "packages.config")
        if os.path.exists(packages_config_path):
            try:
                content = self._read_file(packages_config_path)
                for m in re.finditer(
                    r'<package\s+id="([^"]+)"\s+version="([^"]+)"',
                    content, re.I
                ):
                    deps.append({
                        "name":      m.group(1).lower(),
                        "version":   m.group(2).strip(),
                        "ecosystem": "nuget",
                    })
                if not hasattr(self.store, "tech_stack") or not self.store.tech_stack:
                    self.store.tech_stack = {"runtime": "dotnet", "ecosystem": "nuget", "framework": "aspnet_framework"}
            except Exception as exc:
                print(f"    packages.config parse error: {exc}")

        self.store.package_dependencies = deps

    async def _scan_source_files(self, repo_dir: str):
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [
                d for d in dirs
                if d not in ("node_modules", ".git", "__pycache__", "dist", "build",
                             ".venv", "venv", "bin", "obj", "target", ".idea", ".vs")
            ]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _ALL_SOURCE_EXTS:
                    if fname in ("appsettings.json", "appsettings.Development.json",
                                 "appsettings.Production.json", "application.properties",
                                 "application.yml", "application.yaml"):
                        fpath = os.path.join(root, fname)
                        try:
                            content = self._read_file(fpath)
                            self._scan_config_outbound(content, fpath)
                        except Exception:
                            pass
                    continue

                fpath = os.path.join(root, fname)
                try:
                    content = self._read_file(fpath)
                except Exception:
                    continue

                self._scan_secrets(content, fpath)

                if ext in _JS_TS_EXTENSIONS:
                    await self._scan_js_ts(content, fpath, repo_dir, ext in {".ts", ".tsx"})
                elif ext in _PYTHON_EXTENSIONS:
                    await self._scan_python(content, fpath)
                elif ext in _JAVA_EXTENSIONS:
                    await self._scan_java(content, fpath)
                elif ext in _DOTNET_EXTENSIONS:
                    await self._scan_dotnet(content, fpath)

    async def _scan_js_ts(self, content: str, fpath: str, repo_dir: str, is_typescript: bool):
        rel = os.path.relpath(fpath, repo_dir)
        base = self._base_path_map.get(rel, "")

        if is_typescript:
            await self._scan_nestjs(content, fpath, base)

        for m in _JS_ROUTE_RE.finditer(content):
            verb = m.group(1).upper()
            path = m.group(2).strip()
            if verb == "ALL":
                verb = "GET"
            path = _normalize_route(path, base)
            if _is_noise_path(path):
                continue
            path = re.sub(r":(\w+)", r"{\1}", path)
            module = _infer_module_from_path(fpath, path)
            await self.store.upsert(
                endpoint=path, method=verb, source="source_scan",
                discovered_by=["source_scan"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

        for m in _JS_OUTBOUND_RE.finditer(content):
            url = m.group(1).rstrip("'\"`,)")
            self._register_outbound(url, fpath, content, m.start())

    async def _scan_nestjs(self, content: str, fpath: str, inherited_base: str):
        controller_base = inherited_base
        cm = _TS_NEST_CONTROLLER_RE.search(content)
        if cm:
            controller_base = _normalize_route(cm.group(1), inherited_base)

        for m in _TS_NEST_ROUTE_RE.finditer(content):
            verb      = m.group(1).upper()
            sub_path  = (m.group(2) or "").strip()
            full_path = _normalize_route(sub_path, controller_base) if sub_path else controller_base
            if not full_path or _is_noise_path(full_path):
                continue
            module = _infer_module_from_path(fpath, full_path)
            await self.store.upsert(
                endpoint=full_path, method=verb, source="source_scan",
                discovered_by=["source_scan", "nestjs_decorator"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

    async def _scan_python(self, content: str, fpath: str):
        for m in _PY_FLASK_ROUTE_RE.finditer(content):
            path    = m.group(1).strip()
            methods_raw = m.group(2) or ""
            verbs   = [v.strip().strip("'\"").upper() for v in methods_raw.split(",") if v.strip()]
            if not verbs:
                verbs = ["GET"]
            path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", path)
            path = _normalize_route(path)
            if _is_noise_path(path):
                continue
            module = _infer_module_from_path(fpath, path)
            for verb in verbs:
                if verb not in _HTTP_VERBS:
                    continue
                await self.store.upsert(
                    endpoint=path, method=verb, source="source_scan",
                    discovered_by=["source_scan", "flask_route"],
                    evidence={"file": fpath, "match": m.group(0)[:120]},
                    functional_module=module,
                    first_seen=datetime.now(timezone.utc).isoformat(),
                    last_seen=datetime.now(timezone.utc).isoformat(),
                )

        for m in _PY_FLASK_METHOD_DECORATOR_RE.finditer(content):
            verb = m.group(1).upper()
            path = m.group(2).strip()
            path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", path)
            path = _normalize_route(path)
            if _is_noise_path(path):
                continue
            module = _infer_module_from_path(fpath, path)
            await self.store.upsert(
                endpoint=path, method=verb, source="source_scan",
                discovered_by=["source_scan", "flask_method_decorator"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

        for m in _PY_FASTAPI_ROUTE_RE.finditer(content):
            verb = m.group(1).upper()
            if verb == "WEBSOCKET":
                verb = "GET"
            path = m.group(2).strip()
            path = re.sub(r"\{(\w+)(?::[^}]+)?\}", r"{\1}", path)
            path = _normalize_route(path)
            if _is_noise_path(path):
                continue
            module = _infer_module_from_path(fpath, path)
            await self.store.upsert(
                endpoint=path, method=verb, source="source_scan",
                discovered_by=["source_scan", "fastapi_route"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

        for m in _PY_DJANGO_URL_RE.finditer(content):
            path = m.group(1).strip()
            if path.startswith("^"):
                path = path.lstrip("^").rstrip("$")
            path = re.sub(r"\(\?P<(\w+)>[^)]+\)", r"{\1}", path)
            path = re.sub(r"\(\?:([^)]+)\)", "", path)
            path = _normalize_route("/" + path.lstrip("/"))
            if _is_noise_path(path):
                continue
            module = _infer_module_from_path(fpath, path)
            await self.store.upsert(
                endpoint=path, method="UNKNOWN", source="source_scan",
                discovered_by=["source_scan", "django_url"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

        for m in _PY_OUTBOUND_RE.finditer(content):
            url = m.group(1).rstrip("'\"`,)")
            self._register_outbound(url, fpath, content, m.start())

        for m in _PY_OUTBOUND_VAR_RE.finditer(content):
            url = m.group(1).rstrip("'\"`,)")
            self._register_outbound(url, fpath, content, m.start())

    async def _scan_java(self, content: str, fpath: str):
        class_base = ""
        cm = _JAVA_SPRING_CLASS_MAPPING_RE.search(content)
        if cm:
            class_base = cm.group(1).strip()

        jaxrs_class_base = ""
        jcm_matches = list(_JAVA_JAXRS_CLASS_RE.finditer(content))

        lines = content.splitlines()
        i     = 0
        while i < len(lines):
            line = lines[i]

            sm = _JAVA_SPRING_METHOD_RE.search(line)
            if sm:
                annotation = sm.group(1).upper()
                sub_path   = (sm.group(2) or "").strip()
                verb_map   = {
                    "GETMAPPING":    "GET",
                    "POSTMAPPING":   "POST",
                    "PUTMAPPING":    "PUT",
                    "DELETEMAPPING": "DELETE",
                    "PATCHMAPPING":  "PATCH",
                    "REQUESTMAPPING": "UNKNOWN",
                }
                verb = verb_map.get(annotation, "UNKNOWN")

                if annotation == "REQUESTMAPPING" and not sub_path:
                    jaxrs_class_base = ""
                    cm2 = re.search(r'method\s*=\s*RequestMethod\.(\w+)', line)
                    if cm2:
                        verb = cm2.group(1).upper()

                full = _normalize_route(sub_path, class_base) if sub_path else ("/" + class_base.strip("/")) or "/"
                if not _is_noise_path(full):
                    module = _infer_module_from_path(fpath, full)
                    await self.store.upsert(
                        endpoint=full, method=verb, source="source_scan",
                        discovered_by=["source_scan", "spring_annotation"],
                        evidence={"file": fpath, "match": line.strip()[:120]},
                        functional_module=module,
                        first_seen=datetime.now(timezone.utc).isoformat(),
                        last_seen=datetime.now(timezone.utc).isoformat(),
                    )
                i += 1
                continue

            mm = _JAVA_MICRONAUT_RE.search(line)
            if mm:
                verb     = mm.group(1).upper()
                sub_path = (mm.group(2) or "").strip()
                full     = _normalize_route(sub_path, class_base)
                if not _is_noise_path(full):
                    module = _infer_module_from_path(fpath, full)
                    await self.store.upsert(
                        endpoint=full, method=verb, source="source_scan",
                        discovered_by=["source_scan", "micronaut_annotation"],
                        evidence={"file": fpath, "match": line.strip()[:120]},
                        functional_module=module,
                        first_seen=datetime.now(timezone.utc).isoformat(),
                        last_seen=datetime.now(timezone.utc).isoformat(),
                    )
                i += 1
                continue

            i += 1

        jaxrs_pairs = self._extract_jaxrs_routes(content, fpath)
        for verb, full in jaxrs_pairs:
            if not _is_noise_path(full):
                module = _infer_module_from_path(fpath, full)
                await self.store.upsert(
                    endpoint=full, method=verb, source="source_scan",
                    discovered_by=["source_scan", "jaxrs_annotation"],
                    evidence={"file": fpath, "match": full[:120]},
                    functional_module=module,
                    first_seen=datetime.now(timezone.utc).isoformat(),
                    last_seen=datetime.now(timezone.utc).isoformat(),
                )

        for m in _JAVA_OUTBOUND_RE.finditer(content):
            url = m.group(1).rstrip("'\"`;)")
            self._register_outbound(url, fpath, content, m.start())

        for m in _JAVA_URL_CONST_RE.finditer(content):
            url = m.group(1).rstrip("'\"`;)")
            self._register_outbound(url, fpath, content, m.start())

    def _extract_jaxrs_routes(self, content: str, fpath: str) -> List[Tuple[str, str]]:
        results = []
        class_path = ""
        cm = _JAVA_JAXRS_CLASS_RE.search(content)
        if cm:
            class_path = cm.group(1).strip()

        method_blocks = re.split(r'\n\s*(?=@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Path))', content)
        for block in method_blocks:
            verb_m = _JAVA_JAXRS_METHOD_RE.search(block)
            if not verb_m:
                continue
            verb = verb_m.group(1).upper()
            path_m = _JAVA_JAXRS_PATH_RE.search(block)
            sub_path = path_m.group(1).strip() if path_m else ""
            full = _normalize_route(sub_path, class_path) if sub_path else ("/" + class_path.lstrip("/"))
            full = re.sub(r"\{(\w+)(?::[^}]+)?\}", r"{\1}", full)
            results.append((verb, full))
        return results

    async def _scan_dotnet(self, content: str, fpath: str):
        controller_route = ""
        cr = _DOTNET_CONTROLLER_ROUTE_RE.search(content)
        if cr:
            raw = cr.group(1).strip()
            raw = re.sub(r"\[controller\]", self._infer_controller_name(fpath), raw, flags=re.I)
            raw = re.sub(r"\[action\]", "", raw, flags=re.I)
            controller_route = raw

        for m in _DOTNET_HTTP_METHOD_RE.finditer(content):
            annotation = m.group(1).lower()
            verb_map = {
                "httpget": "GET", "httppost": "POST", "httpput": "PUT",
                "httpdelete": "DELETE", "httppatch": "PATCH",
                "httpoptions": "OPTIONS", "httphead": "HEAD",
            }
            verb     = verb_map.get(annotation, "UNKNOWN")
            sub_path = (m.group(2) or "").strip()
            sub_path = re.sub(r"\[action\]", "", sub_path, flags=re.I)

            if sub_path:
                full = _normalize_route(sub_path, controller_route)
            elif controller_route:
                full = "/" + controller_route.lstrip("/")
            else:
                full = "/"

            full = re.sub(r"\{(\w+)(?::[^}]+)?\}", r"{\1}", full)
            if _is_noise_path(full):
                continue
            module = _infer_module_from_path(fpath, full)
            await self.store.upsert(
                endpoint=full, method=verb, source="source_scan",
                discovered_by=["source_scan", "aspnetcore_attribute"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

        for m in _DOTNET_MINIMAL_API_RE.finditer(content):
            verb = m.group(1).upper()
            path = m.group(2).strip()
            path = re.sub(r"\{(\w+)(?::[^}]+)?\}", r"{\1}", path)
            path = _normalize_route(path)
            if _is_noise_path(path):
                continue
            module = _infer_module_from_path(fpath, path)
            await self.store.upsert(
                endpoint=path, method=verb, source="source_scan",
                discovered_by=["source_scan", "aspnet_minimal_api"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

        for m in _DOTNET_LEGACY_ROUTE_RE.finditer(content):
            raw = m.group(1).strip()
            raw = re.sub(r"\{(\w+)(?::[^}]*)?\}", r"{\1}", raw)
            path = _normalize_route("/" + raw.lstrip("/"))
            if _is_noise_path(path):
                continue
            module = _infer_module_from_path(fpath, path)
            await self.store.upsert(
                endpoint=path, method="UNKNOWN", source="source_scan",
                discovered_by=["source_scan", "aspnet_legacy_route"],
                evidence={"file": fpath, "match": m.group(0)[:120]},
                functional_module=module,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

        for m in _DOTNET_OUTBOUND_RE.finditer(content):
            url = m.group(1).rstrip("'\"`;)")
            self._register_outbound(url, fpath, content, m.start())

        for m in _DOTNET_URL_CONST_RE.finditer(content):
            url = m.group(1).rstrip("'\"`;)")
            self._register_outbound(url, fpath, content, m.start())

    def _scan_config_outbound(self, content: str, fpath: str):
        for m in _DOTNET_APPSETTINGS_URL_RE.finditer(content):
            url = m.group(1).rstrip('"')
            self._register_outbound(url, fpath, content, m.start())

        for m in re.finditer(r'(?:base[_-]?url|api[_-]?url|service[_-]?url|endpoint):\s*["\']?(https?://[^\s"\']+)', content, re.I):
            url = m.group(1).rstrip("'\"")
            self._register_outbound(url, fpath, content, m.start())

    def _scan_secrets(self, content: str, fpath: str):
        secrets: List[Dict] = getattr(self.store, "secrets_found", [])
        for pattern, secret_type in _SECRET_PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[:m.start()].count("\n") + 1
                value   = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                preview = value[:6] + "..." + value[-4:] if len(value) > 10 else "***"
                secrets.append({
                    "type":             secret_type,
                    "file":             fpath,
                    "line":             line_no,
                    "match_preview":    preview,
                    "severity":         "CRITICAL",
                    "recommendation":   "Remove from source. Rotate credential. Use secrets manager (Vault, AWS Secrets Manager, Azure Key Vault).",
                })
        self.store.secrets_found = secrets

    def _register_outbound(self, url: str, fpath: str, content: str, pos: int):
        url = url.strip().rstrip("/")
        if not url.startswith("http"):
            return
        if len(url) > 300:
            return
        if re.search(r'localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|test\.com|placeholder', url, re.I):
            return

        try:
            parsed   = urlparse(url)
            host     = parsed.hostname or ""
            path_pfx = "/" + parsed.path.lstrip("/").split("/")[0] if parsed.path and parsed.path != "/" else "/"
        except Exception:
            host     = url
            path_pfx = "/"

        dedup_key = host + path_pfx
        inventory: List[Dict] = getattr(self.store, "outbound_api_inventory", [])
        existing_keys = {(e.get("_host", "") + e.get("_path_prefix", "")) for e in inventory}
        if dedup_key in existing_keys:
            for entry in inventory:
                if entry.get("_host", "") + entry.get("_path_prefix", "") == dedup_key:
                    if fpath not in entry.get("source_files", []):
                        entry.setdefault("source_files", []).append(fpath)
            self.store.outbound_api_inventory = inventory
            return

        context_line = content[max(0, pos - 80):pos + 200].replace("\n", " ")
        auth_method  = _detect_auth_in_outbound(context_line)

        method = "UNKNOWN"
        verb_m = re.search(r'\.(get|post|put|delete|patch)\s*\(', context_line, re.I)
        if verb_m:
            method = verb_m.group(1).upper()

        integration, category, exposure, source_type = _classify_outbound(url)

        risk = "HIGH" if exposure == "External" else "MEDIUM"
        if auth_method == "hardcoded_key":
            risk = "CRITICAL"

        entry = {
            "url":          url,
            "host":         host,
            "integration":  integration,
            "category":     category,
            "exposure":     exposure,
            "method":       method,
            "auth_method":  auth_method,
            "risk":         risk,
            "source_files": [fpath],
            "source_type":  source_type,
            "_host":        host,
            "_path_prefix": path_pfx,
        }
        inventory.append(entry)
        self.store.outbound_api_inventory = inventory

    @staticmethod
    def _infer_controller_name(fpath: str) -> str:
        fname = os.path.basename(fpath)
        name  = re.sub(r'Controller\.cs$', '', fname, flags=re.I).lower()
        return name if name else "api"

    @staticmethod
    def _read_file(fpath: str) -> str:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            return f.read()