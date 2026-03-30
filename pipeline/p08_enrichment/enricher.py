import re
from typing import Dict, List, Optional, Tuple


AUTH_INDICATORS = {
    "Bearer JWT":       [r"authorization.*bearer", r"jwt", r"/token", r"/oauth", r"/auth"],
    "API Key":          [r"x-api-key", r"api[-_]?key", r"apikey"],
    "Basic Auth":       [r"authorization.*basic", r"/basic-auth"],
    "OAuth2":           [r"oauth2", r"oauth/token", r"authorization_code", r"client_credentials"],
    "OIDC":             [r"openid", r"id_token", r"/.well-known/openid"],
    "SAML":             [r"saml", r"sso"],
    "mTLS":             [r"client[-_]?cert", r"mtls", r"mutual[-_]?tls"],
    "No Auth Required": [r"/health", r"/ping", r"/status", r"/metrics", r"/public/"],
}


SENSITIVITY_RULES = {
    "CRITICAL": [
        "password", "passwd", "secret", "private_key", "private-key",
        "ssn", "social-security", "social_security", "credit-card", "credit_card",
        "cc-num", "cvv", "cvc",
        "bearer", "access_token", "refresh_token", "client_secret",
        "bank-account", "bank_account", "routing-number", "routing_number", "iban", "swift",
        "biometric", "fingerprint",
        "national-id", "national_id", "passport", "drivers-license",
        "private_key", "pem", "rsa",
        "encryption_key", "signing_key",
    ],
    "HIGH": [
        "email", "phone", "mobile", "address", "dob", "birth", "birthdate",
        "user_id", "account_id", "payment", "transaction",
        "license", "voter",
        "salary", "income", "tax",
        "credit-score", "credit_score",
        "ip-address", "ip_address", "ipaddress",
        "user", "register", "login", "logout",
        "pii", "gdpr", "hipaa",
    ],
    "MEDIUM": [
        "profile", "preferences", "settings", "config",
        "session", "cart", "order", "report",
        "analytics", "log", "audit",
        "upload", "generate", "scan", "result",
        "vulnerability", "cve", "cvss",
        "malware", "threat", "indicator",
        "export", "download",
    ],
}


FUNCTIONAL_TYPE_RULES = [
    ("auth", [
        r"/login", r"/logout", r"/register", r"/signup", r"/sign-in", r"/sign-up",
        r"/verify", r"/confirm", r"/activate",
        r"/auth", r"/token", r"/oauth", r"/sso", r"/saml", r"/oidc",
        r"/password", r"/reset-password", r"/forgot-password", r"/change-password",
        r"/2fa", r"/mfa", r"/otp",
        r"/refresh", r"/revoke",
    ]),
    ("admin", [
        r"/admin", r"/administration", r"/backoffice", r"/back-office",
        r"/management", r"/manage",
        r"/actuator", r"/debug", r"/trace", r"/heapdump",
        r"/superuser", r"/root", r"/sudo",
        r"/permission", r"/permissions", r"/role", r"/roles",
        r"/grant", r"/revoke", r"/policy", r"/policies",
        r"/directive", r"/rule", r"/rules",
    ]),
    ("upload", [
        r"/upload", r"/uploads",
        r"/import", r"/ingest", r"/intake",
        r"/file", r"/files", r"/attachment", r"/attachments",
        r"/media", r"/asset", r"/assets",
        r"/document", r"/documents",
    ]),
    ("search", [
        r"/search", r"/find", r"/lookup", r"/query",
        r"/filter", r"/autocomplete", r"/suggest",
        r"/browse", r"/discover",
    ]),
    ("reporting", [
        r"/report", r"/reports",
        r"/export", r"/generate",
        r"/download",
        r"/summary", r"/overview",
        r"/dashboard",
    ]),
    ("data_read", [
        r"list$", r"details$", r"count$", r"data$", r"info$",
        r"all$", r"get$", r"fetch$",
        r"score$", r"scores$",
    ]),
    ("health", [
        r"/health", r"/healthz", r"/liveness", r"/readiness",
        r"/ping", r"/status", r"/probes", r"/alive",
        r"/metrics", r"/info",
    ]),
    ("notification", [
        r"/notify", r"/notification", r"/notifications",
        r"/alert", r"/alerts",
        r"/email", r"/sms", r"/push",
        r"/message", r"/messages",
        r"/webhook", r"/webhooks",
        r"/subscribe", r"/unsubscribe",
    ]),
    ("integration", [
        r"/integration", r"/integrations",
        r"/webhook", r"/webhooks",
        r"/sync", r"/connect",
        r"/callback", r"/relay",
        r"/bridge", r"/proxy",
    ]),
]


INTERNAL_INDICATORS = [
    r"^/internal/", r"^/private/", r"^/_",
    r"192\.168\.", r"10\.\d+\.", r"172\.(1[6-9]|2\d|3[01])\.",
    r"localhost", r"\.local/", r"\.internal/",
    r"/admin/", r"/management/", r"/actuator",
]


MODULE_OWNER_MAP = {
    "Authentication & Session":   "Identity & Access Management Team",
    "User Management":            "Application Development Team",
    "Administration":             "Platform / DevOps Team",
    "Data Upload & Ingestion":    "Data Engineering Team",
    "Search & Lookup":            "Application Development Team",
    "Reporting & Export":         "Business Intelligence Team",
    "Notifications":              "Application Development Team",
    "Payments & Commerce":        "Payments & Finance Team",
    "Health & Monitoring":        "Platform / DevOps Team",
    "Configuration":              "Platform / DevOps Team",
    "Audit & Logging":            "Security Operations Team",
    "Asset & Device Management":  "IT Operations Team",
    "Risk & Vulnerability":       "Security Operations Team",
    "Integration & Gateway":      "Integration / API Team",
    "Workflow & Jobs":            "Application Development Team",
    "Dashboard":                  "Application Development Team",
    "Analytics":                  "Data Engineering Team",
    "Public / Documentation":     "API Governance Team",
    "Internal / Diagnostic":      "Platform / DevOps Team",
    "Cloud & Storage":            "Platform / Infrastructure Team",
    "Uncategorized":              "Pending Triage - Application Owner",
}


TECH_CVE_MAP = {
    re.compile(r"spring", re.I): [
        {"cve": "CVE-2022-22965", "desc": "Spring4Shell RCE", "cvss": 9.8},
        {"cve": "CVE-2022-22963", "desc": "Spring Cloud Function RCE", "cvss": 9.8},
    ],
    re.compile(r"log4j|log4", re.I): [
        {"cve": "CVE-2021-44228", "desc": "Log4Shell RCE", "cvss": 10.0},
    ],
    re.compile(r"struts", re.I): [
        {"cve": "CVE-2017-5638", "desc": "Apache Struts RCE", "cvss": 10.0},
    ],
    re.compile(r"express", re.I): [
        {"cve": "CVE-2024-29041", "desc": "Express.js open redirect via malformed URL", "cvss": 6.1},
    ],
}


PACKAGE_CVE_DATABASE: Dict[str, List[Dict]] = {
    "express": [
        {
            "cve":            "CVE-2024-29041",
            "desc":           "Express.js open redirect via malformed URL host header",
            "cvss":           6.1,
            "affected_below": (4, 19, 2),
            "ecosystem":      "npm",
        },
    ],
    "axios": [
        {
            "cve":            "CVE-2023-45857",
            "desc":           "Axios CSRF vulnerability via sensitive headers leaked in cross-origin redirects",
            "cvss":           8.8,
            "affected_below": (1, 6, 0),
            "ecosystem":      "npm",
        },
    ],
    "jsonwebtoken": [
        {
            "cve":            "CVE-2022-23529",
            "desc":           "jsonwebtoken arbitrary file write via malicious JWK",
            "cvss":           7.6,
            "affected_below": (9, 0, 0),
            "ecosystem":      "npm",
        },
        {
            "cve":            "CVE-2022-23540",
            "desc":           "jsonwebtoken algorithm confusion via blank password",
            "cvss":           6.4,
            "affected_below": (9, 0, 0),
            "ecosystem":      "npm",
        },
    ],
    "multer": [
        {
            "cve":            "CVE-2022-24434",
            "desc":           "Multer ReDoS via crafted Content-Disposition header",
            "cvss":           5.3,
            "affected_below": (1, 4, 4),
            "ecosystem":      "npm",
        },
    ],
    "lodash": [
        {
            "cve":            "CVE-2021-23337",
            "desc":           "Lodash command injection via template function",
            "cvss":           7.2,
            "affected_below": (4, 17, 21),
            "ecosystem":      "npm",
        },
        {
            "cve":            "CVE-2020-8203",
            "desc":           "Lodash prototype pollution via zipObjectDeep",
            "cvss":           7.4,
            "affected_below": (4, 17, 19),
            "ecosystem":      "npm",
        },
    ],
    "moment": [
        {
            "cve":            "CVE-2022-24785",
            "desc":           "Moment.js path traversal via locale loading",
            "cvss":           7.5,
            "affected_below": (2, 29, 2),
            "ecosystem":      "npm",
        },
    ],
    "mongoose": [
        {
            "cve":            "CVE-2019-17426",
            "desc":           "Mongoose prototype pollution via query",
            "cvss":           9.1,
            "affected_below": (5, 7, 5),
            "ecosystem":      "npm",
        },
    ],
    "sequelize": [
        {
            "cve":            "CVE-2023-22578",
            "desc":           "Sequelize SQL injection via model attributes",
            "cvss":           9.8,
            "affected_below": (6, 28, 1),
            "ecosystem":      "npm",
        },
    ],
    "node-fetch": [
        {
            "cve":            "CVE-2022-0235",
            "desc":           "node-fetch forwards sensitive headers to redirect location",
            "cvss":           6.1,
            "affected_below": (2, 6, 7),
            "ecosystem":      "npm",
        },
    ],
    "sharp": [
        {
            "cve":            "CVE-2023-25166",
            "desc":           "Sharp heap buffer overflow via crafted image",
            "cvss":           7.5,
            "affected_below": (0, 31, 3),
            "ecosystem":      "npm",
        },
    ],
    "ws": [
        {
            "cve":            "CVE-2024-37890",
            "desc":           "ws DoS via headers with multiple HTTP/1.1 upgrade requests",
            "cvss":           7.5,
            "affected_below": (8, 17, 1),
            "ecosystem":      "npm",
        },
    ],
    "@nestjs/core": [
        {
            "cve":            "CVE-2023-26108",
            "desc":           "NestJS ReDoS via overly permissive path matching",
            "cvss":           5.3,
            "affected_below": (9, 2, 1),
            "ecosystem":      "npm",
        },
    ],
    "flask": [
        {
            "cve":            "CVE-2023-30861",
            "desc":           "Flask cookie session bypass via browser cache",
            "cvss":           7.5,
            "affected_below": (2, 3, 2),
            "ecosystem":      "pypi",
        },
    ],
    "django": [
        {
            "cve":            "CVE-2023-41164",
            "desc":           "Django potential denial of service via very long email",
            "cvss":           7.5,
            "affected_below": (4, 2, 6),
            "ecosystem":      "pypi",
        },
    ],
    "fastapi": [
        {
            "cve":            "CVE-2024-24762",
            "desc":           "FastAPI ReDoS via multipart content-type header",
            "cvss":           7.5,
            "affected_below": (0, 109, 1),
            "ecosystem":      "pypi",
        },
    ],
    "requests": [
        {
            "cve":            "CVE-2023-32681",
            "desc":           "Requests forwards proxy-authorization header to destination",
            "cvss":           6.1,
            "affected_below": (2, 31, 0),
            "ecosystem":      "pypi",
        },
    ],
    "pillow": [
        {
            "cve":            "CVE-2023-44271",
            "desc":           "Pillow uncontrolled resource consumption via crafted image",
            "cvss":           7.5,
            "affected_below": (10, 0, 1),
            "ecosystem":      "pypi",
        },
    ],
    "aiohttp": [
        {
            "cve":            "CVE-2024-23334",
            "desc":           "aiohttp path traversal via static file serving",
            "cvss":           7.5,
            "affected_below": (3, 9, 2),
            "ecosystem":      "pypi",
        },
    ],
    "spring-core": [
        {
            "cve":            "CVE-2022-22965",
            "desc":           "Spring4Shell RCE via data binding",
            "cvss":           9.8,
            "affected_below": (5, 3, 18),
            "ecosystem":      "maven",
        },
    ],
    "log4j-core": [
        {
            "cve":            "CVE-2021-44228",
            "desc":           "Log4Shell JNDI injection RCE",
            "cvss":           10.0,
            "affected_below": (2, 15, 0),
            "ecosystem":      "maven",
        },
    ],
    "spring-security-core": [
        {
            "cve":            "CVE-2024-22243",
            "desc":           "Spring Security open redirect via UriComponentsBuilder",
            "cvss":           8.1,
            "affected_below": (6, 2, 2),
            "ecosystem":      "maven",
        },
    ],
    "microsoft.aspnetcore.app": [
        {
            "cve":            "CVE-2024-21319",
            "desc":           "ASP.NET Core denial of service via malformed JWT",
            "cvss":           6.5,
            "affected_below": (8, 0, 1),
            "ecosystem":      "nuget",
        },
    ],
    "newtonsoft.json": [
        {
            "cve":            "CVE-2024-21907",
            "desc":           "Newtonsoft.Json ReDoS via crafted JSON string",
            "cvss":           7.5,
            "affected_below": (13, 0, 2),
            "ecosystem":      "nuget",
        },
    ],
}


RISK_WEIGHTS = {
    "classification":        {"Rogue": 40, "Shadow": 25, "New": 10, "Valid": 0, "UNCLASSIFIED": 15},
    "data_sensitivity":      {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 0},
    "exposure":              {"external": 20, "partner": 10, "internal": 5, "unknown": 8},
    "owasp_severity":        {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2},
    "cve":                   10,
    "no_auth":               15,
    "missing_tls":           10,
    "functional_type_bonus": {"auth": 10, "admin": 15, "upload": 5},
}


INVENTORY_NOISE_TAGS = {"secret_scan", "secret"}
MODEL_PATH_PATTERN   = re.compile(r'\.(h5|pkl|pt|pth|onnx|pb|tflite)$', re.I)
FILE_PATH_PATTERN    = re.compile(r'^\.\.[/\\]|^[a-zA-Z]:[/\\]')


def _parse_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    if not version_str or version_str in ("unknown", "*", "latest", ""):
        return None
    clean = re.sub(r'^[^0-9]*', '', str(version_str))
    clean = re.split(r'[-+]', clean)[0]
    parts = clean.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return None


def _version_is_affected(installed: Tuple[int, int, int],
                          affected_below: Tuple[int, int, int]) -> bool:
    return installed < affected_below


class Enricher:
    def __init__(self, store, cfg: dict):
        self.store       = store
        self.cfg         = cfg
        self._tech_stack = getattr(store, "tech_stack", {})

        self._package_deps: List[Dict] = getattr(store, "package_dependencies", [])

        self._pkg_version_map: Dict[str, Optional[Tuple[int, int, int]]] = {}
        for dep in self._package_deps:
            name = dep.get("name", "").lower()
            ver  = _parse_version(dep.get("version", ""))
            self._pkg_version_map[name] = ver

    async def run(self):
        all_entries = self.store.all()

        api_entries   = []
        noise_entries = []
        for entry in all_entries:
            if self._is_inventory_noise(entry):
                noise_entries.append(entry)
            else:
                api_entries.append(entry)

        print(f"    Enriching {len(api_entries)} API endpoints "
              f"(filtered {len(noise_entries)} non-API entries)")

        if self._package_deps:
            print(f"    CVE check: {len(self._pkg_version_map)} packages loaded for version-aware matching")
        else:
            print("    CVE check: No package manifests found — falling back to framework-level CVE matching")

        for entry in api_entries:
            if entry.auth_type in ("UNKNOWN", None):
                entry.auth_type = self._detect_auth(entry)

            if entry.data_sensitivity in ("LOW", None):
                entry.data_sensitivity = self._detect_sensitivity(entry)

            if entry.exposure in ("unknown", None):
                entry.exposure = self._detect_exposure(entry)

            if entry.environment in ("unknown", None):
                entry.environment = self._detect_environment(entry)

            if entry.functional_type in ("unknown", None):
                entry.functional_type = self._detect_functional_type(entry)

            if entry.functional_module in ("Uncategorized", None, ""):
                from pipeline.p02_source_scan.scanner import _infer_module_from_path
                file_path = entry.evidence.get("file", "")
                entry.functional_module = _infer_module_from_path(file_path, entry.endpoint)

            entry.inferred_owner = MODULE_OWNER_MAP.get(
                entry.functional_module,
                "Pending Triage - Application Owner"
            )

            if not entry.cve_findings:
                entry.cve_findings = self._check_cve(entry)

            if self._tech_stack:
                fw      = self._tech_stack.get("framework", "")
                runtime = self._tech_stack.get("runtime", "")
                if fw and fw != "unknown":
                    entry.tech_stack = f"{fw.capitalize()} / {runtime}"

            integrations = self._tech_stack.get("detected_integrations", [])
            if integrations and not entry.downstream_dependencies:
                entry.downstream_dependencies = integrations[:3]

            entry.owasp_flags = self._enrich_owasp_flags(entry)
            entry.risk_score  = self._score(entry)

        for entry in noise_entries:
            entry.tags           = list(set(entry.tags + ["_noise_filtered"]))
            entry.classification = "FILTERED"

        critical   = sum(1 for e in api_entries if e.data_sensitivity == "CRITICAL")
        high_owasp = sum(1 for e in api_entries if any(
            f.get("severity") in ("CRITICAL", "HIGH") for f in e.owasp_flags
        ))
        cve_total  = sum(len(e.cve_findings) for e in api_entries)
        print(f"    Enrichment complete: {critical} CRITICAL sensitivity, "
              f"{high_owasp} endpoints with HIGH/CRITICAL OWASP flags, "
              f"{cve_total} CVE findings")

    def _is_inventory_noise(self, entry) -> bool:
        if "secret_scan" in entry.discovered_by:
            return True
        if entry.method == "N/A":
            return True
        if any(tag in INVENTORY_NOISE_TAGS for tag in entry.tags):
            return True
        if FILE_PATH_PATTERN.match(entry.endpoint):
            return True
        if MODEL_PATH_PATTERN.search(entry.endpoint):
            return True
        if entry.endpoint.startswith("/https://") or entry.endpoint.startswith("/http://"):
            return True
        return False

    def _detect_auth(self, entry) -> str:
        text = (entry.endpoint + " " + str(entry.evidence) + " " +
                str(entry.headers_observed)).lower()
        for auth_type, patterns in AUTH_INDICATORS.items():
            for pat in patterns:
                if re.search(pat, text, re.I):
                    return auth_type
        if entry.status_code == 401:
            return "Required (type unknown)"
        if entry.functional_module in ("Authentication & Session",):
            return "Session Token"
        return "None detected"

    def _detect_sensitivity(self, entry) -> str:
        text      = entry.endpoint.lower()
        file_text = entry.evidence.get("file", "").lower()
        combined  = text + " " + file_text
        for level in ("CRITICAL", "HIGH", "MEDIUM"):
            for kw in SENSITIVITY_RULES[level]:
                if kw in combined:
                    return level
        return "LOW"

    def _detect_exposure(self, entry) -> str:
        ep = entry.endpoint.lower()
        for pat in INTERNAL_INDICATORS:
            if re.search(pat, ep):
                return "internal"
        if "partner" in ep or "b2b" in ep or "external" in ep:
            return "partner"
        if ep.startswith("http") and not any(
            ep.startswith(f"http://{p}") or ep.startswith(f"https://{p}")
            for p in ["10.", "192.168.", "172.", "localhost", "127."]
        ):
            return "external"
        return "internal"

    def _detect_environment(self, entry) -> str:
        text = entry.endpoint.lower() + " " + str(entry.tags)
        if any(kw in text for kw in ["prod", "production", "live"]):
            return "production"
        if any(kw in text for kw in ["staging", "stage", "stg"]):
            return "staging"
        if any(kw in text for kw in ["dev", "development", "local"]):
            return "development"
        if any(kw in text for kw in ["uat", "qa", "test"]):
            return "uat"
        ep = entry.endpoint
        if any(ep.startswith(f"http://{p}") for p in ["10.", "192.168.", "172."]):
            return "internal_non_prod"
        return "unknown"

    def _detect_functional_type(self, entry) -> str:
        ep     = entry.endpoint.lower()
        method = entry.method.upper()
        for ftype, patterns in FUNCTIONAL_TYPE_RULES:
            if ftype == "data_write":
                if method in ("POST", "PUT", "DELETE", "PATCH"):
                    return "data_write"
                continue
            for pat in patterns:
                if re.search(pat, ep):
                    return ftype
        if method == "GET":
            return "data_read"
        elif method in ("POST", "PUT", "PATCH"):
            return "data_write"
        elif method == "DELETE":
            return "data_delete"
        return "unknown"

    def _check_cve(self, entry) -> List[Dict]:
        findings   = []
        found_cves: set = set()

        evidence_text = str(entry.evidence).lower()
        headers_text  = str(entry.headers_observed).lower()
        combined      = evidence_text + " " + headers_text + " " + entry.endpoint.lower()

        if entry.tech_stack:
            combined += " " + entry.tech_stack.lower()

        for pkg_name, cve_list in PACKAGE_CVE_DATABASE.items():
            pkg_lower    = pkg_name.lower()
            installed_ver = self._pkg_version_map.get(pkg_lower)

            if installed_ver is None:
                continue

            for cve_entry in cve_list:
                cve_id         = cve_entry["cve"]
                affected_below = cve_entry.get("affected_below")

                if cve_id in found_cves:
                    continue

                if affected_below and _version_is_affected(installed_ver, affected_below):
                    findings.append({
                        "cve":               cve_id,
                        "desc":              cve_entry["desc"],
                        "cvss":              cve_entry["cvss"],
                        "package":           pkg_name,
                        "installed_version": ".".join(str(x) for x in installed_ver),
                        "fixed_in":          ".".join(str(x) for x in affected_below),
                        "source":            "package_manifest",
                    })
                    found_cves.add(cve_id)
                elif not affected_below:
                    findings.append({
                        "cve":               cve_id,
                        "desc":              cve_entry["desc"],
                        "cvss":              cve_entry["cvss"],
                        "package":           pkg_name,
                        "installed_version": ".".join(str(x) for x in installed_ver),
                        "fixed_in":          "unknown",
                        "source":            "package_manifest_no_version_boundary",
                    })
                    found_cves.add(cve_id)

        if not self._pkg_version_map:
            for pattern, cves in TECH_CVE_MAP.items():
                if pattern.search(combined):
                    for cve_entry in cves:
                        cve_id = cve_entry["cve"]
                        if cve_id not in found_cves:
                            findings.append({
                                **cve_entry,
                                "source": "framework_pattern_match",
                                "note":   "Version not confirmed — package manifest not available",
                            })
                            found_cves.add(cve_id)

        return findings

    def _enrich_owasp_flags(self, entry) -> List[Dict]:
        flags = list(entry.owasp_flags)
        ep    = entry.endpoint.lower()
        method = entry.method.upper()

        if entry.auth_type in ("None detected", "UNKNOWN") and entry.functional_type not in ("health",):
            if not any(f.get("category") == "API2" for f in flags):
                flags.append({
                    "category": "API2",
                    "name":     "Broken Authentication",
                    "finding":  "No authentication mechanism detected on this endpoint. "
                                "Verify authentication middleware is enforced.",
                    "severity": "HIGH" if entry.data_sensitivity in ("CRITICAL", "HIGH") else "MEDIUM",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        if entry.endpoint.startswith("http://"):
            if not any(f.get("category") == "API8" and "TLS" in f.get("finding", "") for f in flags):
                flags.append({
                    "category": "API8",
                    "name":     "Security Misconfiguration",
                    "finding":  "Endpoint served over unencrypted HTTP. TLS/HTTPS should be enforced.",
                    "severity": "HIGH",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        if method == "UNKNOWN":
            flags.append({
                "category": "API9",
                "name":     "Improper Inventory Management",
                "finding":  "HTTP method undocumented. Endpoint contract is unknown.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        if entry.api_version is None and "/api/" in ep:
            flags.append({
                "category": "API9",
                "name":     "Improper Inventory Management",
                "finding":  "No API versioning detected. Versioning is required for lifecycle management.",
                "severity": "LOW",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        if entry.parameters and entry.auth_type in ("None detected", "UNKNOWN"):
            params_str = ", ".join(p["name"] for p in entry.parameters)
            if not any(f.get("category") == "API1" for f in flags):
                flags.append({
                    "category": "API1",
                    "name":     "Broken Object Level Authorization (BOLA)",
                    "finding":  f"Endpoint accepts object identifier(s) [{params_str}] "
                                f"with no confirmed authentication. BOLA testing recommended.",
                    "severity": "HIGH",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        if entry.functional_type == "admin" and entry.auth_type in ("None detected", "UNKNOWN"):
            if not any(f.get("category") == "API5" for f in flags):
                flags.append({
                    "category": "API5",
                    "name":     "Broken Function Level Authorization",
                    "finding":  "Administrative endpoint detected with no confirmed authentication.",
                    "severity": "CRITICAL",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        if entry.downstream_dependencies:
            deps = ", ".join(entry.downstream_dependencies[:3])
            flags.append({
                "category": "API10",
                "name":     "Unsafe Consumption of Third-Party APIs",
                "finding":  f"Endpoint integrates with external services [{deps}]. "
                            f"Validate all external API responses; sanitize before use.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        if entry.functional_type in ("upload",) and method in ("POST", "PUT"):
            flags.append({
                "category": "API4",
                "name":     "Unrestricted Resource Consumption",
                "finding":  "File upload endpoint detected. Verify file size limits, "
                            "rate limiting, and file type validation.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        if entry.cve_findings:
            highest_cvss = max((c.get("cvss", 0) for c in entry.cve_findings), default=0)
            sev = "CRITICAL" if highest_cvss >= 9.0 else "HIGH" if highest_cvss >= 7.0 else "MEDIUM"
            if not any(f.get("category") == "API6" for f in flags):
                cve_ids = ", ".join(c["cve"] for c in entry.cve_findings[:3])
                flags.append({
                    "category": "API6",
                    "name":     "Unrestricted Access to Sensitive Business Flows",
                    "finding":  f"Vulnerable dependency detected affecting this endpoint's stack: {cve_ids}",
                    "severity": sev,
                    "endpoint": entry.endpoint,
                    "source":   "cve_correlation",
                })

        return flags

    def _score(self, entry) -> int:
        score = 0
        score += RISK_WEIGHTS["classification"].get(entry.classification, 15)
        score += RISK_WEIGHTS["data_sensitivity"].get(entry.data_sensitivity, 0)
        score += RISK_WEIGHTS["exposure"].get(entry.exposure, 8)

        for flag in entry.owasp_flags:
            sev = flag.get("severity", "LOW")
            score += RISK_WEIGHTS["owasp_severity"].get(sev, 0)

        if entry.cve_findings:
            score += RISK_WEIGHTS["cve"] * min(len(entry.cve_findings), 3)

        if entry.auth_type in ("None detected", "UNKNOWN"):
            score += RISK_WEIGHTS["no_auth"]

        if entry.endpoint.startswith("http://"):
            score += RISK_WEIGHTS["missing_tls"]

        score += RISK_WEIGHTS["functional_type_bonus"].get(entry.functional_type, 0)

        return min(score, 100)