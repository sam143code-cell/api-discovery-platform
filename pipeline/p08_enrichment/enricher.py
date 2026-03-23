"""
pipeline/p08_enrichment/enricher.py
Fixes applied:
  - CVE correlation now uses parsed package_dependencies from store (version-aware matching)
  - Added PACKAGE_CVE_DATABASE with version ranges for common npm/python/java packages
  - Functional type classification (auth, data, admin, upload, search, etc.)
  - Module-based inferred_owner assignment
  - Tech stack enrichment from store metadata
  - Downstream dependency detection
  - Improved sensitivity detection with endpoint context
  - Noise filtering: skip secret_scan and file-path entries
"""

import re
from typing import Dict, List, Optional, Tuple

# ── Auth detection patterns ─────────────────────────────────────────────────
AUTH_INDICATORS = {
    "Bearer JWT": [r"authorization.*bearer", r"jwt", r"/token", r"/oauth", r"/auth"],
    "API Key":    [r"x-api-key", r"api[-_]?key", r"apikey"],
    "Basic Auth": [r"authorization.*basic", r"/basic-auth"],
    "OAuth2":     [r"oauth2", r"oauth/token", r"authorization_code", r"client_credentials"],
    "OIDC":       [r"openid", r"id_token", r"/.well-known/openid"],
    "SAML":       [r"saml", r"sso"],
    "mTLS":       [r"client[-_]?cert", r"mtls", r"mutual[-_]?tls"],
    "No Auth Required": [r"/health", r"/ping", r"/status", r"/metrics", r"/public/"],
}

# ── Data sensitivity keywords ───────────────────────────────────────────────
SENSITIVITY_RULES = {
    "CRITICAL": [
        "password", "passwd", "secret", "private_key", "private-key",
        "ssn", "social-security", "credit-card", "cc-num", "cvv",
        "bearer", "access_token", "refresh_token", "client_secret",
        "bank-account", "routing-number", "iban", "swift",
        "biometric", "fingerprint", "aadhar", "pan",
        "ldap", "activedirectory", "ad-dashboard",
    ],
    "HIGH": [
        "email", "phone", "mobile", "address", "dob", "birth",
        "user_id", "account_id", "payment", "transaction",
        "passport", "license", "national-id", "voter",
        "salary", "income", "tax",
        "credit-score", "credit_score", "cibil",
        "hostip", "ipaddress", "ip-address",
        "user", "register", "login", "logout",
    ],
    "MEDIUM": [
        "profile", "preferences", "settings", "config",
        "session", "cart", "order", "report",
        "analytics", "log", "audit",
        "upload", "generate", "scan", "result",
        "vulnerability", "cve", "cvss", "epss",
        "malware", "threat", "indicator",
    ],
}

# ── Functional type classification ─────────────────────────────────────────
FUNCTIONAL_TYPE_RULES = [
    ("auth", [
        r"/login", r"/logout", r"/register", r"/verify-otp", r"/confirmation",
        r"/auth", r"/token", r"/oauth", r"/sso",
    ]),
    ("admin", [
        r"/admin", r"/management", r"/actuator", r"/debug",
        r"/add-menu", r"/delete-menu", r"/add-permission", r"/delete-permission",
        r"/update-permission", r"/create-group", r"/create-directive",
        r"/create-rule", r"/update-rule",
    ]),
    ("upload", [
        r"/upload", r"/uploadcsv", r"/uploadasset", r"/uploadhuman",
        r"/clearuploaded", r"/previewcsv", r"/upload-file",
        r"/upload-vulnerability", r"/upload-ip",
    ]),
    ("search", [
        r"/search", r"/searchcve", r"/searchhost", r"/searchpatch",
        r"/cve-id", r"/attack-technique", r"/defense-technique",
    ]),
    ("reporting", [
        r"/report", r"/generate-report", r"/report-count", r"/report-list",
    ]),
    ("data_read", [
        r"list$", r"details$", r"count$", r"data$", r"info$",
        r"score$", r"scores$",
    ]),
    ("data_write", [
        r"^post$|^put$|^delete$|^patch$",
    ]),
    ("health", [
        r"/health", r"/ping", r"/status", r"/probes",
    ]),
    ("integration", [
        r"/itsm", r"/manageengine", r"/ldap", r"/adlist", r"/sendrequest",
        r"/sendbulk", r"/escalate",
    ]),
]

# ── Exposure detection ──────────────────────────────────────────────────────
INTERNAL_INDICATORS = [
    r"^/internal/", r"^/private/", r"^/_",
    r"192\.168\.", r"10\.\d+\.", r"172\.(1[6-9]|2\d|3[01])\.",
    r"localhost", r"\.local/", r"\.internal/",
    r"/admin/", r"/management/", r"/actuator",
]

# ── Module → Owner mapping ──────────────────────────────────────────────────
MODULE_OWNER_MAP = {
    "Authentication & Session":           "Security Team / IAM",
    "Vulnerability Management - Counts":  "Security Operations",
    "Vulnerability Management - Lists":   "Security Operations",
    "Data Upload & Ingestion":            "Data Engineering",
    "Access Control & RBAC":              "Security Team / IAM",
    "Cyber Risk Quantification":          "Risk Management",
    "CIA Triad Assessment":               "Risk Management",
    "Asset CIA Mapping":                  "Risk Management",
    "Comparative Analysis":               "Analytics",
    "Threat Intelligence":                "Threat Intelligence Team",
    "Reporting":                          "Security Operations",
    "Risk Scoring":                       "Risk Management",
    "Host Discovery & Scanning":          "Security Operations",
    "ITSM Integration":                   "IT Operations",
    "SIEM / Detection Rules":             "SOC / SIEM Team",
    "Search & Lookup":                    "Security Operations",
    "Risk Acceptance":                    "Risk Management",
    "Active Directory Integration":       "IT Operations / IAM",
    "ManageEngine ITSM":                  "IT Operations",
    "Threat Graph":                       "Threat Intelligence Team",
    "SBOM & AI/ML Components":            "Engineering",
    "Static Assets":                      "Engineering",
    "Scanner Core API":                   "Engineering",
    "User Management":                    "Security Team / IAM",
    "Uncategorized":                      "Pending Triage - Application Owner",
}

# ── Legacy tech-stack CVE map (pattern-based, framework level) ──────────────
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

# ── Package-level CVE database (version-aware) ─────────────────────────────
# Format: package_name -> list of {cve, desc, cvss, affected_versions_below, ecosystem}
# affected_versions_below: tuple of (major, minor, patch) — flag if package version < this
PACKAGE_CVE_DATABASE: Dict[str, List[Dict]] = {
    # npm packages
    "express": [
        {
            "cve": "CVE-2024-29041",
            "desc": "Express.js open redirect via malformed URL host header",
            "cvss": 6.1,
            "affected_below": (4, 19, 2),
            "ecosystem": "npm",
        },
    ],
    "axios": [
        {
            "cve": "CVE-2023-45857",
            "desc": "Axios CSRF vulnerability via sensitive headers leaked in cross-origin redirects",
            "cvss": 8.8,
            "affected_below": (1, 6, 0),
            "ecosystem": "npm",
        },
    ],
    "jsonwebtoken": [
        {
            "cve": "CVE-2022-23529",
            "desc": "jsonwebtoken arbitrary file write via malicious JWK",
            "cvss": 7.6,
            "affected_below": (9, 0, 0),
            "ecosystem": "npm",
        },
        {
            "cve": "CVE-2022-23540",
            "desc": "jsonwebtoken algorithm confusion via blank password",
            "cvss": 6.4,
            "affected_below": (9, 0, 0),
            "ecosystem": "npm",
        },
    ],
    "multer": [
        {
            "cve": "CVE-2022-24434",
            "desc": "Multer ReDoS via crafted Content-Disposition header",
            "cvss": 5.3,
            "affected_below": (1, 4, 4),
            "ecosystem": "npm",
        },
    ],
    "lodash": [
        {
            "cve": "CVE-2021-23337",
            "desc": "Lodash command injection via template function",
            "cvss": 7.2,
            "affected_below": (4, 17, 21),
            "ecosystem": "npm",
        },
        {
            "cve": "CVE-2020-8203",
            "desc": "Lodash prototype pollution via zipObjectDeep",
            "cvss": 7.4,
            "affected_below": (4, 17, 19),
            "ecosystem": "npm",
        },
    ],
    "moment": [
        {
            "cve": "CVE-2022-24785",
            "desc": "Moment.js path traversal via locale loading",
            "cvss": 7.5,
            "affected_below": (2, 29, 2),
            "ecosystem": "npm",
        },
    ],
    "mongoose": [
        {
            "cve": "CVE-2019-17426",
            "desc": "Mongoose prototype pollution via query",
            "cvss": 9.1,
            "affected_below": (5, 7, 5),
            "ecosystem": "npm",
        },
    ],
    "sequelize": [
        {
            "cve": "CVE-2023-22578",
            "desc": "Sequelize SQL injection via model attributes",
            "cvss": 9.8,
            "affected_below": (6, 28, 1),
            "ecosystem": "npm",
        },
    ],
    "node-fetch": [
        {
            "cve": "CVE-2022-0235",
            "desc": "node-fetch forwards sensitive headers to redirect location",
            "cvss": 6.1,
            "affected_below": (2, 6, 7),
            "ecosystem": "npm",
        },
    ],
    "sharp": [
        {
            "cve": "CVE-2023-25166",
            "desc": "Sharp heap buffer overflow via crafted image",
            "cvss": 7.5,
            "affected_below": (0, 31, 3),
            "ecosystem": "npm",
        },
    ],
    "ws": [
        {
            "cve": "CVE-2024-37890",
            "desc": "ws DoS via headers with multiple HTTP/1.1 upgrade requests",
            "cvss": 7.5,
            "affected_below": (8, 17, 1),
            "ecosystem": "npm",
        },
    ],
    # Python packages
    "flask": [
        {
            "cve": "CVE-2023-30861",
            "desc": "Flask cookie session bypass via browser cache",
            "cvss": 7.5,
            "affected_below": (2, 3, 2),
            "ecosystem": "pypi",
        },
    ],
    "django": [
        {
            "cve": "CVE-2023-41164",
            "desc": "Django potential denial of service via very long email",
            "cvss": 7.5,
            "affected_below": (4, 2, 6),
            "ecosystem": "pypi",
        },
    ],
    "requests": [
        {
            "cve": "CVE-2023-32681",
            "desc": "Requests forwards proxy-authorization header to destination",
            "cvss": 6.1,
            "affected_below": (2, 31, 0),
            "ecosystem": "pypi",
        },
    ],
    "pillow": [
        {
            "cve": "CVE-2023-44271",
            "desc": "Pillow uncontrolled resource consumption via crafted image",
            "cvss": 7.5,
            "affected_below": (10, 0, 1),
            "ecosystem": "pypi",
        },
    ],
    # Java / Maven packages (artifactId matching)
    "spring-core": [
        {
            "cve": "CVE-2022-22965",
            "desc": "Spring4Shell RCE via data binding",
            "cvss": 9.8,
            "affected_below": (5, 3, 18),
            "ecosystem": "maven",
        },
    ],
    "log4j-core": [
        {
            "cve": "CVE-2021-44228",
            "desc": "Log4Shell JNDI injection RCE",
            "cvss": 10.0,
            "affected_below": (2, 15, 0),
            "ecosystem": "maven",
        },
    ],
}

# ── Risk scoring weights ────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "classification":   {"Rogue": 40, "Shadow": 25, "New": 10, "Valid": 0, "UNCLASSIFIED": 15},
    "data_sensitivity": {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 0},
    "exposure":         {"external": 20, "partner": 10, "internal": 5, "unknown": 8},
    "owasp_severity":   {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2},
    "cve":              10,
    "no_auth":          15,
    "missing_tls":      10,
    "functional_type_bonus": {"auth": 10, "admin": 15, "upload": 5},
}

# ── Noise: entries that should never be in API inventory ────────────────────
INVENTORY_NOISE_TAGS = {"secret_scan", "secret"}
MODEL_PATH_PATTERN  = re.compile(r'\.(h5|pkl|pt|pth|onnx|pb|tflite)$', re.I)
FILE_PATH_PATTERN   = re.compile(r'^\.\.[/\\]|^[a-zA-Z]:[/\\]')


def _parse_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a version string like '4.18.2', '4.18', '4' into a (major, minor, patch) tuple.
    Returns None if parsing fails.
    """
    if not version_str or version_str in ("unknown", "*", "latest", ""):
        return None
    # Strip leading non-numeric characters: ^4.18.2 -> 4.18.2
    clean = re.sub(r'^[^0-9]*', '', str(version_str))
    # Take only the numeric portion before any pre-release tag: 4.18.2-beta -> 4.18.2
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
    """Returns True if installed version is strictly below affected_below."""
    return installed < affected_below


class Enricher:
    def __init__(self, store, cfg: dict):
        self.store       = store
        self.cfg         = cfg
        self._tech_stack = getattr(store, "tech_stack", {})
        # FIX: Load parsed package dependencies for version-aware CVE matching
        self._package_deps: List[Dict] = getattr(store, "package_dependencies", [])
        # Build a fast lookup: {name.lower(): parsed_version_tuple or None}
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

            # FIX: Use e.inferred_owner from MODULE_OWNER_MAP, not a hardcoded string
            entry.inferred_owner = MODULE_OWNER_MAP.get(
                entry.functional_module,
                "Pending Triage - Application Owner"
            )

            # FIX: Version-aware CVE matching using parsed package deps
            if not entry.cve_findings:
                entry.cve_findings = self._check_cve(entry)

            if self._tech_stack:
                fw      = self._tech_stack.get("framework", "")
                runtime = self._tech_stack.get("runtime", "")
                if fw and fw != "unknown":
                    entry.tech_stack = f"{fw.capitalize()} / {runtime}"

            integrations = self._tech_stack.get("detected_integrations", [])
            if integrations and not entry.downstream_dependencies:
                if entry.functional_module in (
                    "ITSM Integration", "Active Directory Integration",
                    "ManageEngine ITSM", "Threat Graph"
                ):
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
        module = entry.functional_module
        if module in ("Authentication & Session",):
            return "Session Token"
        return "None detected"

    def _detect_sensitivity(self, entry) -> str:
        text       = entry.endpoint.lower()
        file_text  = entry.evidence.get("file", "").lower()
        combined   = text + " " + file_text
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
        """
        FIX: Version-aware CVE matching.
        Priority order:
          1. Check PACKAGE_CVE_DATABASE against parsed package versions from store
          2. Fall back to TECH_CVE_MAP (framework-level, no version info)
        """
        findings = []
        found_cves = set()  # deduplicate

        evidence_text = str(entry.evidence).lower()
        headers_text  = str(entry.headers_observed).lower()
        combined      = evidence_text + " " + headers_text + " " + entry.endpoint.lower()
        if entry.tech_stack:
            combined += " " + entry.tech_stack.lower()

        # Priority 1: Version-aware package CVE matching
        for pkg_name, cve_list in PACKAGE_CVE_DATABASE.items():
            pkg_lower = pkg_name.lower()
            installed_ver = self._pkg_version_map.get(pkg_lower)

            if installed_ver is None:
                # Package not found in manifest — skip version-aware check for this pkg
                # (don't fire just because the name appears in a file path)
                continue

            for cve_entry in cve_list:
                cve_id        = cve_entry["cve"]
                affected_below = cve_entry.get("affected_below")

                if cve_id in found_cves:
                    continue

                if affected_below and _version_is_affected(installed_ver, affected_below):
                    findings.append({
                        "cve":     cve_id,
                        "desc":    cve_entry["desc"],
                        "cvss":    cve_entry["cvss"],
                        "package": pkg_name,
                        "installed_version": ".".join(str(x) for x in installed_ver),
                        "fixed_in": ".".join(str(x) for x in affected_below),
                        "source":  "package_manifest",
                    })
                    found_cves.add(cve_id)
                elif not affected_below:
                    # No version boundary defined — flag regardless (legacy entry)
                    findings.append({
                        "cve":     cve_id,
                        "desc":    cve_entry["desc"],
                        "cvss":    cve_entry["cvss"],
                        "package": pkg_name,
                        "installed_version": ".".join(str(x) for x in installed_ver),
                        "fixed_in": "unknown",
                        "source":  "package_manifest_no_version_boundary",
                    })
                    found_cves.add(cve_id)

        # Priority 2: Framework-level fallback (only if no package manifest available)
        if not self._pkg_version_map:
            for pattern, cves in TECH_CVE_MAP.items():
                if pattern.search(combined):
                    for cve_entry in cves:
                        cve_id = cve_entry["cve"]
                        if cve_id not in found_cves:
                            findings.append({
                                **cve_entry,
                                "source": "framework_pattern_match",
                                "note": "Version not confirmed — package.json not available",
                            })
                            found_cves.add(cve_id)

        return findings

    def _enrich_owasp_flags(self, entry) -> List[Dict]:
        """
        Returns enriched OWASP flags combining live scan flags + inferred flags.
        """
        flags = list(entry.owasp_flags)
        ep    = entry.endpoint.lower()
        method = entry.method.upper()

        # API2 — Broken Authentication
        if entry.auth_type in ("None detected", "UNKNOWN") and entry.functional_type not in ("health",):
            if not any(f.get("category") == "API2" for f in flags):
                flags.append({
                    "category": "API2",
                    "name": "Broken Authentication",
                    "finding": "No authentication mechanism detected on this endpoint. "
                               "Verify authentication middleware is enforced.",
                    "severity": "HIGH" if entry.data_sensitivity in ("CRITICAL", "HIGH") else "MEDIUM",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        # API8 — Security Misconfiguration: unencrypted HTTP
        if entry.endpoint.startswith("http://"):
            if not any(f.get("category") == "API8" and "TLS" in f.get("finding", "") for f in flags):
                flags.append({
                    "category": "API8",
                    "name": "Security Misconfiguration",
                    "finding": "Endpoint served over unencrypted HTTP. TLS/HTTPS should be enforced.",
                    "severity": "HIGH",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        # API9 — Improper Inventory Management: undocumented method
        if method == "UNKNOWN":
            flags.append({
                "category": "API9",
                "name": "Improper Inventory Management",
                "finding": "HTTP method undocumented. Endpoint contract is unknown.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        # API9 — No versioning
        if entry.api_version is None and "/api/" in ep:
            flags.append({
                "category": "API9",
                "name": "Improper Inventory Management",
                "finding": "No API versioning detected. Versioning is required for lifecycle management.",
                "severity": "LOW",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        # API1 — BOLA risk
        if entry.parameters and entry.auth_type in ("None detected", "UNKNOWN"):
            params_str = ", ".join(p["name"] for p in entry.parameters)
            if not any(f.get("category") == "API1" for f in flags):
                flags.append({
                    "category": "API1",
                    "name": "Broken Object Level Authorization (BOLA)",
                    "finding": f"Endpoint accepts object identifier(s) [{params_str}] "
                               f"with no confirmed authentication. BOLA testing recommended.",
                    "severity": "HIGH",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        # API5 — Broken Function Level Authorization: admin endpoints
        if entry.functional_type == "admin" and entry.auth_type in ("None detected", "UNKNOWN"):
            if not any(f.get("category") == "API5" for f in flags):
                flags.append({
                    "category": "API5",
                    "name": "Broken Function Level Authorization",
                    "finding": "Administrative endpoint detected with no confirmed authentication.",
                    "severity": "CRITICAL",
                    "endpoint": entry.endpoint,
                    "source":   "inferred",
                })

        # API10 — Unsafe Consumption of Third-Party APIs
        if entry.downstream_dependencies:
            deps = ", ".join(entry.downstream_dependencies[:3])
            flags.append({
                "category": "API10",
                "name": "Unsafe Consumption of Third-Party APIs",
                "finding": f"Endpoint integrates with external services [{deps}]. "
                           f"Validate all external API responses; sanitize before use.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        # API4 — Unrestricted Resource Consumption: upload endpoints
        if entry.functional_type in ("upload",) and method in ("POST", "PUT"):
            flags.append({
                "category": "API4",
                "name": "Unrestricted Resource Consumption",
                "finding": "File upload endpoint detected. Verify file size limits, "
                           "rate limiting, and file type validation.",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
                "source":   "inferred",
            })

        # API6 — CVE findings mean supply chain risk
        if entry.cve_findings:
            highest_cvss = max((c.get("cvss", 0) for c in entry.cve_findings), default=0)
            sev = "CRITICAL" if highest_cvss >= 9.0 else "HIGH" if highest_cvss >= 7.0 else "MEDIUM"
            if not any(f.get("category") == "API6" for f in flags):
                cve_ids = ", ".join(c["cve"] for c in entry.cve_findings[:3])
                flags.append({
                    "category": "API6",
                    "name": "Unrestricted Access to Sensitive Business Flows",
                    "finding": f"Vulnerable dependency detected affecting this endpoint's stack: {cve_ids}",
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