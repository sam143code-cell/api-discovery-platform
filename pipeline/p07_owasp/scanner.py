import asyncio
import re
import json
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

OWASP_CATEGORIES = {
    "API2":  "Broken Authentication",
    "API3":  "Broken Object Property Level Authorization",
    "API8":  "Security Misconfiguration",
    "API9":  "Improper Inventory Management",
    "API10": "Unsafe Consumption of Third-Party APIs",
}

SENSITIVE_DATA_PATTERNS = [
    (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'), "credit_card"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "ssn"),
    (re.compile(r'[:=]\s*["\'](A3T[A-Z0-9]{16,})["\']', re.I), "aws_access_key"),
    (re.compile(r'[:=]\s*["\'](xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})["\']', re.I), "slack_token"),
    (re.compile(r'[:=]\s*["\'](eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)["\']'), "jwt_exposed"),
    (re.compile(r'["\'](?:password|secret|api_?key|private_?key)["\']\s*:\s*["\']([^"\'*]{8,})["\']', re.I), "hardcoded_secret_value"),
]

DEBUG_PATHS = [
    re.compile(r'/(?:debug|actuator|vars|env|heapdump|trace|phpinfo|server-status)(?:/|$)', re.I),
    re.compile(r'/\.env$', re.I),
]

MISSING_SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
]

INTERNAL_FIELDS = {"is_admin", "is_superuser", "role_id", "internal_id", "privileges", "permissions_mask", "account_status"}
SENSITIVE_KEYWORDS = {"user", "account", "profile", "admin", "payment", "order", "invoice", "settings", "config", "vault"}

class OWASPScanner:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg
        self.owasp_cfg = cfg.get("owasp", {})
        self._checked_hosts: Set[str] = set()

    async def run(self):
        entries = self.store.all()
        active_entries = [
            e for e in entries 
            if getattr(e, "status_code", 0) and e.status_code not in (404, 410)
            and not e.endpoint.startswith("source_finding")
        ]

        if not active_entries:
            return

        print(f"    OWASP passive assessment: {len(active_entries)} endpoints")

        for entry in active_entries:
            await self._assess_entry(entry)

        self._check_api10_global()

        flagged = sum(1 for e in entries if getattr(e, "owasp_flags", []))
        print(f"    OWASP: {flagged} endpoints with findings")

    async def _assess_entry(self, entry):
        flags = []
        
        if self.owasp_cfg.get("test_broken_auth", True):
            flags += self._check_api2_passive(entry)

        if self.owasp_cfg.get("test_mass_assignment", True):
            flags += self._check_api3_passive(entry)

        if self.owasp_cfg.get("test_misconfiguration", True):
            flags += self._check_api8_passive(entry)

        if self.owasp_cfg.get("test_inventory", True):
            flags += self._check_api9_passive(entry)

        if flags:
            if not hasattr(entry, "owasp_flags") or entry.owasp_flags is None:
                entry.owasp_flags = []
            entry.owasp_flags.extend(flags)

    def _check_api2_passive(self, entry) -> List[Dict]:
        flags = []
        endpoint = entry.endpoint
        path_lower = urlparse(endpoint).path.lower()
        headers = {k.lower(): str(v) for k, v in (getattr(entry, "headers_observed", {}) or {}).items()}
        has_auth = any(h in headers for h in ["authorization", "x-api-key", "api-key", "cookie", "token"])

        if entry.status_code == 200 and not has_auth:
            path_segments = set(re.split(r'[/_\-]', path_lower))
            if path_segments.intersection(SENSITIVE_KEYWORDS):
                flags.append({
                    "category": "API2",
                    "name": OWASP_CATEGORIES["API2"],
                    "finding": "Sensitive endpoint accessible without detected authentication headers",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                })
        return flags

    def _check_api3_passive(self, entry) -> List[Dict]:
        flags = []
        resp_preview = str(getattr(entry, "evidence", {}).get("response_preview", "")).lower()
        if not resp_preview:
            return flags
            
        found_fields = [f for f in INTERNAL_FIELDS if f'"{f}"' in resp_preview or f"'{f}'" in resp_preview]
        if found_fields:
            flags.append({
                "category": "API3",
                "name": OWASP_CATEGORIES["API3"],
                "finding": f"Administrative/internal fields reflected in response body: {', '.join(found_fields)}",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
            })
        return flags

    def _check_api8_passive(self, entry) -> List[Dict]:
        flags = []
        endpoint = entry.endpoint
        parsed = urlparse(endpoint)
        host = parsed.netloc
        headers = {k.lower(): str(v) for k, v in (getattr(entry, "headers_observed", {}) or {}).items()}

        if host and host not in self._checked_hosts:
            for h in MISSING_SECURITY_HEADERS:
                if h not in headers:
                    flags.append({
                        "category": "API8",
                        "name": OWASP_CATEGORIES["API8"],
                        "finding": f"Global Misconfiguration: Missing security header '{h}' on host",
                        "severity": "LOW",
                        "endpoint": f"{parsed.scheme}://{host}/*",
                    })
            self._checked_hosts.add(host)

        cors = headers.get("access-control-allow-origin", "")
        if cors in ("*", "null"):
            flags.append({
                "category": "API8",
                "name": OWASP_CATEGORIES["API8"],
                "finding": f"Permissive CORS policy: Access-Control-Allow-Origin: {cors}",
                "severity": "MEDIUM",
                "endpoint": endpoint,
            })

        for pat in DEBUG_PATHS:
            if pat.search(parsed.path):
                flags.append({
                    "category": "API8",
                    "name": OWASP_CATEGORIES["API8"],
                    "finding": f"Debug or diagnostic endpoint exposure detected",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                })

        resp_preview = str(getattr(entry, "evidence", {}).get("response_preview", ""))
        if resp_preview:
            for pat, label in SENSITIVE_DATA_PATTERNS:
                match = pat.search(resp_preview)
                if match:
                    val = match.group(1) if match.groups() else match.group(0)
                    if len(set(val)) < 4:
                        continue
                    flags.append({
                        "category": "API8",
                        "name": OWASP_CATEGORIES["API8"],
                        "finding": f"Sensitive data exposure in response: {label}",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                    })
        return flags

    def _check_api9_passive(self, entry) -> List[Dict]:
        flags = []
        path = urlparse(entry.endpoint).path
        
        if getattr(entry, "classification", "") == "Shadow":
            flags.append({
                "category": "API9",
                "name": OWASP_CATEGORIES["API9"],
                "finding": "Shadow API: Endpoint exists in codebase but lacks documentation/governance",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
            })

        version_match = re.search(r'/v(\d+)/', path)
        if version_match:
            current_v = int(version_match.group(1))
            next_v_path = path.replace(f"/v{current_v}/", f"/v{current_v + 1}/")
            if hasattr(self.store, "seen_endpoint") and self.store.seen_endpoint(next_v_path):
                flags.append({
                    "category": "API9",
                    "name": OWASP_CATEGORIES["API9"],
                    "finding": f"Deprecated API versioning: v{current_v} is active alongside a newer version",
                    "severity": "LOW",
                    "endpoint": entry.endpoint,
                })
        return flags

    def _check_api10_global(self):
        inventory = getattr(self.store, "outbound_api_inventory", [])
        if not inventory:
            return

        global_flags = []
        for item in inventory:
            url = item.get("url", "")
            if url.startswith("http://"):
                global_flags.append({
                    "category": "API10",
                    "name": OWASP_CATEGORIES["API10"],
                    "finding": f"Unsafe outbound communication: Data sent to {item.get('host')} over unencrypted HTTP",
                    "severity": "HIGH",
                    "endpoint": "Outbound Integration",
                    "url": url
                })

        if global_flags:
            dummy_entry = self.store.get_or_create_finding_placeholder("Global Third-Party Risks")
            if not hasattr(dummy_entry, "owasp_flags") or dummy_entry.owasp_flags is None:
                dummy_entry.owasp_flags = []
            dummy_entry.owasp_flags.extend(global_flags)