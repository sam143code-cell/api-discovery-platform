import asyncio
import re
import json
from typing import Dict, List, Optional
import aiohttp

USER_AGENT = "Mozilla/5.0 (compatible; SecurityAssessment/1.0)"

OWASP_CATEGORIES = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of Third-Party APIs",
}

SENSITIVE_DATA_PATTERNS = [
    (re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'), "credit_card"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "ssn"),
    (re.compile(r'["\']password["\']\s*:', re.I), "password_in_response"),
    (re.compile(r'["\']secret["\']\s*:', re.I), "secret_in_response"),
    (re.compile(r'["\']api_?key["\']\s*:', re.I), "api_key_in_response"),
    (re.compile(r'["\']private_?key["\']\s*:', re.I), "private_key_in_response"),
    (re.compile(r'["\']token["\']\s*:\s*"[A-Za-z0-9_\-\.]{20,}"', re.I), "token_exposed"),
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
]

CORS_DANGEROUS = ["*", "null"]

OLD_VERSION_PATTERNS = [
    re.compile(r"/v(\d+)/"),
    re.compile(r"/api/v(\d+)/"),
]

DEBUG_PATHS = [
    "/debug", "/debug/vars", "/actuator", "/actuator/env",
    "/actuator/heapdump", "/actuator/threaddump", "/.env",
    "/server-status", "/phpinfo.php", "/trace",
]

MISSING_SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
    "content-security-policy",
]


class OWASPScanner:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg
        self.owasp_cfg = cfg.get("owasp", {})
        self.mode = cfg.get("scan", {}).get("mode", "passive")
        self.active_delay = self.owasp_cfg.get("active_delay_ms", 500) / 1000
        self._session: Optional[aiohttp.ClientSession] = None

    async def run(self):
        entries = self.store.all()
        active_entries = [
            e for e in entries
            if e.status_code and e.status_code not in (404, 410)
               and not e.endpoint.startswith("source_finding")
        ]

        if not active_entries:
            print("    No active endpoints to assess")
            return

        print(f"    OWASP assessment: {len(active_entries)} endpoints "
              f"[mode={self.mode}]")

        conn = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(
            connector=conn, timeout=timeout,
            headers={"User-Agent": USER_AGENT}
        ) as session:
            self._session = session
            tasks = [self._assess_entry(e) for e in active_entries]
            await asyncio.gather(*tasks, return_exceptions=True)

        flagged = sum(1 for e in entries if e.owasp_flags)
        print(f"    OWASP: {flagged} endpoints with findings")

    async def _assess_entry(self, entry):
        flags = []

        # ── API8: Security Misconfiguration (passive — always run) ─────────────
        if self.owasp_cfg.get("test_misconfiguration", True):
            flags += await self._check_api8_passive(entry)

        # ── API2: Broken Authentication (passive) ──────────────────────────────
        if self.owasp_cfg.get("test_broken_auth", True):
            flags += self._check_api2_passive(entry)

        # ── API9: Improper Inventory (passive) ─────────────────────────────────
        if self.owasp_cfg.get("test_inventory", True):
            flags += self._check_api9_passive(entry)

        # ── Active tests (only in active mode) ────────────────────────────────
        if self.mode == "active":
            await asyncio.sleep(self.active_delay)

            if self.owasp_cfg.get("test_bola", True):
                flags += await self._check_api1_bola(entry)

            if self.owasp_cfg.get("test_mass_assignment", True):
                flags += await self._check_api3_mass_assignment(entry)

            if self.owasp_cfg.get("test_rate_limit", True):
                flags += await self._check_api4_rate_limit(entry)

            if self.owasp_cfg.get("test_bfla", True):
                flags += await self._check_api5_bfla(entry)

            if self.owasp_cfg.get("test_ssrf", True):
                flags += await self._check_api7_ssrf(entry)

            if self.owasp_cfg.get("test_misconfiguration", True):
                flags += await self._check_api8_active(entry)

        if flags:
            entry.owasp_flags.extend(flags)

    # ── Passive checks ─────────────────────────────────────────────────────────

    async def _check_api8_passive(self, entry) -> List[Dict]:
        flags = []
        endpoint = entry.endpoint

        # Check response headers we already captured
        headers = entry.headers_observed or {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for h in MISSING_SECURITY_HEADERS:
            if h not in headers_lower:
                flags.append({
                    "category": "API8",
                    "name": OWASP_CATEGORIES["API8"],
                    "finding": f"Missing security header: {h}",
                    "severity": "MEDIUM",
                    "endpoint": endpoint,
                })

        # CORS check
        cors = headers_lower.get("access-control-allow-origin", "")
        if cors in CORS_DANGEROUS:
            flags.append({
                "category": "API8",
                "name": OWASP_CATEGORIES["API8"],
                "finding": f"Permissive CORS: Access-Control-Allow-Origin: {cors}",
                "severity": "HIGH",
                "endpoint": endpoint,
            })

        # Probe for debug paths in active mode prep — check if debug path pattern
        for dp in DEBUG_PATHS:
            if dp in endpoint.lower():
                flags.append({
                    "category": "API8",
                    "name": OWASP_CATEGORIES["API8"],
                    "finding": f"Debug/diagnostic endpoint exposed: {dp}",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                })

        # Sensitive data in response (from evidence)
        resp_preview = str(entry.evidence.get("response_preview", ""))
        for pat, label in SENSITIVE_DATA_PATTERNS:
            if pat.search(resp_preview):
                flags.append({
                    "category": "API8",
                    "name": OWASP_CATEGORIES["API8"],
                    "finding": f"Sensitive data in response: {label}",
                    "severity": "CRITICAL",
                    "endpoint": endpoint,
                })

        return flags

    def _check_api2_passive(self, entry) -> List[Dict]:
        flags = []
        auth = entry.auth_type
        headers = {k.lower(): v for k, v in (entry.headers_observed or {}).items()}

        if auth == "UNKNOWN" and entry.status_code not in (401, 403):
            flags.append({
                "category": "API2",
                "name": OWASP_CATEGORIES["API2"],
                "finding": "Endpoint accessible without detected authentication",
                "severity": "HIGH",
                "endpoint": entry.endpoint,
            })

        if "authorization" not in headers and entry.status_code == 200:
            if any(kw in entry.endpoint.lower() for kw in
                   ["user", "account", "profile", "admin", "payment", "order"]):
                flags.append({
                    "category": "API2",
                    "name": OWASP_CATEGORIES["API2"],
                    "finding": "Sensitive endpoint may lack authentication",
                    "severity": "HIGH",
                    "endpoint": entry.endpoint,
                })

        return flags

    def _check_api9_passive(self, entry) -> List[Dict]:
        flags = []
        for pat in OLD_VERSION_PATTERNS:
            m = pat.search(entry.endpoint)
            if m:
                version = int(m.group(1))
                if version >= 2:
                    # Check if newer version also exists
                    newer = pat.sub(f"/v{version + 1}/", entry.endpoint)
                    if self.store.seen_endpoint(newer):
                        flags.append({
                            "category": "API9",
                            "name": OWASP_CATEGORIES["API9"],
                            "finding": f"Old API version still active (v{version}) while newer version exists",
                            "severity": "MEDIUM",
                            "endpoint": entry.endpoint,
                        })
        return flags

    # ── Active checks ──────────────────────────────────────────────────────────

    async def _check_api1_bola(self, entry) -> List[Dict]:
        flags = []
        endpoint = entry.endpoint
        # Look for numeric IDs in path — try substituting another ID
        if re.search(r"/\d+", endpoint):
            test_url = re.sub(r"/(\d+)", lambda m: f"/{int(m.group(1)) + 1}", endpoint, count=1)
            try:
                resp = await self._session.get(test_url, allow_redirects=False)
                if resp.status == 200:
                    flags.append({
                        "category": "API1",
                        "name": OWASP_CATEGORIES["API1"],
                        "finding": f"Possible BOLA: accessing resource with incremented ID returned 200",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "test_url": test_url,
                    })
            except Exception:
                pass
        return flags

    async def _check_api3_mass_assignment(self, entry) -> List[Dict]:
        flags = []
        if entry.method not in ("POST", "PUT", "PATCH", "UNKNOWN"):
            return flags
        # Send extra fields and check if they're reflected
        payload = json.dumps({
            "id": 99999,
            "admin": True,
            "role": "admin",
            "is_admin": True,
            "_isAdmin": True,
        })
        try:
            resp = await self._session.post(
                entry.endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
            text = await resp.text()
            if resp.status in (200, 201) and any(
                kw in text.lower() for kw in ['"admin":true', '"role":"admin"', '"is_admin":true']
            ):
                flags.append({
                    "category": "API3",
                    "name": OWASP_CATEGORIES["API3"],
                    "finding": "Possible mass assignment: admin fields accepted and reflected",
                    "severity": "CRITICAL",
                    "endpoint": entry.endpoint,
                })
        except Exception:
            pass
        return flags

    async def _check_api4_rate_limit(self, entry) -> List[Dict]:
        flags = []
        responses = []
        for _ in range(10):
            try:
                resp = await self._session.get(entry.endpoint, allow_redirects=False)
                responses.append(resp.status)
                if resp.status == 429:
                    return flags  # Rate limit working
            except Exception:
                pass
        if all(r == 200 for r in responses) and len(responses) == 10:
            flags.append({
                "category": "API4",
                "name": OWASP_CATEGORIES["API4"],
                "finding": "No rate limiting detected after 10 rapid requests",
                "severity": "MEDIUM",
                "endpoint": entry.endpoint,
            })
        return flags

    async def _check_api5_bfla(self, entry) -> List[Dict]:
        flags = []
        # Check if admin-like endpoints are accessible without special headers
        admin_indicators = ["/admin", "/management", "/internal", "/superuser", "/root"]
        if any(ind in entry.endpoint.lower() for ind in admin_indicators):
            try:
                resp = await self._session.get(entry.endpoint, allow_redirects=False)
                if resp.status == 200:
                    flags.append({
                        "category": "API5",
                        "name": OWASP_CATEGORIES["API5"],
                        "finding": "Admin/privileged endpoint accessible without elevated auth",
                        "severity": "CRITICAL",
                        "endpoint": entry.endpoint,
                    })
            except Exception:
                pass
        return flags

    async def _check_api7_ssrf(self, entry) -> List[Dict]:
        flags = []
        # Inject SSRF payloads into URL parameters
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(entry.endpoint)
        params = parse_qs(parsed.query)
        url_params = {k: v[0] for k, v in params.items()
                      if any(kw in k.lower() for kw in
                             ["url", "uri", "path", "redirect", "callback", "webhook", "dest"])}
        if not url_params:
            return flags
        for param in url_params:
            for payload in SSRF_PAYLOADS[:2]:
                test_params = dict(params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    resp = await self._session.get(test_url, allow_redirects=False)
                    text = await resp.text()
                    if "ami-id" in text or "computeMetadata" in text or "local-hostname" in text:
                        flags.append({
                            "category": "API7",
                            "name": OWASP_CATEGORIES["API7"],
                            "finding": f"SSRF confirmed via parameter '{param}': cloud metadata accessible",
                            "severity": "CRITICAL",
                            "endpoint": entry.endpoint,
                            "payload": payload,
                        })
                except Exception:
                    pass
        return flags

    async def _check_api8_active(self, entry) -> List[Dict]:
        flags = []
        # Probe debug paths relative to the endpoint's base
        from urllib.parse import urlparse
        parsed = urlparse(entry.endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for dp in DEBUG_PATHS:
            test_url = f"{base}{dp}"
            try:
                resp = await self._session.get(test_url, allow_redirects=False)
                if resp.status not in (404, 410, 403):
                    text = await resp.text()
                    if len(text) > 50:
                        flags.append({
                            "category": "API8",
                            "name": OWASP_CATEGORIES["API8"],
                            "finding": f"Debug endpoint accessible: {dp} returned {resp.status}",
                            "severity": "HIGH",
                            "endpoint": test_url,
                        })
            except Exception:
                pass
        return flags
