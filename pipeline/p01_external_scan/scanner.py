import asyncio
import re
import hashlib
import os
import socket
import statistics
import urllib.parse
from collections import deque
from typing import List, Dict, Optional
import aiohttp
import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

NOISE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".css", ".map", ".mp4", ".webp", ".bmp", ".zip",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".mp3", ".wav",
}
NOISE_PATTERNS = [
    r"/(static|assets|images|img|fonts|icons|media|dist|build|public|vendor)/",
    r"\.(min\.js|bundle\.js|chunk\.[a-f0-9]+\.js)(\?|$)",
    r"//localhost", r"//127\.0\.", r"//0\.0\.0\.0",
    r"example\.(com|org|net)", r"schema\.org", r"w3\.org",
]

JS_PATTERNS = [
    r'["\'`](/api/[a-zA-Z0-9/_\-\{\}:.?=&@]+)["\'`]',
    r'["\'`](/v\d+/[a-zA-Z0-9/_\-\{\}:.?=&@]+)["\'`]',
    r'["\'`](/rest/[a-zA-Z0-9/_\-\{\}:.?=&@]+)["\'`]',
    r'fetch\(\s*["\'`]([^"\'`\s\)]{4,})["\'`]',
    r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\'`]([^"\'`\s]{4,})["\'`]',
    r'(?:url|endpoint|baseUrl|baseURL|apiUrl|apiBase)\s*[=:]\s*["\'`]([^"\'`\s]{4,})["\'`]',
    r'["\'`](https?://[^\s"\'`<>]{4,}/(?:api|v\d+|rest|graphql)/[^\s"\'`<>]{2,})["\'`]',
    r'XMLHttpRequest[\s\S]{0,80}?\.open\s*\(\s*["\'`]\w+["\'`]\s*,\s*["\'`]([^"\'`\s]{4,})["\'`]',
]

SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json", "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/v1/api-docs", "/v2/api-docs",
    "/.well-known/openapi", "/docs/swagger.json", "/spec", "/spec.json",
]

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/gql", "/api/graphql",
    "/v1/graphql", "/v2/graphql", "/_graphql",
]

GRAPHQL_INTROSPECTION = """{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"""

SUBDOMAINS = [
    "api", "api2", "v1", "v2", "rest", "graphql", "internal", "admin",
    "dev", "staging", "sandbox", "beta", "mobile", "backend", "gateway",
    "auth", "sso", "data", "analytics", "platform", "core", "legacy",
    "uat", "qa", "preprod", "ms", "svc", "portal", "console", "mgmt",
]

WELL_KNOWN = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server", "/.well-known/jwks.json",
]

SENTINEL_TEMPLATES = [
    "/____fake_{hex}", "/api/____fake_{hex}", "/v1/____fake_{hex}",
    "/api/v1/users/____fake_{hex}", "/____fake_{hex}/items",
]

# ---------------------------------------------------------------------------
# Dotfile / Apache-config noise filter (used in brute-force)
# ---------------------------------------------------------------------------
EXCLUDE_EXTENSIONS = {
    '.htm', '.html', '.htaccess', '.htpasswd', '.hta', '.htc', '.hts',
    '.htn', '.htx', '.htlm', '.htgroup', '.htuser', '.htacess',
}
EXCLUDE_PREFIXES = ('/.ht', '/.htm', '/.html')


def _is_dotfile_noise(path: str) -> bool:
    """Filter Apache dotfile variants and plain HTML paths that are not APIs."""
    path_lower = path.lower()
    if path_lower.startswith(EXCLUDE_PREFIXES):
        return True
    _, ext = os.path.splitext(path_lower)
    if ext in EXCLUDE_EXTENSIONS:
        return True
    return False


def _is_noisy(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext in NOISE_EXTENSIONS:
            return True
        for p in NOISE_PATTERNS:
            if re.search(p, url, re.IGNORECASE):
                return True
    except Exception:
        pass
    return False


def _load_wordlist(path: str) -> List[str]:
    if not path or not os.path.exists(path):
        return []
    seen, result = set(), []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            if line not in seen:
                seen.add(line)
                result.append(line)
    return result


class Baseline:
    def __init__(self):
        self.available = False
        self.is_wildcard = False
        self._wildcard_status = None
        self._wildcard_avg = 0
        self._all_hashes: set = set()
        self._buckets: Dict = {}
        self._tolerance = 80

    def establish(self, session, base_url, timeout):
        print("    Establishing false-positive baseline...")
        all_sizes, all_statuses = [], []
        for tmpl in SENTINEL_TEMPLATES:
            url = f"{base_url}{tmpl.format(hex=os.urandom(5).hex())}"
            try:
                r = session.get(url, timeout=timeout, allow_redirects=False)
                size = len(r.content)
                h = hashlib.md5(r.content).hexdigest()
                self._all_hashes.add(h)
                all_sizes.append(size)
                all_statuses.append(r.status_code)
                st = r.status_code
                if st not in self._buckets:
                    self._buckets[st] = {"hashes": set(), "sizes": [], "snippets": []}
                self._buckets[st]["hashes"].add(h)
                self._buckets[st]["sizes"].append(size)
                self._buckets[st]["snippets"].append(r.text[:300].strip())
                self.available = True
            except Exception:
                pass
        if not all_sizes:
            return
        if len(all_sizes) > 1:
            self._tolerance = max(80, int(statistics.variance(all_sizes) ** 0.5 * 3))
        if len(set(all_statuses)) == 1:
            st = all_statuses[0]
            spread = max(all_sizes) - min(all_sizes)
            if spread < 20:
                self.is_wildcard = True
                self._wildcard_status = st
                self._wildcard_avg = statistics.mean(all_sizes)
                print(f"    Wildcard server: status={st} size≈{int(self._wildcard_avg)}B")
                return
        print(f"    Baseline: {len(self._buckets)} response pattern(s) fingerprinted")

    def is_fp(self, resp) -> bool:
        if not self.available:
            return False
        h = hashlib.md5(resp.content).hexdigest()
        if h in self._all_hashes:
            return True
        st = resp.status_code
        size = len(resp.content)
        if self.is_wildcard:
            if st == self._wildcard_status and abs(size - self._wildcard_avg) < self._tolerance:
                return True
            return False
        if st in self._buckets:
            avg = statistics.mean(self._buckets[st]["sizes"])
            if abs(size - avg) < self._tolerance * 0.25:
                return True
        return False


class AsyncHTTPClient:
    def __init__(self, timeout=12, concurrency=20):
        self._sem = None
        self._session = None
        self.timeout = timeout
        self.concurrency = concurrency

    async def __aenter__(self):
        self._sem = asyncio.Semaphore(self.concurrency)
        conn = aiohttp.TCPConnector(ssl=False, limit=self.concurrency + 10)
        to = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(
            connector=conn, timeout=to,
            headers={"User-Agent": USER_AGENT}
        )
        return self

    async def __aexit__(self, *a):
        if self._session:
            await self._session.close()
            await asyncio.sleep(0.1)

    async def request(self, method, url, **kw):
        async with self._sem:
            for attempt in range(3):
                try:
                    async with self._session.request(
                        method, url,
                        allow_redirects=kw.get("allow_redirects", True),
                        headers=kw.get("headers"),
                        data=kw.get("data"),
                    ) as resp:
                        if resp.status in {429, 503, 502}:
                            await asyncio.sleep(2 ** attempt)
                            continue
                        body = await resp.read()
                        return _SimpleResp(resp.status, dict(resp.headers), body, str(resp.url))
                except asyncio.TimeoutError:
                    if attempt < 2:
                        await asyncio.sleep(1)
                except Exception:
                    if attempt < 2:
                        await asyncio.sleep(1)
        return None

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)


class _SimpleResp:
    def __init__(self, status, headers, content, url):
        self.status_code = status
        self.headers = headers
        self.content = content
        self.text = content.decode("utf-8", errors="replace")
        self.url = url

    def json(self):
        import json
        return json.loads(self.text)


class ExternalScanner:
    def __init__(self, domain: str, store, cfg: dict):
        self.domain = domain.rstrip("/")
        if not self.domain.startswith("http"):
            self.domain = "https://" + self.domain
        self.parsed = urllib.parse.urlparse(self.domain)
        self.store = store
        self.cfg = cfg
        self.baseline = Baseline()
        self.visited: set = set()
        self.wordlist = _load_wordlist(cfg.get("wordlist", ""))
        self._spec_endpoints: set = set()

    def _norm(self, url, base=None):
        if not base:
            base = self.domain
        url = url.strip()
        if not url or url.startswith(("mailto:", "tel:", "javascript:", "#", "data:", "blob:")):
            return None
        if url.startswith("//"):
            url = self.parsed.scheme + ":" + url
        elif url.startswith("/"):
            url = f"{self.parsed.scheme}://{self.parsed.netloc}{url}"
        elif not url.startswith("http"):
            url = urllib.parse.urljoin(base, url)
        return url.split("#")[0].rstrip("/") or None

    def _same_domain(self, url):
        try:
            parsed = urllib.parse.urlparse(url)
            base = self.parsed.netloc.lower().lstrip("www.")
            target = parsed.netloc.lower().lstrip("www.")
            return target == base or target.endswith("." + base)
        except Exception:
            return False

    def _api_like(self, path):
        indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/",
                      "/graphql", "/rpc", "/query", "/data/", "/_api", "/internal", "/svc/"]
        return any(i in path.lower() for i in indicators)

    async def run(self):
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = USER_AGENT
        self.baseline.establish(sess, self.domain, self.cfg.get("timeout", 12))

        async with AsyncHTTPClient(
            timeout=self.cfg.get("timeout", 12),
            concurrency=self.cfg.get("concurrency", 20)
        ) as client:
            await self._robots_sitemap(client)
            await self._crawl(client)
            if self.cfg.get("js_crawl", True):
                await self._js_crawl()
            await self._bruteforce(client)
            await self._graphql(client)
            await self._fetch_specs(client)
            if self.cfg.get("subdomain_discovery", True):
                await self._subdomains()

    async def _robots_sitemap(self, client):
        for path in WELL_KNOWN:
            url = f"{self.domain}{path}"
            resp = await client.get(url)
            if not resp or resp.status_code != 200:
                continue
            if "robots" in path:
                for line in resp.text.splitlines():
                    l = line.strip().lower()
                    if l.startswith(("disallow:", "allow:")):
                        p = line.split(":", 1)[-1].strip()
                        if p and p != "/" and "*" not in p:
                            full = f"{self.domain}{p}"
                            await self.store.upsert(full, "GET", "robots_txt",
                                                    exposure="external", discovered_by=["robots_txt"])
            elif "sitemap" in path:
                await self._parse_sitemap(client, url, resp.text)
            elif "openid-configuration" in path or "oauth-authorization-server" in path:
                import json
                try:
                    data = json.loads(resp.text)
                    for field in ["authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                                  "jwks_uri", "introspection_endpoint", "revocation_endpoint"]:
                        if field in data:
                            await self.store.upsert(data[field], "GET", "well_known",
                                                    auth_type="OAuth2/OIDC",
                                                    evidence={"well_known_field": field})
                except Exception:
                    pass

    async def _parse_sitemap(self, client, url, content):
        try:
            soup = BeautifulSoup(content, "xml")
            for loc in soup.find_all("loc"):
                loc_url = loc.text.strip()
                parsed = urllib.parse.urlparse(loc_url)
                if self._api_like(parsed.path):
                    await self.store.upsert(loc_url, "GET", "sitemap")
            for tag in soup.find_all("sitemap"):
                loc = tag.find("loc")
                if loc:
                    r = await client.get(loc.text.strip())
                    if r and r.status_code == 200:
                        await self._parse_sitemap(client, loc.text.strip(), r.text)
        except Exception:
            pass

    async def _crawl(self, client):
        max_pages = self.cfg.get("max_pages", 300)
        queue = deque([self.domain])
        active = []
        crawled = 0
        while (queue or active) and crawled < max_pages:
            while queue and len(active) < 15 and crawled < max_pages:
                url = queue.popleft()
                if url not in self.visited:
                    self.visited.add(url)
                    crawled += 1
                    active.append(asyncio.create_task(self._crawl_page(url, queue, client)))
            if active:
                done, pending = await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)
                active = list(pending)
                for t in done:
                    try:
                        await t
                    except Exception:
                        pass
        for t in active:
            t.cancel()

    async def _crawl_page(self, url, queue, client):
        resp = await client.get(url, allow_redirects=True)
        if not resp:
            return
        ct = resp.headers.get("Content-Type", "")
        path = urllib.parse.urlparse(url).path
        if self._api_like(path) and not self.baseline.is_fp(resp):
            await self.store.upsert(url, "GET", "http_crawler",
                                    status_code=resp.status_code,
                                    content_type=ct.split(";")[0].strip(),
                                    response_size_bytes=len(resp.content),
                                    exposure="external")
        if "javascript" in ct or url.endswith(".js"):
            await self._extract_js(resp.text, url)
            return
        if "html" not in ct:
            await self._extract_js(resp.text, url)
            return
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return
        for tag in soup.find_all(["a", "link"], href=True):
            n = self._norm(tag["href"], url)
            if not n or _is_noisy(n):
                continue
            if self._same_domain(n):
                if n not in self.visited:
                    queue.append(n)
            else:
                await self.store.upsert(n, "GET", "http_crawler_outbound",
                                        exposure="external", tags=["outbound"])
        for tag in soup.find_all("form"):
            action = tag.get("action") or url
            n = self._norm(action, url)
            if not n:
                continue
            method = tag.get("method", "GET").upper()
            etype = "http_crawler" if self._same_domain(n) else "http_crawler_outbound"
            await self.store.upsert(n, method, etype, exposure="external")
        for tag in soup.find_all("script", src=True):
            src = self._norm(tag["src"], url)
            if src and self._same_domain(src) and src not in self.visited:
                queue.append(src)
        for script in soup.find_all("script", src=False):
            if script.string:
                await self._extract_js(script.string, url)
        for tag in soup.find_all(True):
            for attr in ["data-url", "data-api", "data-endpoint", "data-href",
                         "data-action", "hx-get", "hx-post", "hx-put", "hx-delete"]:
                val = tag.get(attr, "")
                if val and isinstance(val, str):
                    n = self._norm(val, url)
                    if n and not _is_noisy(n):
                        etype = "http_crawler" if self._same_domain(n) else "http_crawler_outbound"
                        await self.store.upsert(n, "GET", etype)

    async def _extract_js(self, js, source):
        for pat in JS_PATTERNS:
            try:
                for match in re.findall(pat, js):
                    if isinstance(match, tuple):
                        match = next((m for m in match if m and (m.startswith("/") or m.startswith("http"))), None)
                    if not match:
                        continue
                    match = match.strip().rstrip("?&,;")
                    if len(match) < 3 or match in ("/", "#", "//"):
                        continue
                    if _is_noisy(match):
                        continue
                    if match.startswith("http"):
                        etype = "js_extract" if self._same_domain(match) else "js_extract_outbound"
                        await self.store.upsert(match, "UNKNOWN", etype,
                                                evidence={"js_source": source})
                    elif match.startswith("/"):
                        full = f"{self.domain}{match}"
                        await self.store.upsert(full, "UNKNOWN", "js_extract",
                                                evidence={"js_source": source})
            except Exception:
                pass

    async def _js_crawl(self):
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return
        max_pages = min(self.cfg.get("max_pages", 300), 100)
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage",
                          "--ignore-certificate-errors", "--disable-web-security"],
                )
                context = await browser.new_context(
                    user_agent=USER_AGENT, ignore_https_errors=True)
                visited_js = set()
                queue = [self.domain]
                count = 0
                while queue and count < max_pages:
                    url = queue.pop(0)
                    if url in visited_js:
                        continue
                    visited_js.add(url)
                    count += 1
                    page = None
                    try:
                        page = await context.new_page()
                        intercepted = []

                        async def handle_req(req):
                            ru = req.url
                            rp = urllib.parse.urlparse(ru).path
                            if self._api_like(rp) and not _is_noisy(ru):
                                intercepted.append((ru, req.method))

                        page.on("request", lambda r: asyncio.ensure_future(handle_req(r)))
                        try:
                            await page.goto(url, timeout=20000, wait_until="networkidle")
                        except Exception:
                            try:
                                await page.goto(url, timeout=20000, wait_until="domcontentloaded")
                                await page.wait_for_timeout(3000)
                            except Exception:
                                pass
                        for ru, rm in intercepted:
                            etype = "playwright_intercept" if self._same_domain(ru) else "playwright_intercept_outbound"
                            await self.store.upsert(ru, rm, etype,
                                                    evidence={"detected_by": "playwright_network_intercept"})
                        hrefs = await page.evaluate(
                            "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)")
                        for href in hrefs:
                            n = self._norm(href, url)
                            if n and self._same_domain(n) and n not in visited_js:
                                queue.append(n)
                    except Exception:
                        pass
                    finally:
                        if page:
                            try:
                                await page.close()
                            except Exception:
                                pass
                await context.close()
                await browser.close()
        except Exception:
            pass

    async def _bruteforce(self, client):
        if not self.wordlist:
            return
        print(f"    Brute-forcing {len(self.wordlist):,} paths...")
        BATCH = 500
        found = 0
        for i in range(0, len(self.wordlist), BATCH):
            batch = self.wordlist[i:i + BATCH]
            tasks = [self._probe_path(client, p) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            found += sum(1 for r in results if r)
            done = min(i + BATCH, len(self.wordlist))
            print(f"      {done:,}/{len(self.wordlist):,} — {found} live", end="\r")
        print(f"      Brute-force: {found} confirmed paths")

    async def _probe_path(self, client, path):
        # Skip Apache dotfile variants and plain HTML paths — not API endpoints
        if _is_dotfile_noise(path):
            return False

        url = f"{self.domain}{path}"
        resp = await client.get(url, allow_redirects=False)
        if not resp or resp.status_code in (404, 410):
            return False
        if self.baseline.is_fp(resp):
            return False
        if self.baseline.is_wildcard and resp.status_code == self.baseline._wildcard_status:
            return False
        allowed = await self._probe_methods(client, url)
        await self.store.upsert(
            url, "GET", "brute_force",
            status_code=resp.status_code,
            content_type=resp.headers.get("Content-Type", "").split(";")[0].strip(),
            response_size_bytes=len(resp.content),
            allowed_methods=allowed,
            exposure="external",
        )
        return True

    async def _probe_methods(self, client, url):
        results = await asyncio.gather(*[self._try_method(client, url, m) for m in HTTP_METHODS],
                                       return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _try_method(self, client, url, method):
        try:
            resp = await client.request(method, url, allow_redirects=False)
            if not resp or self.baseline.is_fp(resp):
                return None
            if resp.status_code not in (404, 405, 501, 400):
                r = {"method": method, "status_code": resp.status_code}
                if resp.status_code == 403:
                    r["note"] = "forbidden_but_exists"
                return r
        except Exception:
            pass
        return None

    async def _graphql(self, client):
        for path in GRAPHQL_PATHS:
            url = f"{self.domain}{path}"
            resp = await client.post(url,
                                     data='{"query":"{__typename}"}',
                                     headers={"Content-Type": "application/json"})
            if not resp or resp.status_code in (404, 405, 410):
                continue
            try:
                data = resp.json()
                if "data" not in data and "errors" not in data:
                    continue
            except Exception:
                continue
            ops = await self._graphql_introspect(client, url)
            await self.store.upsert(url, "POST", "graphql_probe",
                                    status_code=resp.status_code,
                                    tags=["graphql"],
                                    evidence={"introspection_enabled": len(ops) > 0,
                                              "operations_count": len(ops),
                                              "operations": ops[:50]})
            for op in ops:
                await self.store.upsert(f"{url}#{op['name']}", "POST", "graphql_operation",
                                        tags=["graphql", op.get("kind", "query")],
                                        evidence={"operation": op})

    async def _graphql_introspect(self, client, url):
        ops = []
        try:
            resp = await client.post(url,
                                     data=f'{{"query":"{GRAPHQL_INTROSPECTION}"}}',
                                     headers={"Content-Type": "application/json"})
            if not resp:
                return ops
            data = resp.json()
            schema = data.get("data", {}).get("__schema", {})
            qt = (schema.get("queryType") or {}).get("name")
            mt = (schema.get("mutationType") or {}).get("name")
            root_names = {n for n in [qt, mt] if n}
            for t in schema.get("types", []):
                if not t.get("name") or t["name"].startswith("__"):
                    continue
                if t["name"] not in root_names:
                    continue
                kind = "query" if t["name"] == qt else "mutation"
                for f in (t.get("fields") or []):
                    ops.append({"name": f["name"], "kind": kind})
        except Exception:
            pass
        return ops

    async def _fetch_specs(self, client):
        import json, yaml
        for path in SPEC_PATHS:
            url = f"{self.domain}{path}"
            resp = await client.get(url)
            if not resp or resp.status_code != 200:
                continue
            spec = None
            try:
                spec = json.loads(resp.text)
            except Exception:
                try:
                    spec = yaml.safe_load(resp.text)
                except Exception:
                    continue
            if not spec or "paths" not in spec:
                continue
            for sp_path, methods in spec.get("paths", {}).items():
                if isinstance(methods, dict):
                    for method in methods.keys():
                        if method.lower() in [m.lower() for m in HTTP_METHODS]:
                            full = f"{self.domain}{sp_path}"
                            await self.store.upsert(full, method.upper(), "openapi_spec",
                                                    baseline_status="in_spec",
                                                    evidence={"spec_url": url})
                            self._spec_endpoints.add(sp_path)

    async def _subdomains(self):
        root = self.parsed.netloc.lower().lstrip("www.").split(":")[0]
        parts = root.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
        tasks = [self._resolve_subdomain(sub, root) for sub in SUBDOMAINS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _resolve_subdomain(self, sub, root):
        fqdn = f"{sub}.{root}"
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            url = f"{self.parsed.scheme}://{fqdn}"
            await self.store.upsert(url, "GET", "subdomain_discovery",
                                    tags=["subdomain"],
                                    evidence={"fqdn": fqdn})
        except Exception:
            pass