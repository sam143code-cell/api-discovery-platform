import os
import re
import gzip
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

# ── Format signatures ──────────────────────────────────────────────────────────
NGINX_CLF   = re.compile(r'(?P<ip>[\d\.]+)\s+-\s+-\s+\[.+?\]\s+"(?P<method>\w+)\s+(?P<path>[^\s"]+)\s+HTTP[^"]*"\s+(?P<status>\d+)\s+(?P<size>\d+)(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?')
NGINX_JSON  = None   # detected dynamically
APACHE_CLF  = NGINX_CLF
KONG_LOG    = re.compile(r'"request":\{"uri":"(?P<path>[^"]+)","method":"(?P<method>[^"]+)".*?"status":(?P<status>\d+)')
AWS_ALB     = re.compile(r'\S+\s+\S+\s+\S+\s+\S+:\d+\s+\S+:\d+\s+[\d\.]+\s+[\d\.]+\s+[\d\.]+\s+(?P<status>\d+)\s+\d+\s+\d+\s+\d+\s+"(?P<method>\w+)\s+(?P<url>https?://[^\s]+)\s+HTTP')
CF_ACCESS   = re.compile(r'"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"\s+"(?P<path>/[^"]+)".*?"(?P<status>\d{3})"')
W3C_IIS     = re.compile(r'(?P<date>\S+)\s+(?P<time>\S+)\s+\S+\s+\S+\s+(?P<method>\w+)\s+(?P<path>/[^\s]+)\s+\S+\s+\d+\s+\d+\s+(?P<status>\d+)')


def _detect_format(sample_lines: List[str]) -> str:
    for line in sample_lines:
        line = line.strip()
        if not line:
            continue
        # JSON log
        if line.startswith("{"):
            try:
                d = json.loads(line)
                if "request" in d and isinstance(d["request"], dict):
                    return "kong_json"
                if "method" in d and "path" in d:
                    return "json_flat"
                if "request" in d and "uri" in str(d.get("request", "")):
                    return "kong_json"
                if "cs-method" in d or "cs-uri-stem" in d:
                    return "w3c_json"
                return "json_generic"
            except Exception:
                pass
        # W3C IIS
        if line.startswith("#Fields:") or "cs-method" in line:
            return "w3c"
        # AWS ALB
        if re.match(r'^\w+\s+\d{4}-\d{2}-\d{2}T', line) and "HTTP/1" in line:
            return "aws_alb"
        # Nginx/Apache CLF
        if NGINX_CLF.match(line):
            return "clf"
        # Cloudflare
        if '"RayID"' in line or '"rayId"' in line or ('"status"' in line and '"method"' in line):
            return "cloudflare_json"
    return "unknown"


def _parse_clf(line: str) -> Optional[Dict]:
    m = NGINX_CLF.match(line.strip())
    if not m:
        return None
    path = m.group("path").split("?")[0]
    return {
        "method": m.group("method").upper(),
        "path": path,
        "status": int(m.group("status")),
        "client_ip": m.group("ip"),
        "user_agent": m.group("ua") if m.lastindex and m.lastindex >= 6 else "",
    }


def _parse_json_flat(line: str) -> Optional[Dict]:
    try:
        d = json.loads(line)
        path = (d.get("path") or d.get("uri") or d.get("url") or d.get("request_path") or "").split("?")[0]
        method = (d.get("method") or d.get("http_method") or d.get("request_method") or "UNKNOWN").upper()
        status = int(d.get("status") or d.get("status_code") or d.get("response_status") or 0)
        auth = d.get("authorization") or d.get("auth_header") or d.get("headers", {}).get("authorization", "")
        return {
            "method": method, "path": path, "status": status,
            "client_ip": d.get("client_ip") or d.get("remote_addr") or d.get("ip") or "",
            "auth_header": auth,
            "user_agent": d.get("user_agent") or d.get("ua") or "",
            "consumer_id": d.get("consumer_id") or d.get("user_id") or d.get("client_id") or "",
        }
    except Exception:
        return None


def _parse_kong_json(line: str) -> Optional[Dict]:
    try:
        d = json.loads(line)
        req = d.get("request", {})
        resp = d.get("response", {})
        path = req.get("uri", "").split("?")[0]
        method = req.get("method", "UNKNOWN").upper()
        status = int(resp.get("status", 0))
        auth = req.get("headers", {}).get("authorization", "")
        consumer = d.get("consumer", {}).get("id", "") or d.get("authenticated_entity", {}).get("id", "")
        service = d.get("service", {}).get("name", "") or d.get("service", {}).get("host", "")
        return {
            "method": method, "path": path, "status": status,
            "auth_header": auth, "consumer_id": consumer,
            "service": service,
            "client_ip": d.get("client_ip") or req.get("headers", {}).get("x-forwarded-for", ""),
        }
    except Exception:
        return None


def _parse_aws_alb(line: str) -> Optional[Dict]:
    m = AWS_ALB.match(line.strip())
    if not m:
        return None
    from urllib.parse import urlparse
    parsed = urlparse(m.group("url"))
    return {
        "method": m.group("method").upper(),
        "path": parsed.path,
        "status": int(m.group("status")),
        "client_ip": "",
    }


def _parse_w3c(line: str, fields: List[str]) -> Optional[Dict]:
    if line.startswith("#"):
        return None
    parts = line.strip().split()
    if len(parts) < len(fields):
        return None
    d = dict(zip(fields, parts))
    path = d.get("cs-uri-stem", d.get("cs-uri", "")).split("?")[0]
    method = d.get("cs-method", "UNKNOWN").upper()
    status = int(d.get("sc-status", 0))
    return {"method": method, "path": path, "status": status, "client_ip": d.get("c-ip", "")}


def _parse_cloudflare_json(line: str) -> Optional[Dict]:
    try:
        d = json.loads(line)
        path = (d.get("ClientRequestPath") or d.get("request", {}).get("url", "")).split("?")[0]
        method = (d.get("ClientRequestMethod") or d.get("request", {}).get("method") or "UNKNOWN").upper()
        status = int(d.get("EdgeResponseStatus") or d.get("response", {}).get("status") or 0)
        return {"method": method, "path": path, "status": status,
                "client_ip": d.get("ClientIP", ""),
                "user_agent": d.get("ClientRequestUserAgent", "")}
    except Exception:
        return None


class LogAnalyzer:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg
        self._stats: Dict = {"files_processed": 0, "entries_parsed": 0, "endpoints_found": 0}

    async def run(self):
        import asyncio
        logs_dir = self.cfg.get("logs_dir", "inputs/logs")
        if not os.path.exists(logs_dir):
            print("    No logs directory found — skipping log analysis")
            return

        log_files = []
        for root, _, files in os.walk(logs_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if fname.endswith((".log", ".txt", ".gz", ".json", ".csv")):
                    log_files.append(fpath)

        if not log_files:
            print("    No log files found in inputs/logs/")
            return

        print(f"    Processing {len(log_files)} log file(s)...")
        for fpath in log_files:
            await asyncio.get_event_loop().run_in_executor(None, self._process_file, fpath)

        print(f"    Log analysis: {self._stats['entries_parsed']:,} entries → {self._stats['endpoints_found']} unique endpoints")

    def _process_file(self, fpath: str):
        import asyncio
        try:
            if fpath.endswith(".gz"):
                opener = gzip.open(fpath, "rt", encoding="utf-8", errors="ignore")
            else:
                opener = open(fpath, "r", encoding="utf-8", errors="ignore")

            with opener as f:
                lines = []
                for i, line in enumerate(f):
                    lines.append(line)
                    if i >= 20:
                        break

            fmt = _detect_format(lines)
            w3c_fields: List[str] = []

            if fpath.endswith(".gz"):
                opener = gzip.open(fpath, "rt", encoding="utf-8", errors="ignore")
            else:
                opener = open(fpath, "r", encoding="utf-8", errors="ignore")

            with opener as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # W3C fields header
                    if line.startswith("#Fields:"):
                        w3c_fields = line.replace("#Fields:", "").strip().split()
                        continue
                    if line.startswith("#"):
                        continue

                    entry = None
                    if fmt == "clf":
                        entry = _parse_clf(line)
                    elif fmt in ("json_flat", "json_generic"):
                        entry = _parse_json_flat(line)
                    elif fmt == "kong_json":
                        entry = _parse_kong_json(line)
                    elif fmt == "aws_alb":
                        entry = _parse_aws_alb(line)
                    elif fmt == "w3c":
                        entry = _parse_w3c(line, w3c_fields)
                    elif fmt == "cloudflare_json":
                        entry = _parse_cloudflare_json(line)
                    else:
                        # Try all parsers as fallback
                        for parser in [_parse_clf, _parse_json_flat, _parse_kong_json]:
                            entry = parser(line)
                            if entry:
                                break

                    if not entry or not entry.get("path"):
                        continue

                    self._stats["entries_parsed"] += 1
                    path = entry["path"]
                    method = entry.get("method", "UNKNOWN")
                    status = entry.get("status", 0)

                    loop = asyncio.new_event_loop()
                    try:
                        loop.run_until_complete(
                            self.store.upsert(
                                path, method, "log_analysis",
                                status_code=status if status else None,
                                evidence={
                                    "log_file": os.path.basename(fpath),
                                    "log_format": fmt,
                                    "consumer_id": entry.get("consumer_id", ""),
                                    "service": entry.get("service", ""),
                                },
                                auth_type=self._detect_auth(entry.get("auth_header", "")),
                                tags=["from_logs"],
                            )
                        )
                        self._stats["endpoints_found"] += 1
                    finally:
                        loop.close()

            self._stats["files_processed"] += 1

        except Exception as e:
            print(f"    Error processing {os.path.basename(fpath)}: {e}")

    def _detect_auth(self, auth_header: str) -> str:
        if not auth_header:
            return "UNKNOWN"
        auth_lower = auth_header.lower()
        if auth_lower.startswith("bearer "):
            return "Bearer JWT"
        if auth_lower.startswith("basic "):
            return "Basic Auth"
        if auth_lower.startswith("apikey ") or auth_lower.startswith("api-key "):
            return "API Key"
        if "oauth" in auth_lower:
            return "OAuth2"
        return "Other"
