import os
import re
import json
from typing import Set, List, Dict, Tuple
from datetime import datetime
from urllib.parse import urlparse

ROGUE_DEFAULT_PATTERNS = [
    r"/debug", r"/internal", r"/admin", r"/.env",
    r"/actuator", r"/phpinfo", r"/server-status",
    r"/\.git", r"/wp-admin", r"/phpmyadmin",
    r"/console", r"/trace", r"/heapdump",
    r"/swagger-ui\.html", r"/api-docs",
]

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

def _normalize_path(url_or_path: str) -> str:
    try:
        path = urlparse(url_or_path).path
    except Exception:
        path = url_or_path
    path = path.lower().rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/\d{1,20}(?=/|$)", "/{id}", path)
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
        "/{uuid}", path,
    )
    path = re.sub(r"/[a-z0-9]{24,}(?=/|$)", "/{hash}", path)
    return path

def _path_matches(discovered: str, spec_paths: Set[str]) -> bool:
    norm = _normalize_path(discovered)
    if norm in spec_paths:
        return True
    disc_parts = norm.split("/")
    for sp in spec_paths:
        sp_parts = sp.split("/")
        if len(sp_parts) != len(disc_parts):
            continue
        if all(s == d or re.match(r"^\{.+\}$", s) for s, d in zip(sp_parts, disc_parts)):
            return True
    return False

class Classifier:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg
        self.class_cfg = cfg.get("classification", {})
        self._authorized_endpoints: Set[Tuple[str, str]] = set()
        self._gateway_endpoints: Set[Tuple[str, str]] = set()
        self._spec_endpoints: Set[Tuple[str, str]] = set()
        self._baseline_endpoints: Set[Tuple[str, str]] = set()
        self._rogue_patterns: List[re.Pattern] = []
        self._new_since: datetime = None

    async def run(self):
        print("    Loading governance baseline...")
        self._load_baseline()
        self._compile_rogue_patterns()

        new_since_str = self.class_cfg.get("new_api_since", "")
        if new_since_str:
            try:
                self._new_since = datetime.fromisoformat(new_since_str)
            except Exception:
                pass

        entries = self.store.all()
        print(f"    Classifying {len(entries)} endpoints...")

        for entry in entries:
            cls = self._classify(entry)
            entry.classification = cls
            entry.baseline_status = self._baseline_status(entry)

        counts = self.store.count()
        print(f"    Classification: Valid={counts.get('Valid',0)} "
              f"Shadow={counts.get('Shadow',0)} "
              f"New={counts.get('New',0)} "
              f"Rogue={counts.get('Rogue',0)}")

    def _load_baseline(self):
        cfg = self.class_cfg
        inputs = self.cfg.get("inputs", {})

        if cfg.get("use_gateway_export", True):
            gw_dir = inputs.get("gateway_exports_dir", "inputs/gateway_exports")
            if os.path.exists(gw_dir):
                for fname in os.listdir(gw_dir):
                    fpath = os.path.join(gw_dir, fname)
                    eps = self._extract_endpoints_from_file(fpath)
                    self._gateway_endpoints.update(eps)
                    self._authorized_endpoints.update(eps)

        if cfg.get("use_openapi_specs", True):
            spec_dir = inputs.get("openapi_specs_dir", "inputs/openapi_specs")
            if os.path.exists(spec_dir):
                for fname in os.listdir(spec_dir):
                    fpath = os.path.join(spec_dir, fname)
                    eps = self._extract_endpoints_from_file(fpath)
                    self._spec_endpoints.update(eps)
                    self._authorized_endpoints.update(eps)

        if cfg.get("use_baseline_json", True):
            baseline_file = inputs.get("baseline_file", "inputs/baseline.json")
            if os.path.exists(baseline_file):
                try:
                    with open(baseline_file) as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            self._add_baseline_item(item)
                    elif isinstance(data, dict):
                        for item in data.get("endpoints", data.get("apis", [])):
                            self._add_baseline_item(item)
                    self._authorized_endpoints.update(self._baseline_endpoints)
                except Exception as e:
                    print(f"    Baseline load error: {e}")

        for entry in self.store.all():
            if "gateway_registered" in getattr(entry, "tags", []):
                m = getattr(entry, "method", "ALL").upper()
                p = _normalize_path(entry.endpoint)
                self._authorized_endpoints.add((m, p))

        print(f"    Baseline: {len(self._authorized_endpoints)} authorized endpoints "
              f"({len(self._gateway_endpoints)} gateway, "
              f"{len(self._spec_endpoints)} spec, "
              f"{len(self._baseline_endpoints)} registry)")

    def _add_baseline_item(self, item):
        if isinstance(item, str):
            self._baseline_endpoints.add(("ALL", _normalize_path(item)))
        elif isinstance(item, dict):
            p = item.get("endpoint") or item.get("path") or item.get("url") or ""
            if p:
                norm_p = _normalize_path(p)
                methods = item.get("methods", [item.get("method", "ALL")])
                if isinstance(methods, str):
                    methods = [methods]
                for m in methods:
                    self._baseline_endpoints.add((m.upper(), norm_p))

    def _extract_endpoints_from_file(self, fpath: str) -> Set[Tuple[str, str]]:
        endpoints = set()
        try:
            with open(fpath) as f:
                if fpath.endswith(".json"):
                    data = json.load(f)
                else:
                    import yaml
                    data = yaml.safe_load(f)
            if isinstance(data, dict) and "paths" in data:
                for p, methods_dict in data["paths"].items():
                    norm_p = _normalize_path(p)
                    if isinstance(methods_dict, dict):
                        for m in methods_dict.keys():
                            if m.upper() in HTTP_METHODS:
                                endpoints.add((m.upper(), norm_p))
                    else:
                        endpoints.add(("ALL", norm_p))
            elif isinstance(data, dict) and "services" in data:
                for svc in data.get("services", []):
                    for route in svc.get("routes", []):
                        methods = route.get("methods", ["ALL"])
                        for p in (route.get("paths") or ["/"]):
                            norm_p = _normalize_path(p)
                            for m in methods:
                                endpoints.add((m.upper(), norm_p))
        except Exception:
            pass
        return endpoints

    def _compile_rogue_patterns(self):
        default = ROGUE_DEFAULT_PATTERNS
        custom = self.class_cfg.get("rogue_patterns", [])
        all_patterns = default + custom
        for p in all_patterns:
            try:
                self._rogue_patterns.append(re.compile(p, re.IGNORECASE))
            except Exception:
                pass

    def _classify(self, entry) -> str:
        endpoint = entry.endpoint
        method = getattr(entry, "method", "ALL").upper()
        first_seen_str = getattr(entry, "first_seen", "")

        if self._new_since and first_seen_str:
            try:
                fs_clean = first_seen_str.replace("Z", "+00:00")
                if datetime.fromisoformat(fs_clean) > self._new_since:
                    return "New"
            except Exception:
                pass

        auth_paths_for_method = {
            p for m, p in self._authorized_endpoints 
            if m == "ALL" or m == method
        }

        if _path_matches(endpoint, auth_paths_for_method):
            return "Valid"

        for pat in self._rogue_patterns:
            if pat.search(endpoint):
                return "Rogue"

        return "Shadow"

    def _baseline_status(self, entry) -> str:
        endpoint = entry.endpoint
        method = getattr(entry, "method", "ALL").upper()

        def is_in(ep_set):
            paths = {p for m, p in ep_set if m == "ALL" or m == method}
            return _path_matches(endpoint, paths)

        statuses = []
        if is_in(self._gateway_endpoints):
            statuses.append("in_gateway")
        if is_in(self._spec_endpoints):
            statuses.append("in_spec")
        if is_in(self._baseline_endpoints):
            statuses.append("in_registry")
            
        if not statuses:
            statuses.append("not_documented")
            
        return ",".join(statuses)