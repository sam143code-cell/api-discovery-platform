import os
import re
import json
from typing import Set, List, Dict
from datetime import datetime


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
        from urllib.parse import urlparse
        path = urlparse(url_or_path).path
    except Exception:
        path = url_or_path
    path = path.lower().rstrip("/")
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
        self._authorized_paths: Set[str] = set()
        self._gateway_paths: Set[str] = set()
        self._spec_paths: Set[str] = set()
        self._baseline_paths: Set[str] = set()
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

        # 1. Load gateway exports
        if cfg.get("use_gateway_export", True):
            gw_dir = inputs.get("gateway_exports_dir", "inputs/gateway_exports")
            if os.path.exists(gw_dir):
                for fname in os.listdir(gw_dir):
                    fpath = os.path.join(gw_dir, fname)
                    paths = self._extract_paths_from_file(fpath)
                    self._gateway_paths.update(paths)
                    self._authorized_paths.update(paths)

        # 2. Load OpenAPI specs
        if cfg.get("use_openapi_specs", True):
            spec_dir = inputs.get("openapi_specs_dir", "inputs/openapi_specs")
            if os.path.exists(spec_dir):
                for fname in os.listdir(spec_dir):
                    fpath = os.path.join(spec_dir, fname)
                    paths = self._extract_paths_from_file(fpath)
                    self._spec_paths.update(paths)
                    self._authorized_paths.update(paths)

        # 3. Load baseline JSON
        if cfg.get("use_baseline_json", True):
            baseline_file = inputs.get("baseline_file", "inputs/baseline.json")
            if os.path.exists(baseline_file):
                try:
                    with open(baseline_file) as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                self._baseline_paths.add(_normalize_path(item))
                            elif isinstance(item, dict):
                                ep = item.get("endpoint") or item.get("path") or item.get("url") or ""
                                if ep:
                                    self._baseline_paths.add(_normalize_path(ep))
                    elif isinstance(data, dict):
                        for ep in data.get("endpoints", data.get("apis", [])):
                            if isinstance(ep, str):
                                self._baseline_paths.add(_normalize_path(ep))
                            elif isinstance(ep, dict):
                                p = ep.get("endpoint") or ep.get("path") or ep.get("url") or ""
                                if p:
                                    self._baseline_paths.add(_normalize_path(p))
                    self._authorized_paths.update(self._baseline_paths)
                except Exception as e:
                    print(f"    Baseline load error: {e}")

        # Also include APIs discovered by gateway sources as authorized
        for entry in self.store.all():
            if "gateway_registered" in entry.tags:
                self._authorized_paths.add(_normalize_path(entry.endpoint))

        norm_gateway = {_normalize_path(p) for p in self._gateway_paths}
        norm_spec = {_normalize_path(p) for p in self._spec_paths}
        self._gateway_paths_norm = norm_gateway
        self._spec_paths_norm = norm_spec
        self._authorized_norm = {_normalize_path(p) for p in self._authorized_paths}

        print(f"    Baseline: {len(self._authorized_norm)} authorized paths "
              f"({len(self._gateway_paths_norm)} gateway, "
              f"{len(self._spec_paths_norm)} spec, "
              f"{len(self._baseline_paths)} registry)")

    def _extract_paths_from_file(self, fpath: str) -> Set[str]:
        paths = set()
        try:
            with open(fpath) as f:
                if fpath.endswith(".json"):
                    data = json.load(f)
                else:
                    import yaml
                    data = yaml.safe_load(f)
            if isinstance(data, dict) and "paths" in data:
                paths.update(_normalize_path(p) for p in data["paths"].keys())
            elif isinstance(data, dict) and "services" in data:
                for svc in data.get("services", []):
                    for route in svc.get("routes", []):
                        for p in (route.get("paths") or ["/"]):
                            paths.add(_normalize_path(p))
        except Exception:
            pass
        return paths

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
        norm = _normalize_path(endpoint)

        # ROGUE: matches rogue patterns AND not in authorized baseline
        for pat in self._rogue_patterns:
            if pat.search(endpoint):
                if norm not in self._authorized_norm:
                    return "Rogue"

        # VALID: in authorized baseline (gateway or spec or registry)
        if norm in self._authorized_norm:
            # NEW: in baseline but appeared recently
            if self._new_since:
                try:
                    first_seen = datetime.fromisoformat(entry.first_seen.rstrip("Z"))
                    if first_seen > self._new_since:
                        return "New"
                except Exception:
                    pass
            return "Valid"

        # Check if discovered only from spec (it's documented = Valid)
        if "in_spec" in (entry.baseline_status or ""):
            return "Valid"

        # Shadow: exists in traffic/code/scan but not in any authorized baseline
        return "Shadow"

    def _baseline_status(self, entry) -> str:
        norm = _normalize_path(entry.endpoint)
        statuses = []
        if norm in self._gateway_paths_norm:
            statuses.append("in_gateway")
        if norm in self._spec_paths_norm:
            statuses.append("in_spec")
        if norm in self._baseline_paths:
            statuses.append("in_registry")
        if not statuses:
            statuses.append("not_documented")
        return ",".join(statuses)
