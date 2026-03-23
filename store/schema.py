"""
store/schema.py
Extended APIEntry with:
  - functional_module: inferred from source file path
  - api_version: extracted from URL path
  - functional_type: inferred endpoint type (data, auth, admin, etc.)
  - inferred_owner: module-level owner placeholder for triage
  - owasp_flags now includes inferred flags, not just live-scan flags
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class APIEntry:
    # ── Core identification ────────────────────────────────────────────────
    endpoint: str
    method: str = "UNKNOWN"
    classification: str = "UNCLASSIFIED"  # Valid, Shadow, New, Rogue

    # ── Timestamps ────────────────────────────────────────────────────────
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    # ── Discovery ─────────────────────────────────────────────────────────
    discovered_by: List[str] = field(default_factory=list)

    # ── Security attributes ───────────────────────────────────────────────
    auth_type: str = "UNKNOWN"
    data_sensitivity: str = "LOW"
    exposure: str = "unknown"         # external, internal, partner
    environment: str = "unknown"      # production, staging, dev, uat

    # ── OWASP & CVE ───────────────────────────────────────────────────────
    owasp_flags: List[Dict] = field(default_factory=list)
    cve_findings: List[Dict] = field(default_factory=list)

    # ── Risk ─────────────────────────────────────────────────────────────
    risk_score: int = 0

    # ── Ownership & governance ────────────────────────────────────────────
    owner: str = "unknown"
    inferred_owner: str = "Pending Triage"   # NEW: module-level owner placeholder
    baseline_status: str = "unknown"         # in_spec, not_in_spec, in_gateway, not_in_gateway

    # ── HTTP metadata ─────────────────────────────────────────────────────
    status_code: Optional[int] = None
    content_type: str = ""
    response_size_bytes: Optional[int] = None
    allowed_methods: List[Dict] = field(default_factory=list)

    # ── API contract ──────────────────────────────────────────────────────
    parameters: List[Dict] = field(default_factory=list)
    headers_observed: Dict = field(default_factory=dict)

    # ── NEW: API metadata ──────────────────────────────────────────────────
    functional_module: str = "Uncategorized"   # e.g. "Vulnerability Management"
    api_version: Optional[str] = None          # e.g. "v1", "v2"
    functional_type: str = "unknown"           # data, auth, admin, upload, search, reporting
    tech_stack: str = "unknown"                # e.g. "Express.js / Node.js"
    upstream_services: List[str] = field(default_factory=list)   # known upstream callers
    downstream_dependencies: List[str] = field(default_factory=list)  # external services called

    # ── Evidence & tags ───────────────────────────────────────────────────
    evidence: Dict = field(default_factory=dict)
    raw_findings: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "classification": self.classification,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "discovered_by": self.discovered_by,
            "auth_type": self.auth_type,
            "data_sensitivity": self.data_sensitivity,
            "exposure": self.exposure,
            "environment": self.environment,
            "owasp_flags": self.owasp_flags,
            "cve_findings": self.cve_findings,
            "risk_score": self.risk_score,
            "owner": self.owner,
            "inferred_owner": self.inferred_owner,
            "baseline_status": self.baseline_status,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_size_bytes": self.response_size_bytes,
            "allowed_methods": self.allowed_methods,
            "parameters": self.parameters,
            "headers_observed": self.headers_observed,
            "functional_module": self.functional_module,
            "api_version": self.api_version,
            "functional_type": self.functional_type,
            "tech_stack": self.tech_stack,
            "upstream_services": self.upstream_services,
            "downstream_dependencies": self.downstream_dependencies,
            "evidence": self.evidence,
            "tags": self.tags,
        }