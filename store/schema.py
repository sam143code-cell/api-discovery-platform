
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class APIEntry:
   
    endpoint: str
    method: str = "UNKNOWN"
    classification: str = "UNCLASSIFIED"  


    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    
    discovered_by: List[str] = field(default_factory=list)

    
    auth_type: str = "UNKNOWN"
    data_sensitivity: str = "LOW"
    exposure: str = "unknown"         
    environment: str = "unknown"      

    
    owasp_flags: List[Dict] = field(default_factory=list)
    cve_findings: List[Dict] = field(default_factory=list)

    
    risk_score: int = 0

   
    owner: str = "unknown"
    inferred_owner: str = "Pending Triage"   
    baseline_status: str = "unknown"         

   
    status_code: Optional[int] = None
    content_type: str = ""
    response_size_bytes: Optional[int] = None
    allowed_methods: List[Dict] = field(default_factory=list)

    
    parameters: List[Dict] = field(default_factory=list)
    headers_observed: Dict = field(default_factory=dict)

   
    functional_module: str = "Uncategorized"  
    api_version: Optional[str] = None         
    functional_type: str = "unknown"           
    tech_stack: str = "unknown"               
    upstream_services: List[str] = field(default_factory=list)  
    downstream_dependencies: List[str] = field(default_factory=list)  

    
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