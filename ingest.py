import json
import os
from datetime import datetime
from sqlalchemy.orm import Session

from db_models import (
    Engagement, ApiEndpoint, DiscoverySource, OWASPFinding,
    OWASPConformance, SecretFinding, OutboundApi, OutboundDependency,
    PackageDependency, CVEFinding, ScanPhaseLog, ShadowRogueRegister,
)


def _parse_dt(val):
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00").replace("+00:00", ""))
    except Exception:
        return None


def _risk_band(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"


def _safe_exposure(val: str) -> str:
    if val in ("External", "Internal"):
        return val
    if val and val.lower() == "external":
        return "External"
    return "External"


def _safe_risk(val: str) -> str:
    if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return val
    return "MEDIUM"


def _safe_sensitivity(val: str) -> str:
    if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        return val
    return "UNKNOWN"


def _safe_classification(val: str) -> str:
    if val in ("Valid", "Shadow", "New", "Rogue", "UNCLASSIFIED"):
        return val
    return "UNCLASSIFIED"


def _safe_severity_owasp(val: str) -> str:
    if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return val
    return "INFO"


def _safe_severity_secret(val: str) -> str:
    if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return val
    return "CRITICAL"


def ingest_scan_output(
    db:            Session,
    output_path:   str,
    engagement_id: int,
) -> dict:
    if not os.path.exists(output_path):
        raise FileNotFoundError(f"Output file not found: {output_path}")

    with open(output_path, "r", encoding="utf-8") as f:
        body = json.load(f)

    engagement = db.query(Engagement).filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        raise ValueError(f"Engagement {engagement_id} not found or inactive")

    summary          = body.get("summary", {})
    exec_summary     = body.get("executive_summary", {})
    key_metrics      = exec_summary.get("key_metrics", {})
    bom              = body.get("api_bom", {})
    tech_stack       = bom.get("tech_stack", {})
    inbound_outbound = body.get("inbound_outbound_classification", {})
    outbound_info    = inbound_outbound.get("outbound_apis", {})
    sensitivity      = summary.get("data_sensitivity", {})

    engagement.OverallRisk           = exec_summary.get("overall_risk", "UNKNOWN")
    engagement.Narrative             = exec_summary.get("narrative")
    engagement.TotalApis             = summary.get("total", 0)
    engagement.InboundApiCount       = summary.get("inbound_api_count", 0)
    engagement.OutboundApiCount      = summary.get("outbound_api_count", 0)
    engagement.OutboundExternalCount = summary.get("outbound_external_count", outbound_info.get("external", 0))
    engagement.OutboundInternalCount = summary.get("outbound_internal_count", outbound_info.get("internal", 0))
    engagement.ValidCount            = summary.get("Valid", 0)
    engagement.ShadowCount           = summary.get("Shadow", 0)
    engagement.NewCount              = summary.get("New", 0)
    engagement.RogueCount            = summary.get("Rogue", 0)
    engagement.UnclassifiedCount     = summary.get("UNCLASSIFIED", 0)
    engagement.SecretsCount          = summary.get("secrets_count", 0)
    engagement.OWASPFindingsTotal    = summary.get("owasp_findings_total", 0)
    engagement.InferredOWASPFindings = summary.get("inferred_owasp_findings", 0)
    engagement.LiveOWASPFindings     = summary.get("live_owasp_findings", 0)
    engagement.CVEFindingsTotal      = summary.get("cve_findings_total", 0)
    engagement.HighCriticalRiskCount = summary.get("high_critical_risk_count", key_metrics.get("high_critical_risk_endpoints", 0))
    engagement.EndpointsWithoutAuth  = summary.get("endpoints_without_auth", key_metrics.get("endpoints_without_auth", 0))
    engagement.ExternalIntegrations  = summary.get("external_integrations", key_metrics.get("external_integrations", 0))
    engagement.SensitivityCritical   = sensitivity.get("CRITICAL", 0)
    engagement.SensitivityHigh       = sensitivity.get("HIGH", 0)
    engagement.SensitivityMedium     = sensitivity.get("MEDIUM", 0)
    engagement.SensitivityLow        = sensitivity.get("LOW", 0)
    engagement.SensitivityUnknown    = sensitivity.get("UNKNOWN", 0)
    engagement.TechStackRuntime      = tech_stack.get("runtime")
    engagement.TechStackLanguage     = tech_stack.get("language")
    engagement.TechStackFramework    = tech_stack.get("framework")
    engagement.TechStackFrontend     = tech_stack.get("frontend")
    db.flush()

    endpoint_url_to_id: dict[str, int] = {}
    shadow_rogue_rows = []

    for ep in body.get("all_endpoints", []):
        url = ep.get("endpoint") or ep.get("url")
        if not url:
            continue

        score = int(ep.get("risk_score", 0) or 0)

        endpoint_row = ApiEndpoint(
            EngagementId=engagement_id,
            ApiDirection=ep.get("api_direction", "inbound"),
            EndpointUrl=url,
            HttpMethod=(ep.get("method") or "UNKNOWN")[:20],
            Classification=_safe_classification(ep.get("classification")),
            RiskScore=score,
            RiskBand=_risk_band(score),
            AuthType=(ep.get("auth_type") or "")[:100] or None,
            DataSensitivity=_safe_sensitivity(ep.get("data_sensitivity")),
            Exposure=(ep.get("exposure") or "")[:50] or None,
            Environment=(ep.get("environment") or "")[:100] or None,
            FunctionalModule=(ep.get("functional_module") or "")[:200] or None,
            FunctionalType=(ep.get("functional_type") or "")[:100] or None,
            ApiVersion=(ep.get("api_version") or "")[:20] or None,
            TechStack=(ep.get("tech_stack") or "")[:100] or None,
            InferredOwner=(ep.get("inferred_owner") or "")[:200] or None,
            Owner=(ep.get("owner") or "")[:200] or None,
            BaselineStatus=(ep.get("baseline_status") or "")[:100] or None,
            StatusCode=ep.get("status_code"),
            ContentType=(ep.get("content_type") or "")[:100] or None,
            ResponseSizeBytes=ep.get("response_size_bytes"),
            Remediation=ep.get("remediation"),
            SourceFile=ep.get("source_file"),
            FirstSeen=_parse_dt(ep.get("first_seen")),
            LastSeen=_parse_dt(ep.get("last_seen")),
            IsActive=1,
        )
        db.add(endpoint_row)
        db.flush()

        endpoint_url_to_id[url] = endpoint_row.EndpointId

        for src in ep.get("discovered_by", []):
            db.add(DiscoverySource(
                EndpointId=endpoint_row.EndpointId,
                EngagementId=engagement_id,
                SourceName=str(src)[:100],
                IsActive=1,
            ))

        cls = _safe_classification(ep.get("classification"))
        if cls in ("Shadow", "Rogue"):
            shadow_rogue_rows.append(ShadowRogueRegister(
                EngagementId=engagement_id,
                EndpointId=endpoint_row.EndpointId,
                Classification=cls,
                RiskScore=score,
                ActionRequired=ep.get("remediation"),
                IsActive=1,
            ))

    db.bulk_save_objects(shadow_rogue_rows)
    db.flush()

    owasp_rows = []
    for f in body.get("owasp_findings", []):
        endpoint_url = f.get("endpoint") or f.get("endpoint_url")
        endpoint_id  = endpoint_url_to_id.get(endpoint_url) if endpoint_url else None
        owasp_rows.append(OWASPFinding(
            EndpointId=endpoint_id,
            EngagementId=engagement_id,
            Category=(f.get("category") or "")[:20] or None,
            CategoryName=(f.get("name") or "")[:200] or None,
            Finding=f.get("finding"),
            Severity=_safe_severity_owasp(f.get("severity")),
            Source=(f.get("source") or "inferred")[:50],
            Remediation=f.get("remediation"),
            EndpointUrl=endpoint_url,
            IsActive=1,
        ))
    db.bulk_save_objects(owasp_rows)
    db.flush()

    conformance_rows = [
        OWASPConformance(
            EngagementId=engagement_id,
            OWASPId=(c.get("owasp_id") or "")[:10] or None,
            Name=(c.get("name") or "")[:200] or None,
            Status=(c.get("status") or "")[:50] or None,
            AffectedCount=c.get("affected_count", 0),
            Note=c.get("note"),
            ConformanceLevel=(c.get("conformance_level") or "")[:100] or None,
            IsActive=1,
        )
        for c in body.get("owasp_conformance_summary", [])
    ]
    db.bulk_save_objects(conformance_rows)
    db.flush()

    secret_rows = [
        SecretFinding(
            EngagementId=engagement_id,
            SecretType=(s.get("type") or "")[:100] or None,
            FilePath=s.get("file"),
            LineNumber=s.get("line"),
            Repo=s.get("repo"),
            MatchPreview=(s.get("match_preview") or "")[:200],
            Severity=_safe_severity_secret(s.get("severity")),
            Recommendation=s.get("recommendation"),
            IsActive=1,
        )
        for s in body.get("secrets_findings", [])
    ]
    db.bulk_save_objects(secret_rows)
    db.flush()

    outbound_api_rows = [
        OutboundApi(
            EngagementId=engagement_id,
            Url=a.get("url"),
            Host=(a.get("host") or "")[:255] or None,
            PathPrefix=(a.get("_path_prefix") or a.get("path_prefix") or "")[:255] or None,
            HttpMethod=(a.get("method") or "UNKNOWN")[:20],
            Integration=(a.get("integration") or "")[:200] or None,
            Category=(a.get("category") or "")[:100] or None,
            Exposure=_safe_exposure(a.get("exposure")),
            Risk=_safe_risk(a.get("risk")),
            AuthMethod=(a.get("auth_method") or "")[:100] or None,
            SourceFiles=str(a.get("source_files", [])),
            LineNumber=a.get("line"),
            Repo=a.get("repo"),
            OWASPReference=(a.get("owasp_reference") or "")[:100] or None,
            Recommendation=a.get("recommendation"),
            IsActive=1,
        )
        for a in outbound_info.get("apis", [])
    ]
    db.bulk_save_objects(outbound_api_rows)
    db.flush()

    dep_rows = [
        OutboundDependency(
            EngagementId=engagement_id,
            Integration=(d.get("integration") or "")[:200] or None,
            Category=(d.get("category") or "")[:100] or None,
            Exposure=_safe_exposure(d.get("exposure")),
            Risk=_safe_risk(d.get("risk")),
            Recommendation=d.get("recommendation"),
            IsActive=1,
        )
        for d in body.get("outbound_dependencies", [])
    ]
    db.bulk_save_objects(dep_rows)
    db.flush()

    package_rows = [
        PackageDependency(
            EngagementId=engagement_id,
            Name=(p.get("name") or "")[:255] or None,
            Version=(p.get("version") or "")[:100] or None,
            Type=(p.get("type") or "")[:100] or None,
            Ecosystem=(p.get("ecosystem") or "")[:100] or None,
            IsActive=1,
        )
        for p in bom.get("package_dependencies", [])
    ]
    db.bulk_save_objects(package_rows)
    db.flush()

    cve_rows = [
        CVEFinding(
            EngagementId=engagement_id,
            CVENumber=(c.get("cve") or "")[:50] or None,
            Description=c.get("desc") or c.get("description"),
            Severity=(c.get("severity") or "")[:50] or None,
            CVSS=c.get("cvss"),
            EndpointCount=c.get("endpoint_count", 0),
            IsActive=1,
        )
        for c in body.get("cve_findings_summary", [])
    ]
    db.bulk_save_objects(cve_rows)
    db.flush()

    engagement.CompletedAt = datetime.utcnow()
    db.commit()

    return {
        "engagement_id":   engagement_id,
        "endpoints":       len(body.get("all_endpoints", [])),
        "owasp_findings":  len(owasp_rows),
        "conformance":     len(conformance_rows),
        "secrets":         len(secret_rows),
        "outbound_apis":   len(outbound_api_rows),
        "dependencies":    len(dep_rows),
        "packages":        len(package_rows),
        "cve_findings":    len(cve_rows),
        "shadow_rogue":    len(shadow_rogue_rows),
    }
