import base64
import json
import os
import shutil
import stat
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from urllib.parse import urlparse

from models   import ScanRequest, ScanAccepted, ScanResult, ScanStatus
from config   import build_cfg, REPO_CLONE_ROOT, SCANS_DIR
from scanner  import run_pipeline
from database import SessionLocal, get_db
from db_models import (
    Engagement, ApiEndpoint, DiscoverySource, OWASPFinding,
    OWASPConformance, SecretFinding, OutboundApi, OutboundDependency,
    PackageDependency, CVEFinding, ShadowRogueRegister,
)

try:
    from git import Repo, GitCommandError
    _GIT_AVAILABLE = True
except ImportError:
    _GIT_AVAILABLE = False

router = APIRouter()

_scan_registry: Dict[str, dict] = {}



def _handle_remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _clone_repo(username: str, access_token: str, url: str) -> dict:
    if not _GIT_AVAILABLE:
        return {"status": "error", "message": "gitpython not installed — pip install gitpython"}

    try:
        parsed   = urlparse(url)
        auth_url = (
            f"{parsed.scheme}://{username}:{access_token}@"
            f"{parsed.netloc}{parsed.path}"
        )
        repo_name   = parsed.path.split("/")[-1].replace(".git", "")
        target_path = os.path.join(REPO_CLONE_ROOT, repo_name)

        if os.path.exists(target_path):
            shutil.rmtree(target_path, onerror=_handle_remove_readonly)

        os.makedirs(REPO_CLONE_ROOT, exist_ok=True)
        Repo.clone_from(auth_url, target_path)

        return {"status": "success", "path": target_path, "repo_name": repo_name}

    except GitCommandError as exc:
        safe_msg = str(exc).replace(access_token, "****")
        return {"status": "error", "message": f"Git error: {safe_msg}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _decode_and_save_files(
    b64_contents: Optional[List[str]],
    filenames:    Optional[List[str]],
    dest_dir:     str,
    default_ext:  str,
) -> List[str]:
    if not b64_contents:
        return []

    os.makedirs(dest_dir, exist_ok=True)
    saved = []

    for idx, b64 in enumerate(b64_contents):
        if not b64:
            continue

        if filenames and idx < len(filenames) and filenames[idx]:
            fname = filenames[idx]
        else:
            fname = f"file_{idx + 1}{default_ext}"

        try:
            raw = base64.b64decode(b64)
        except Exception as exc:
            raise ValueError(f"Invalid base64 for file '{fname}': {exc}")

        dest_path = os.path.join(dest_dir, fname)
        with open(dest_path, "wb") as f:
            f.write(raw)
        saved.append(dest_path)

    return saved




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


def _safe_exposure(val):
    if val in ("External", "Internal"):
        return val
    if val and val.lower() == "external":
        return "External"
    return "External"


def _safe_risk(val):
    return val if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"


def _safe_sensitivity(val):
    return val if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") else "UNKNOWN"


def _safe_classification(val):
    return val if val in ("Valid", "Shadow", "New", "Rogue", "UNCLASSIFIED") else "UNCLASSIFIED"


def _safe_severity_owasp(val):
    return val if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO"


def _safe_severity_secret(val):
    return val if val in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "CRITICAL"


def _ingest(db: Session, output_path: str, engagement_id: int) -> dict:
    """
    Read api_discovery_full.json and write all 12 tables.
    Called directly inside the background task — no HTTP round-trip needed.
    """
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
        row = ApiEndpoint(
            EngagementId      = engagement_id,
            ApiDirection      = ep.get("api_direction", "inbound"),
            EndpointUrl       = url,
            HttpMethod        = (ep.get("method") or "UNKNOWN")[:20],
            Classification    = _safe_classification(ep.get("classification")),
            RiskScore         = score,
            RiskBand          = _risk_band(score),
            AuthType          = (ep.get("auth_type") or "")[:100] or None,
            DataSensitivity   = _safe_sensitivity(ep.get("data_sensitivity")),
            Exposure          = (ep.get("exposure") or "")[:50] or None,
            Environment       = (ep.get("environment") or "")[:100] or None,
            FunctionalModule  = (ep.get("functional_module") or "")[:200] or None,
            FunctionalType    = (ep.get("functional_type") or "")[:100] or None,
            ApiVersion        = (ep.get("api_version") or "")[:20] or None,
            TechStack         = (ep.get("tech_stack") or "")[:100] or None,
            InferredOwner     = (ep.get("inferred_owner") or "")[:200] or None,
            Owner             = (ep.get("owner") or "")[:200] or None,
            BaselineStatus    = (ep.get("baseline_status") or "")[:100] or None,
            StatusCode        = ep.get("status_code"),
            ContentType       = (ep.get("content_type") or "")[:100] or None,
            ResponseSizeBytes = ep.get("response_size_bytes"),
            Remediation       = ep.get("remediation"),
            SourceFile        = ep.get("source_file"),
            FirstSeen         = _parse_dt(ep.get("first_seen")),
            LastSeen          = _parse_dt(ep.get("last_seen")),
            IsActive          = 1,
        )
        db.add(row)
        db.flush()  

        endpoint_url_to_id[url] = row.EndpointId

        for src in ep.get("discovered_by", []):
            db.add(DiscoverySource(
                EndpointId   = row.EndpointId,
                EngagementId = engagement_id,
                SourceName   = str(src)[:100],
                IsActive     = 1,
            ))

        cls = _safe_classification(ep.get("classification"))
        if cls in ("Shadow", "Rogue"):
            shadow_rogue_rows.append(ShadowRogueRegister(
                EngagementId   = engagement_id,
                EndpointId     = row.EndpointId,
                Classification = cls,
                RiskScore      = score,
                ActionRequired = ep.get("remediation"),
                IsActive       = 1,
            ))

    db.bulk_save_objects(shadow_rogue_rows)
    db.flush()

    
    owasp_rows = []
    for f in body.get("owasp_findings", []):
        ep_url = f.get("endpoint") or f.get("endpoint_url")
        owasp_rows.append(OWASPFinding(
            EndpointId   = endpoint_url_to_id.get(ep_url) if ep_url else None,
            EngagementId = engagement_id,
            Category     = (f.get("category") or "")[:20] or None,
            CategoryName = (f.get("name") or "")[:200] or None,
            Finding      = f.get("finding"),
            Severity     = _safe_severity_owasp(f.get("severity")),
            Source       = (f.get("source") or "inferred")[:50],
            Remediation  = f.get("remediation"),
            EndpointUrl  = ep_url,
            IsActive     = 1,
        ))
    db.bulk_save_objects(owasp_rows)
    db.flush()

    conformance_rows = [
        OWASPConformance(
            EngagementId     = engagement_id,
            OWASPId          = (c.get("owasp_id") or "")[:10] or None,
            Name             = (c.get("name") or "")[:200] or None,
            Status           = (c.get("status") or "")[:50] or None,
            AffectedCount    = c.get("affected_count", 0),
            Note             = c.get("note"),
            ConformanceLevel = (c.get("conformance_level") or "")[:100] or None,
            IsActive         = 1,
        )
        for c in body.get("owasp_conformance_summary", [])
    ]
    db.bulk_save_objects(conformance_rows)
    db.flush()

    secret_rows = [
        SecretFinding(
            EngagementId   = engagement_id,
            SecretType     = (s.get("type") or "")[:100] or None,
            FilePath       = s.get("file"),
            LineNumber     = s.get("line"),
            Repo           = s.get("repo"),
            MatchPreview   = (s.get("match_preview") or "")[:200],
            Severity       = _safe_severity_secret(s.get("severity")),
            Recommendation = s.get("recommendation"),
            IsActive       = 1,
        )
        for s in body.get("secrets_findings", [])
    ]
    db.bulk_save_objects(secret_rows)
    db.flush()

    outbound_api_rows = [
        OutboundApi(
            EngagementId   = engagement_id,
            Url            = a.get("url"),
            Host           = (a.get("host") or "")[:255] or None,
            PathPrefix     = (a.get("_path_prefix") or a.get("path_prefix") or "")[:255] or None,
            HttpMethod     = (a.get("method") or "UNKNOWN")[:20],
            Integration    = (a.get("integration") or "")[:200] or None,
            Category       = (a.get("category") or "")[:100] or None,
            Exposure       = _safe_exposure(a.get("exposure")),
            Risk           = _safe_risk(a.get("risk")),
            AuthMethod     = (a.get("auth_method") or "")[:100] or None,
            SourceFiles    = str(a.get("source_files", [])),
            LineNumber     = a.get("line"),
            Repo           = a.get("repo"),
            OWASPReference = (a.get("owasp_reference") or "")[:100] or None,
            Recommendation = a.get("recommendation"),
            IsActive       = 1,
        )
        for a in outbound_info.get("apis", [])
    ]
    db.bulk_save_objects(outbound_api_rows)
    db.flush()

    dep_rows = [
        OutboundDependency(
            EngagementId   = engagement_id,
            Integration    = (d.get("integration") or "")[:200] or None,
            Category       = (d.get("category") or "")[:100] or None,
            Exposure       = _safe_exposure(d.get("exposure")),
            Risk           = _safe_risk(d.get("risk")),
            Recommendation = d.get("recommendation"),
            IsActive       = 1,
        )
        for d in body.get("outbound_dependencies", [])
    ]
    db.bulk_save_objects(dep_rows)
    db.flush()

    package_rows = [
        PackageDependency(
            EngagementId = engagement_id,
            Name         = (p.get("name") or "")[:255] or None,
            Version      = (p.get("version") or "")[:100] or None,
            Type         = (p.get("type") or "")[:100] or None,
            Ecosystem    = (p.get("ecosystem") or "")[:100] or None,
            IsActive     = 1,
        )
        for p in bom.get("package_dependencies", [])
    ]
    db.bulk_save_objects(package_rows)
    db.flush()

    cve_rows = [
        CVEFinding(
            EngagementId  = engagement_id,
            CVENumber     = (c.get("cve") or "")[:50] or None,
            Description   = c.get("desc") or c.get("description"),
            Severity      = (c.get("severity") or "")[:50] or None,
            CVSS          = c.get("cvss"),
            EndpointCount = c.get("endpoint_count", 0),
            IsActive      = 1,
        )
        for c in body.get("cve_findings_summary", [])
    ]
    db.bulk_save_objects(cve_rows)
    db.flush()

    engagement.CompletedAt = datetime.utcnow()
    db.commit()

    return {
        "engagement_id": engagement_id,
        "endpoints":     len(endpoint_url_to_id),
        "owasp":         len(owasp_rows),
        "conformance":   len(conformance_rows),
        "secrets":       len(secret_rows),
        "outbound_apis": len(outbound_api_rows),
        "dependencies":  len(dep_rows),
        "packages":      len(package_rows),
        "cve_findings":  len(cve_rows),
        "shadow_rogue":  len(shadow_rogue_rows),
    }




def _create_engagement_record(
    db:              Session,
    client_name:     str,
    app_name:        str,
    engagement_name: str,
) -> int:
    engagement = Engagement(
        EngagementName = engagement_name,
        ClientName     = client_name,
        Mode           = "passive",
        StartedAt      = datetime.utcnow(),
        OverallRisk    = "UNKNOWN",
        IsActive       = 1,
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    return engagement.EngagementId




async def _run_scan(scan_id: str, request: ScanRequest, has_pcap: bool):
    record               = _scan_registry[scan_id]
    record["status"]     = ScanStatus.running
    record["started_at"] = datetime.now(timezone.utc).isoformat()

    try:

        repo_path = None
        if request.repo_url:
            if not request.username or not request.access_token:
                raise ValueError("username and access_token are required when repo_url is provided")

            clone_result = _clone_repo(request.username, request.access_token, request.repo_url)
            if clone_result["status"] != "success":
                raise RuntimeError(clone_result["message"])

            repo_path = clone_result["path"]


        app_name = request.app_name or request.client_name
        cfg      = build_cfg(
            scan_id     = scan_id,
            domain      = request.domain,
            repo_path   = repo_path,
            client_name = request.client_name,
            app_name    = app_name,
            has_pcap    = has_pcap,
        )

        result = await run_pipeline(cfg)

        record["summary"]      = result["summary"]
        record["output_files"] = result["output_files"]


        output_files  = result.get("output_files") or {}
        output_path   = output_files.get("api_discovery_full.json")


        if not output_path or not os.path.exists(output_path):
            output_path = os.path.join(
                cfg["output"]["directory"], "api_discovery_full.json"
            )

        engagement_id = record.get("engagement_id")
        if not engagement_id:
            raise RuntimeError("No engagement_id found in registry — this should never happen")

        db = SessionLocal()
        try:
            ingest_counts = _ingest(db, output_path, engagement_id)
        finally:
            db.close()

        record["ingest"]       = ingest_counts
        record["status"]       = ScanStatus.done
        record["completed_at"] = datetime.now(timezone.utc).isoformat()

    except Exception as exc:
        record["status"]       = ScanStatus.failed
        record["completed_at"] = datetime.now(timezone.utc).isoformat()
        record["error"]        = str(exc)
        print(f"[scan:{scan_id}] FAILED — {exc}")



@router.post(
    "/scan",
    response_model = ScanAccepted,
    status_code    = 202,
    summary        = "Trigger a new API discovery scan",
)
async def trigger_scan(
    request:          ScanRequest,
    background_tasks: BackgroundTasks,
    db:               Session = Depends(get_db),
):
    
    existing = [
        sid for sid, rec in _scan_registry.items()
        if rec["status"] in (ScanStatus.queued, ScanStatus.running)
    ]
    if existing:
        raise HTTPException(
            status_code = 409,
            detail      = (
                f"A scan is already in progress (scan_id={existing[0]}). "
                f"Poll GET /scan/{existing[0]}/result for status."
            ),
        )

    scan_id  = str(uuid.uuid4())
    scan_dir = os.path.join(SCANS_DIR, scan_id)
    pcap_dir = os.path.join(scan_dir, "inputs", "pcap")
    spec_dir = os.path.join(scan_dir, "inputs", "openapi_specs")

    
    try:
        saved_pcaps = _decode_and_save_files(
            request.pcap_files, request.pcap_filenames, pcap_dir, ".pcap",
        )
        saved_specs = _decode_and_save_files(
            request.openapi_specs, request.openapi_filenames, spec_dir, ".yaml",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    app_name        = request.app_name or request.client_name
    engagement_name = f"API Discovery & Security Evaluation — {app_name}"

    engagement_id = _create_engagement_record(
        db              = db,
        client_name     = request.client_name,
        app_name        = app_name,
        engagement_name = engagement_name,
    )

    _scan_registry[scan_id] = {
        "status":        ScanStatus.queued,
        "started_at":    None,
        "completed_at":  None,
        "error":         None,
        "summary":       None,
        "output_files":  None,
        "ingest":        None,
        "engagement_id": engagement_id,
        "request": {
            "domain":        request.domain,
            "repo_url":      request.repo_url,
            "client_name":   request.client_name,
            "pcap_files":    [os.path.basename(p) for p in saved_pcaps],
            "openapi_specs": [os.path.basename(p) for p in saved_specs],
        },
    }

    background_tasks.add_task(_run_scan, scan_id, request, bool(saved_pcaps))

    return ScanAccepted(
        scan_id    = scan_id,
        status     = ScanStatus.queued,
        message    = "Scan accepted and queued. Poll the status URL to check progress.",
        status_url = f"/scan/{scan_id}/result",
    )


@router.get(
    "/scan/{scan_id}/result",
    response_model = ScanResult,
    summary        = "Poll a scan for status and results",
)
async def get_scan_result(scan_id: str):
    record = _scan_registry.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id!r} not found")

    return ScanResult(
        scan_id      = scan_id,
        status       = record["status"],
        started_at   = record.get("started_at"),
        completed_at = record.get("completed_at"),
        error        = record.get("error"),
        summary      = record.get("summary"),
        output_files = record.get("output_files"),
        ingest       = record.get("ingest"),
    )


@router.get(
    "/scan",
    summary = "List all scans in this server session",
)
async def list_scans():
    return [
        {
            "scan_id":       sid,
            "status":        rec["status"],
            "engagement_id": rec.get("engagement_id"),
            "started_at":    rec.get("started_at"),
            "completed_at":  rec.get("completed_at"),
            "domain":        rec["request"].get("domain"),
        }
        for sid, rec in _scan_registry.items()
    ]


@router.get("/health", summary="Health check")
async def health():
    return {"status": "ok"}