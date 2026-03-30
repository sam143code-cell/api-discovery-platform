from flask import Blueprint, request, jsonify
from . import db
from .models import (
    Engagement, ApiEndpoint, DiscoverySource, OWASPFinding,
    OWASPConformance, SecretFinding, OutboundApi, OutboundDependency,
    PackageDependency, CVEFinding, ScanPhaseLog, ShadowRogueRegister
)
from datetime import datetime
import subprocess
import threading
import json
import os
import uuid
import sys

bp = Blueprint("api", __name__, url_prefix="/api")

_jobs = {}


def _parse_dt(val):
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00").replace("+00:00", ""))
    except Exception:
        return None


def _ok(data=None, code=200):
    return jsonify({"success": True, "data": data, "error": None}), code


def _err(msg, code=400):
    return jsonify({"success": False, "data": None, "error": msg}), code


def _ingest_full_json(job_id, engagement_id, output_path, app):
    with app.app_context():
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                body = json.load(f)

            engagement = Engagement.query.filter_by(
                EngagementId=engagement_id, IsActive=1
            ).first()
            if not engagement:
                return

            summary = body.get("summary", {})
            exec_summary = body.get("executive_summary", {})
            key_metrics = exec_summary.get("key_metrics", {})
            bom = body.get("api_bom", {})
            tech_stack = bom.get("tech_stack", {})
            inbound_outbound = body.get("inbound_outbound_classification", {})
            outbound_info = inbound_outbound.get("outbound_apis", {})
            sensitivity = summary.get("data_sensitivity", {})

            engagement.OverallRisk = exec_summary.get("overall_risk", "UNKNOWN")
            engagement.Narrative = exec_summary.get("narrative")
            engagement.TotalApis = summary.get("total", 0)
            engagement.InboundApiCount = summary.get("inbound_api_count", 0)
            engagement.OutboundApiCount = summary.get("outbound_api_count", 0)
            engagement.OutboundExternalCount = summary.get("outbound_external_count", outbound_info.get("external", 0))
            engagement.OutboundInternalCount = summary.get("outbound_internal_count", outbound_info.get("internal", 0))
            engagement.ValidCount = summary.get("Valid", 0)
            engagement.ShadowCount = summary.get("Shadow", 0)
            engagement.NewCount = summary.get("New", 0)
            engagement.RogueCount = summary.get("Rogue", 0)
            engagement.UnclassifiedCount = summary.get("UNCLASSIFIED", 0)
            engagement.SecretsCount = summary.get("secrets_count", 0)
            engagement.OWASPFindingsTotal = summary.get("owasp_findings_total", 0)
            engagement.InferredOWASPFindings = summary.get("inferred_owasp_findings", 0)
            engagement.LiveOWASPFindings = summary.get("live_owasp_findings", 0)
            engagement.CVEFindingsTotal = summary.get("cve_findings_total", 0)
            engagement.HighCriticalRiskCount = summary.get("high_critical_risk_count", key_metrics.get("high_critical_risk_endpoints", 0))
            engagement.EndpointsWithoutAuth = summary.get("endpoints_without_auth", key_metrics.get("endpoints_without_auth", 0))
            engagement.ExternalIntegrations = summary.get("external_integrations", key_metrics.get("external_integrations", 0))
            engagement.SensitivityCritical = sensitivity.get("CRITICAL", 0)
            engagement.SensitivityHigh = sensitivity.get("HIGH", 0)
            engagement.SensitivityMedium = sensitivity.get("MEDIUM", 0)
            engagement.SensitivityLow = sensitivity.get("LOW", 0)
            engagement.SensitivityUnknown = sensitivity.get("UNKNOWN", 0)
            engagement.TechStackRuntime = tech_stack.get("runtime")
            engagement.TechStackLanguage = tech_stack.get("language")
            engagement.TechStackFramework = tech_stack.get("framework")
            engagement.TechStackFrontend = tech_stack.get("frontend")
            db.session.commit()

            all_endpoints = body.get("all_endpoints", [])
            shadow_rogue_rows = []
            for ep in all_endpoints:
                url = ep.get("endpoint") or ep.get("url")
                if not url:
                    continue
                risk_score = ep.get("risk_score", 0)
                score = int(risk_score) if risk_score is not None else 0
                if score >= 75:
                    band = "CRITICAL"
                elif score >= 50:
                    band = "HIGH"
                elif score >= 25:
                    band = "MEDIUM"
                else:
                    band = "LOW"

                endpoint_row = ApiEndpoint(
                    EngagementId=engagement_id,
                    ApiDirection=ep.get("api_direction", "inbound"),
                    EndpointUrl=url,
                    HttpMethod=ep.get("method", "UNKNOWN"),
                    Classification=ep.get("classification", "UNCLASSIFIED"),
                    RiskScore=score,
                    RiskBand=band,
                    AuthType=ep.get("auth_type"),
                    DataSensitivity=ep.get("data_sensitivity", "UNKNOWN"),
                    Exposure=ep.get("exposure"),
                    Environment=ep.get("environment"),
                    FunctionalModule=ep.get("functional_module"),
                    FunctionalType=ep.get("functional_type"),
                    ApiVersion=ep.get("api_version"),
                    TechStack=ep.get("tech_stack"),
                    InferredOwner=ep.get("inferred_owner"),
                    Owner=ep.get("owner"),
                    BaselineStatus=ep.get("baseline_status"),
                    StatusCode=ep.get("status_code"),
                    ContentType=ep.get("content_type"),
                    ResponseSizeBytes=ep.get("response_size_bytes"),
                    Remediation=ep.get("remediation"),
                    SourceFile=ep.get("source_file"),
                    FirstSeen=_parse_dt(ep.get("first_seen")),
                    LastSeen=_parse_dt(ep.get("last_seen")),
                    IsActive=1,
                )
                db.session.add(endpoint_row)
                db.session.flush()

                for src in ep.get("discovered_by", []):
                    db.session.add(DiscoverySource(
                        EndpointId=endpoint_row.EndpointId,
                        EngagementId=engagement_id,
                        SourceName=src,
                        IsActive=1,
                    ))

                classification = ep.get("classification", "UNCLASSIFIED")
                if classification in ("Shadow", "Rogue"):
                    shadow_rogue_rows.append(ShadowRogueRegister(
                        EngagementId=engagement_id,
                        EndpointId=endpoint_row.EndpointId,
                        Classification=classification,
                        RiskScore=score,
                        ActionRequired=ep.get("remediation"),
                        IsActive=1,
                    ))

            db.session.bulk_save_objects(shadow_rogue_rows)
            db.session.commit()

            owasp_rows = []
            for f in body.get("owasp_findings", []):
                endpoint_url = f.get("endpoint") or f.get("endpoint_url")
                endpoint_id = None
                if endpoint_url:
                    ep_row = ApiEndpoint.query.filter_by(
                        EngagementId=engagement_id,
                        EndpointUrl=endpoint_url,
                        IsActive=1,
                    ).first()
                    if ep_row:
                        endpoint_id = ep_row.EndpointId
                owasp_rows.append(OWASPFinding(
                    EndpointId=endpoint_id,
                    EngagementId=engagement_id,
                    Category=f.get("category"),
                    CategoryName=f.get("name"),
                    Finding=f.get("finding"),
                    Severity=f.get("severity", "INFO"),
                    Source=f.get("source", "inferred"),
                    Remediation=f.get("remediation"),
                    EndpointUrl=endpoint_url,
                    IsActive=1,
                ))
            db.session.bulk_save_objects(owasp_rows)
            db.session.commit()

            conformance_rows = [
                OWASPConformance(
                    EngagementId=engagement_id,
                    OWASPId=c.get("owasp_id"),
                    Name=c.get("name"),
                    Status=c.get("status"),
                    AffectedCount=c.get("affected_count", 0),
                    Note=c.get("note"),
                    ConformanceLevel=c.get("conformance_level"),
                    IsActive=1,
                )
                for c in body.get("owasp_conformance_summary", [])
            ]
            db.session.bulk_save_objects(conformance_rows)
            db.session.commit()

            secret_rows = [
                SecretFinding(
                    EngagementId=engagement_id,
                    SecretType=s.get("type"),
                    FilePath=s.get("file"),
                    LineNumber=s.get("line"),
                    Repo=s.get("repo"),
                    MatchPreview=s.get("match_preview", "")[:200],
                    Severity=s.get("severity", "CRITICAL"),
                    Recommendation=s.get("recommendation"),
                    IsActive=1,
                )
                for s in body.get("secrets_findings", [])
            ]
            db.session.bulk_save_objects(secret_rows)
            db.session.commit()

            outbound_data = inbound_outbound.get("outbound_apis", {})
            outbound_api_rows = [
                OutboundApi(
                    EngagementId=engagement_id,
                    Url=a.get("url"),
                    Host=a.get("host"),
                    PathPrefix=a.get("path_prefix"),
                    HttpMethod=a.get("method", "UNKNOWN"),
                    Integration=a.get("integration"),
                    Category=a.get("category"),
                    Exposure=a.get("exposure", "External"),
                    Risk=a.get("risk", "MEDIUM"),
                    AuthMethod=a.get("auth_method"),
                    SourceFiles=str(a.get("source_files", [])),
                    LineNumber=a.get("line"),
                    Repo=a.get("repo"),
                    OWASPReference=a.get("owasp_reference"),
                    Recommendation=a.get("recommendation"),
                    IsActive=1,
                )
                for a in outbound_data.get("apis", [])
            ]
            db.session.bulk_save_objects(outbound_api_rows)

            dep_rows = [
                OutboundDependency(
                    EngagementId=engagement_id,
                    Integration=d.get("integration"),
                    Category=d.get("category"),
                    Exposure=d.get("exposure", "External"),
                    Risk=d.get("risk", "MEDIUM"),
                    Recommendation=d.get("recommendation"),
                    IsActive=1,
                )
                for d in body.get("outbound_dependencies", [])
            ]
            db.session.bulk_save_objects(dep_rows)
            db.session.commit()

            package_rows = [
                PackageDependency(
                    EngagementId=engagement_id,
                    Name=p.get("name"),
                    Version=p.get("version"),
                    Type=p.get("type"),
                    Ecosystem=p.get("ecosystem"),
                    IsActive=1,
                )
                for p in bom.get("package_dependencies", [])
            ]
            db.session.bulk_save_objects(package_rows)
            db.session.commit()

            cve_rows = [
                CVEFinding(
                    EngagementId=engagement_id,
                    CVENumber=c.get("cve"),
                    Description=c.get("description"),
                    Severity=c.get("severity"),
                    CVSS=c.get("cvss"),
                    EndpointCount=c.get("endpoint_count", 0),
                    IsActive=1,
                )
                for c in body.get("cve_findings_summary", [])
            ]
            db.session.bulk_save_objects(cve_rows)
            db.session.commit()

            engagement.CompletedAt = datetime.utcnow()
            db.session.commit()

        except Exception as e:
            _jobs[job_id]["error"] = str(e)
            _jobs[job_id]["status"] = "failed"
            return

        _jobs[job_id]["status"] = "completed"


def _run_scan_thread(job_id, engagement_id, scanner_path, domain, mode,
                     wordlist, max_pages, concurrency, output_dir, app):
    _jobs[job_id]["status"] = "scanning"

    cmd = [
        sys.executable, scanner_path,
        "--domain", domain,
        "--mode", mode,
    ]
    if wordlist:
        cmd += ["--wordlist", wordlist]
    if max_pages:
        cmd += ["--max-pages", str(max_pages)]
    if concurrency:
        cmd += ["--concurrency", str(concurrency)]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONLEGACYWINDOWSSTDIO"] = "0"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200,
            env=env,
            cwd=os.path.dirname(os.path.abspath(scanner_path)),
        )
        _jobs[job_id]["scanner_stdout"] = result.stdout[-3000:] if result.stdout else ""
        _jobs[job_id]["scanner_stderr"] = result.stderr[-2000:] if result.stderr else ""

        if result.returncode != 0:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = f"Scanner exited with code {result.returncode}"
            return

    except subprocess.TimeoutExpired:
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["error"] = "Scanner timed out after 2 hours"
        return
    except Exception as e:
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["error"] = str(e)
        return

    output_json = os.path.join(output_dir, "api_discovery_full.json")
    if not os.path.exists(output_json):
        output_candidates = []
        for root, dirs, files in os.walk(output_dir):
            for fname in files:
                if fname == "api_discovery_full.json":
                    output_candidates.append(os.path.join(root, fname))
        if not output_candidates:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["error"] = f"api_discovery_full.json not found in {output_dir}"
            return
        output_candidates.sort(key=os.path.getmtime, reverse=True)
        output_json = output_candidates[0]

    _jobs[job_id]["status"] = "ingesting"
    _jobs[job_id]["output_file"] = output_json
    _ingest_full_json(job_id, engagement_id, output_json, app)


@bp.route("/scanner/scan/start", methods=["POST"])
def start_scan():
    body = request.get_json(silent=True)
    if not body:
        return _err("Request body is required", 400)

    domain = body.get("domain")
    scanner_path = body.get("scanner_path")
    if not domain:
        return _err("Field 'domain' is required", 422)
    if not scanner_path:
        return _err("Field 'scanner_path' is required", 422)
    if not os.path.exists(scanner_path):
        return _err(f"scanner_path does not exist: {scanner_path}", 422)

    mode = body.get("mode", "passive")
    wordlist = body.get("wordlist")
    max_pages = body.get("max_pages")
    concurrency = body.get("concurrency")
    client_name = body.get("client", "Unknown Client")
    engagement_name = body.get("engagement", "API Discovery & Security Evaluation")
    scan_env = body.get("scan_target_environment", "internal_non_prod")

    scanner_dir = os.path.dirname(os.path.abspath(scanner_path))
    output_dir = os.path.join(scanner_dir, "output")

    engagement = Engagement(
        EngagementName=engagement_name,
        ClientName=client_name,
        Mode=mode,
        ScanTargetEnvironment=scan_env,
        StartedAt=datetime.utcnow(),
        OverallRisk="UNKNOWN",
        IsActive=1,
    )
    db.session.add(engagement)
    db.session.commit()

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "engagement_id": engagement.EngagementId,
        "status": "queued",
        "domain": domain,
        "mode": mode,
        "started_at": datetime.utcnow().isoformat(),
        "output_file": None,
        "error": None,
        "scanner_stdout": None,
        "scanner_stderr": None,
    }

    from flask import current_app
    app = current_app._get_current_object()

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(
            job_id, engagement.EngagementId, scanner_path,
            domain, mode, wordlist, max_pages, concurrency,
            output_dir, app
        ),
        daemon=True,
    )
    thread.start()

    return _ok({
        "job_id": job_id,
        "engagement_id": engagement.EngagementId,
        "status": "queued",
        "message": "Scan started. Poll /api/scanner/scan/status/<job_id> for updates.",
    }, 202)


@bp.route("/scanner/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id):
    job = _jobs.get(job_id)
    if not job:
        return _err("Job not found", 404)
    return _ok(job)


@bp.route("/scanner/scan/jobs", methods=["GET"])
def list_jobs():
    jobs_summary = [
        {
            "job_id": j["job_id"],
            "engagement_id": j["engagement_id"],
            "status": j["status"],
            "domain": j["domain"],
            "mode": j["mode"],
            "started_at": j["started_at"],
            "error": j["error"],
        }
        for j in _jobs.values()
    ]
    return _ok(jobs_summary)


@bp.route("/scanner/engagement", methods=["POST"])
def create_engagement():
    body = request.get_json(silent=True)
    if not body:
        return _err("Request body is required", 400)

    required = ["engagement", "client"]
    for field in required:
        if not body.get(field):
            return _err(f"Field '{field}' is required", 422)

    summary = body.get("summary", {})
    exec_summary = body.get("executive_summary", {})
    key_metrics = exec_summary.get("key_metrics", {})
    bom = body.get("api_bom", {})
    tech_stack = bom.get("tech_stack", {})
    inbound_outbound = body.get("inbound_outbound_classification", {})
    outbound_info = inbound_outbound.get("outbound_apis", {})
    sensitivity = summary.get("data_sensitivity", {})

    engagement = Engagement(
        EngagementName=body.get("engagement"),
        ClientName=body.get("client"),
        Mode=body.get("mode", "passive"),
        ScanTargetEnvironment=body.get("scan_target_environment"),
        SchemaVersion=body.get("schema_version"),
        GeneratedAt=_parse_dt(body.get("generated_at")),
        OverallRisk=exec_summary.get("overall_risk", "UNKNOWN"),
        Narrative=exec_summary.get("narrative"),
        TotalApis=summary.get("total", 0),
        InboundApiCount=summary.get("inbound_api_count", 0),
        OutboundApiCount=summary.get("outbound_api_count", 0),
        OutboundExternalCount=summary.get("outbound_external_count", outbound_info.get("external", 0)),
        OutboundInternalCount=summary.get("outbound_internal_count", outbound_info.get("internal", 0)),
        ValidCount=summary.get("Valid", 0),
        ShadowCount=summary.get("Shadow", 0),
        NewCount=summary.get("New", 0),
        RogueCount=summary.get("Rogue", 0),
        UnclassifiedCount=summary.get("UNCLASSIFIED", 0),
        SecretsCount=summary.get("secrets_count", 0),
        OWASPFindingsTotal=summary.get("owasp_findings_total", 0),
        InferredOWASPFindings=summary.get("inferred_owasp_findings", 0),
        LiveOWASPFindings=summary.get("live_owasp_findings", 0),
        CVEFindingsTotal=summary.get("cve_findings_total", 0),
        HighCriticalRiskCount=summary.get("high_critical_risk_count", key_metrics.get("high_critical_risk_endpoints", 0)),
        EndpointsWithoutAuth=summary.get("endpoints_without_auth", key_metrics.get("endpoints_without_auth", 0)),
        ExternalIntegrations=summary.get("external_integrations", key_metrics.get("external_integrations", 0)),
        SensitivityCritical=sensitivity.get("CRITICAL", 0),
        SensitivityHigh=sensitivity.get("HIGH", 0),
        SensitivityMedium=sensitivity.get("MEDIUM", 0),
        SensitivityLow=sensitivity.get("LOW", 0),
        SensitivityUnknown=sensitivity.get("UNKNOWN", 0),
        TechStackRuntime=tech_stack.get("runtime"),
        TechStackLanguage=tech_stack.get("language"),
        TechStackFramework=tech_stack.get("framework"),
        TechStackFrontend=tech_stack.get("frontend"),
        IsActive=1,
    )
    db.session.add(engagement)
    db.session.commit()

    return _ok({"engagement_id": engagement.EngagementId}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/endpoints", methods=["POST"])
def ingest_endpoints(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body or "endpoints" not in body:
        return _err("Field 'endpoints' is required", 422)

    endpoints = body["endpoints"]
    if not isinstance(endpoints, list):
        return _err("'endpoints' must be a list", 422)

    inserted = 0
    shadow_rogue_rows = []

    for ep in endpoints:
        url = ep.get("endpoint") or ep.get("url")
        if not url:
            continue

        risk_score = ep.get("risk_score", 0)
        score = int(risk_score) if risk_score is not None else 0
        if score >= 75:
            band = "CRITICAL"
        elif score >= 50:
            band = "HIGH"
        elif score >= 25:
            band = "MEDIUM"
        else:
            band = "LOW"

        endpoint_row = ApiEndpoint(
            EngagementId=engagement_id,
            ApiDirection=ep.get("api_direction", "inbound"),
            EndpointUrl=url,
            HttpMethod=ep.get("method", "UNKNOWN"),
            Classification=ep.get("classification", "UNCLASSIFIED"),
            RiskScore=score,
            RiskBand=band,
            AuthType=ep.get("auth_type"),
            DataSensitivity=ep.get("data_sensitivity", "UNKNOWN"),
            Exposure=ep.get("exposure"),
            Environment=ep.get("environment"),
            FunctionalModule=ep.get("functional_module"),
            FunctionalType=ep.get("functional_type"),
            ApiVersion=ep.get("api_version"),
            TechStack=ep.get("tech_stack"),
            InferredOwner=ep.get("inferred_owner"),
            Owner=ep.get("owner"),
            BaselineStatus=ep.get("baseline_status"),
            StatusCode=ep.get("status_code"),
            ContentType=ep.get("content_type"),
            ResponseSizeBytes=ep.get("response_size_bytes"),
            Remediation=ep.get("remediation"),
            SourceFile=ep.get("source_file"),
            FirstSeen=_parse_dt(ep.get("first_seen")),
            LastSeen=_parse_dt(ep.get("last_seen")),
            IsActive=1,
        )
        db.session.add(endpoint_row)
        db.session.flush()

        for src in ep.get("discovered_by", []):
            db.session.add(DiscoverySource(
                EndpointId=endpoint_row.EndpointId,
                EngagementId=engagement_id,
                SourceName=src,
                IsActive=1,
            ))

        classification = ep.get("classification", "UNCLASSIFIED")
        if classification in ("Shadow", "Rogue"):
            shadow_rogue_rows.append(ShadowRogueRegister(
                EngagementId=engagement_id,
                EndpointId=endpoint_row.EndpointId,
                Classification=classification,
                RiskScore=score,
                ActionRequired=ep.get("remediation"),
                IsActive=1,
            ))

        inserted += 1

    db.session.bulk_save_objects(shadow_rogue_rows)
    db.session.commit()

    return _ok({"inserted": inserted}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/owasp", methods=["POST"])
def ingest_owasp(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body or "findings" not in body:
        return _err("Field 'findings' is required", 422)

    findings = body["findings"]
    if not isinstance(findings, list):
        return _err("'findings' must be a list", 422)

    rows = []
    for f in findings:
        endpoint_id = None
        endpoint_url = f.get("endpoint") or f.get("endpoint_url")
        if endpoint_url:
            ep_row = ApiEndpoint.query.filter_by(
                EngagementId=engagement_id,
                EndpointUrl=endpoint_url,
                IsActive=1,
            ).first()
            if ep_row:
                endpoint_id = ep_row.EndpointId

        rows.append(OWASPFinding(
            EndpointId=endpoint_id,
            EngagementId=engagement_id,
            Category=f.get("category"),
            CategoryName=f.get("name"),
            Finding=f.get("finding"),
            Severity=f.get("severity", "INFO"),
            Source=f.get("source", "inferred"),
            Remediation=f.get("remediation"),
            EndpointUrl=endpoint_url,
            IsActive=1,
        ))

    db.session.bulk_save_objects(rows)
    db.session.commit()

    return _ok({"inserted": len(rows)}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/owasp-conformance", methods=["POST"])
def ingest_owasp_conformance(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body or "conformance" not in body:
        return _err("Field 'conformance' is required", 422)

    conformance = body["conformance"]
    if not isinstance(conformance, list):
        return _err("'conformance' must be a list", 422)

    rows = [
        OWASPConformance(
            EngagementId=engagement_id,
            OWASPId=c.get("owasp_id"),
            Name=c.get("name"),
            Status=c.get("status"),
            AffectedCount=c.get("affected_count", 0),
            Note=c.get("note"),
            ConformanceLevel=c.get("conformance_level"),
            IsActive=1,
        )
        for c in conformance
    ]
    db.session.bulk_save_objects(rows)
    db.session.commit()

    return _ok({"inserted": len(rows)}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/secrets", methods=["POST"])
def ingest_secrets(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body or "secrets" not in body:
        return _err("Field 'secrets' is required", 422)

    secrets = body["secrets"]
    if not isinstance(secrets, list):
        return _err("'secrets' must be a list", 422)

    rows = [
        SecretFinding(
            EngagementId=engagement_id,
            SecretType=s.get("type"),
            FilePath=s.get("file"),
            LineNumber=s.get("line"),
            Repo=s.get("repo"),
            MatchPreview=s.get("match_preview", "")[:200],
            Severity=s.get("severity", "CRITICAL"),
            Recommendation=s.get("recommendation"),
            IsActive=1,
        )
        for s in secrets
    ]
    db.session.bulk_save_objects(rows)
    db.session.commit()

    return _ok({"inserted": len(rows)}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/outbound", methods=["POST"])
def ingest_outbound(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body:
        return _err("Request body is required", 400)

    apis = body.get("apis", [])
    dependencies = body.get("dependencies", [])

    api_rows = [
        OutboundApi(
            EngagementId=engagement_id,
            Url=a.get("url"),
            Host=a.get("host"),
            PathPrefix=a.get("path_prefix"),
            HttpMethod=a.get("method", "UNKNOWN"),
            Integration=a.get("integration"),
            Category=a.get("category"),
            Exposure=a.get("exposure", "External"),
            Risk=a.get("risk", "MEDIUM"),
            AuthMethod=a.get("auth_method"),
            SourceFiles=str(a.get("source_files", [])),
            LineNumber=a.get("line"),
            Repo=a.get("repo"),
            OWASPReference=a.get("owasp_reference"),
            Recommendation=a.get("recommendation"),
            IsActive=1,
        )
        for a in apis
    ]

    dep_rows = [
        OutboundDependency(
            EngagementId=engagement_id,
            Integration=d.get("integration"),
            Category=d.get("category"),
            Exposure=d.get("exposure", "External"),
            Risk=d.get("risk", "MEDIUM"),
            Recommendation=d.get("recommendation"),
            IsActive=1,
        )
        for d in dependencies
    ]

    db.session.bulk_save_objects(api_rows)
    db.session.bulk_save_objects(dep_rows)
    db.session.commit()

    return _ok({"apis_inserted": len(api_rows), "dependencies_inserted": len(dep_rows)}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/packages", methods=["POST"])
def ingest_packages(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body or "packages" not in body:
        return _err("Field 'packages' is required", 422)

    packages = body["packages"]
    if not isinstance(packages, list):
        return _err("'packages' must be a list", 422)

    rows = [
        PackageDependency(
            EngagementId=engagement_id,
            Name=p.get("name"),
            Version=p.get("version"),
            Type=p.get("type"),
            Ecosystem=p.get("ecosystem"),
            IsActive=1,
        )
        for p in packages
    ]
    db.session.bulk_save_objects(rows)
    db.session.commit()

    return _ok({"inserted": len(rows)}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/cve", methods=["POST"])
def ingest_cve(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body or "cve_findings" not in body:
        return _err("Field 'cve_findings' is required", 422)

    cve_findings = body["cve_findings"]
    if not isinstance(cve_findings, list):
        return _err("'cve_findings' must be a list", 422)

    rows = [
        CVEFinding(
            EngagementId=engagement_id,
            CVENumber=c.get("cve"),
            Description=c.get("description"),
            Severity=c.get("severity"),
            CVSS=c.get("cvss"),
            EndpointCount=c.get("endpoint_count", 0),
            IsActive=1,
        )
        for c in cve_findings
    ]
    db.session.bulk_save_objects(rows)
    db.session.commit()

    return _ok({"inserted": len(rows)}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/phase-log", methods=["POST"])
def ingest_phase_log(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    body = request.get_json(silent=True)
    if not body:
        return _err("Request body is required", 400)

    phases = body.get("phases", [])
    if not isinstance(phases, list):
        return _err("'phases' must be a list", 422)

    rows = [
        ScanPhaseLog(
            EngagementId=engagement_id,
            PhaseNumber=p.get("phase_number"),
            PhaseName=p.get("phase_name"),
            Status=p.get("status", "completed"),
            StartedAt=_parse_dt(p.get("started_at")),
            CompletedAt=_parse_dt(p.get("completed_at")),
            EndpointsFound=p.get("endpoints_found", 0),
            Notes=p.get("notes"),
            IsActive=1,
        )
        for p in phases
    ]
    db.session.bulk_save_objects(rows)
    db.session.commit()

    return _ok({"inserted": len(rows)}, 201)


@bp.route("/scanner/engagement/<int:engagement_id>/finalize", methods=["POST"])
def finalize_engagement(engagement_id):
    engagement = Engagement.query.filter_by(
        EngagementId=engagement_id, IsActive=1
    ).first()
    if not engagement:
        return _err("Engagement not found", 404)

    total = ApiEndpoint.query.filter_by(EngagementId=engagement_id, IsActive=1).count()
    valid = ApiEndpoint.query.filter_by(EngagementId=engagement_id, Classification="Valid", IsActive=1).count()
    shadow = ApiEndpoint.query.filter_by(EngagementId=engagement_id, Classification="Shadow", IsActive=1).count()
    new = ApiEndpoint.query.filter_by(EngagementId=engagement_id, Classification="New", IsActive=1).count()
    rogue = ApiEndpoint.query.filter_by(EngagementId=engagement_id, Classification="Rogue", IsActive=1).count()
    inbound = ApiEndpoint.query.filter_by(EngagementId=engagement_id, ApiDirection="inbound", IsActive=1).count()
    outbound_count = OutboundApi.query.filter_by(EngagementId=engagement_id, IsActive=1).count()
    secrets = SecretFinding.query.filter_by(EngagementId=engagement_id, IsActive=1).count()
    owasp_total = OWASPFinding.query.filter_by(EngagementId=engagement_id, IsActive=1).count()
    cve_total = CVEFinding.query.filter_by(EngagementId=engagement_id, IsActive=1).count()

    engagement.TotalApis = total
    engagement.ValidCount = valid
    engagement.ShadowCount = shadow
    engagement.NewCount = new
    engagement.RogueCount = rogue
    engagement.InboundApiCount = inbound
    engagement.OutboundApiCount = outbound_count
    engagement.SecretsCount = secrets
    engagement.OWASPFindingsTotal = owasp_total
    engagement.CVEFindingsTotal = cve_total
    engagement.CompletedAt = datetime.utcnow()

    db.session.commit()

    return _ok({
        "engagement_id": engagement_id,
        "total_apis": total,
        "valid": valid,
        "shadow": shadow,
        "new": new,
        "rogue": rogue,
        "inbound": inbound,
        "outbound": outbound_count,
        "secrets": secrets,
        "owasp_findings": owasp_total,
        "cve_findings": cve_total,
    })