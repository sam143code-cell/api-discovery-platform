import base64
import os
import shutil
import stat
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from urllib.parse import urlparse

from models   import ScanRequest, ScanAccepted, ScanResult, ScanStatus, IngestRequest
from config   import build_cfg, REPO_CLONE_ROOT, SCANS_DIR
from scanner  import run_pipeline
from database import get_db
from db_models import Engagement
from ingest   import ingest_scan_output

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


def _create_engagement_record(
    db:              Session,
    client_name:     str,
    app_name:        str,
    engagement_name: str,
) -> int:
    engagement = Engagement(
        EngagementName=engagement_name,
        ClientName=client_name,
        Mode="passive",
        StartedAt=datetime.utcnow(),
        OverallRisk="UNKNOWN",
        IsActive=1,
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    return engagement.EngagementId


async def _run_scan(scan_id: str, request: ScanRequest, has_pcap: bool):
    record = _scan_registry[scan_id]
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

        cfg = build_cfg(
            scan_id=scan_id,
            domain=request.domain,
            repo_path=repo_path,
            client_name=request.client_name,
            app_name=app_name,
            has_pcap=has_pcap,
        )

        result = await run_pipeline(cfg)

        record["status"]       = ScanStatus.done
        record["completed_at"] = datetime.now(timezone.utc).isoformat()
        record["summary"]      = result["summary"]
        record["output_files"] = result["output_files"]

    except Exception as exc:
        record["status"]       = ScanStatus.failed
        record["completed_at"] = datetime.now(timezone.utc).isoformat()
        record["error"]        = str(exc)
        print(f"[scan:{scan_id}] FAILED — {exc}")


@router.post(
    "/scan",
    response_model=ScanAccepted,
    status_code=202,
    summary="Trigger a new API discovery scan",
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
            status_code=409,
            detail=f"A scan is already in progress (scan_id={existing[0]}). "
                   f"Poll GET /scan/{existing[0]}/result for status.",
        )

    scan_id  = str(uuid.uuid4())
    scan_dir = os.path.join(SCANS_DIR, scan_id)
    pcap_dir = os.path.join(scan_dir, "inputs", "pcap")
    spec_dir = os.path.join(scan_dir, "inputs", "openapi_specs")

    try:
        saved_pcaps = _decode_and_save_files(
            request.pcap_files,
            request.pcap_filenames,
            pcap_dir,
            ".pcap",
        )
        saved_specs = _decode_and_save_files(
            request.openapi_specs,
            request.openapi_filenames,
            spec_dir,
            ".yaml",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    app_name        = request.app_name or request.client_name
    engagement_name = f"API Discovery & Security Evaluation — {app_name}"

    engagement_id = _create_engagement_record(
        db=db,
        client_name=request.client_name,
        app_name=app_name,
        engagement_name=engagement_name,
    )

    _scan_registry[scan_id] = {
        "status":        ScanStatus.queued,
        "started_at":    None,
        "completed_at":  None,
        "error":         None,
        "summary":       None,
        "output_files":  None,
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
        scan_id=scan_id,
        status=ScanStatus.queued,
        message="Scan accepted and queued. Poll the status URL to check progress.",
        status_url=f"/scan/{scan_id}/result",
    )


@router.post(
    "/scan/{scan_id}/ingest",
    summary="Ingest completed scan output into the database",
    status_code=200,
)
async def ingest_scan(
    scan_id: str,
    body:    IngestRequest = IngestRequest(),
    db:      Session = Depends(get_db),
):
    record = _scan_registry.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id} not found")

    if record["status"] != ScanStatus.done:
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not complete yet (status={record['status']}). "
                   "Wait for status=done before ingesting.",
        )

    output_files = record.get("output_files") or {}
    output_path  = output_files.get("api_discovery_full.json")

    if not output_path or not os.path.exists(output_path):
        scan_dir    = os.path.join(SCANS_DIR, scan_id, "output")
        output_path = os.path.join(scan_dir, "api_discovery_full.json")
        if not os.path.exists(output_path):
            raise HTTPException(
                status_code=404,
                detail="api_discovery_full.json not found for this scan.",
            )

    engagement_id = record.get("engagement_id")
    if not engagement_id:
        raise HTTPException(
            status_code=500,
            detail="No engagement_id associated with this scan. Scan may have been triggered before DB support was added.",
        )

    if body.engagement_name:
        engagement = db.query(Engagement).filter_by(
            EngagementId=engagement_id, IsActive=1
        ).first()
        if engagement:
            engagement.EngagementName = body.engagement_name
            db.commit()

    try:
        result = ingest_scan_output(
            db=db,
            output_path=output_path,
            engagement_id=engagement_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Ingest failed: {exc}")

    return {"success": True, "data": result, "error": None}


@router.get(
    "/scan/{scan_id}/result",
    response_model=ScanResult,
    summary="Poll a scan for status and results",
)
async def get_scan_result(scan_id: str):
    record = _scan_registry.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"scan_id {scan_id} not found")

    return ScanResult(
        scan_id=scan_id,
        status=record["status"],
        started_at=record.get("started_at"),
        completed_at=record.get("completed_at"),
        error=record.get("error"),
        summary=record.get("summary"),
        output_files=record.get("output_files"),
    )


@router.get(
    "/scan",
    summary="List all scans in this server session",
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