import requests
import time
import sys

BASE_URL = "http://localhost:5001"
SCANNER_PATH = "E:\\api_discovery_platform\\main.py"
DOMAIN = "http://10.20.40.14:7085"
MODE = "passive"
CLIENT = "testing-CRVM"
ENGAGEMENT = "API Discovery & Security Evaluation"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        log(f"Flask returned non-JSON response (status {resp.status_code})")
        log(f"Raw response: {resp.text[:500]}")
        sys.exit(1)


def test_health():
    log("Checking Flask is reachable...")
    try:
        resp = requests.get(f"{BASE_URL}/api/scanner/scan/jobs", timeout=5)
        data = safe_json(resp)
        if data.get("success"):
            log("Flask is up and responding correctly.")
        else:
            log(f"Flask responded but returned error: {data.get('error')}")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        log("Cannot connect to Flask at http://localhost:5001")
        log("Make sure Flask is running: python run.py")
        sys.exit(1)


def test_db_connection():
    log("Testing DB connection via minimal engagement creation...")
    payload = {
        "engagement": "DB Connection Test",
        "client": "test",
        "mode": "passive",
        "executive_summary": {},
        "summary": {},
        "api_bom": {}
    }
    resp = requests.post(
        f"{BASE_URL}/api/scanner/engagement",
        json=payload,
        timeout=10
    )
    data = safe_json(resp)

    if not data.get("success"):
        log(f"DB connection FAILED: {data.get('error')}")
        log("Check your .env DB credentials and make sure MySQL is running.")
        sys.exit(1)

    engagement_id = data["data"]["engagement_id"]
    log(f"DB connection OK — test engagement created with id={engagement_id}")
    return engagement_id


def test_start_scan():
    log("Starting scan...")
    payload = {
        "domain": DOMAIN,
        "scanner_path": SCANNER_PATH,
        "mode": MODE,
        "client": CLIENT,
        "engagement": ENGAGEMENT,
        "scan_target_environment": "internal_non_prod"
    }
    resp = requests.post(
        f"{BASE_URL}/api/scanner/scan/start",
        json=payload,
        timeout=10
    )
    data = safe_json(resp)

    if not data.get("success"):
        log(f"FAILED to start scan: {data.get('error')}")
        sys.exit(1)

    job_id = data["data"]["job_id"]
    engagement_id = data["data"]["engagement_id"]
    log(f"Scan started — job_id: {job_id} | engagement_id: {engagement_id}")
    return job_id, engagement_id


def test_poll_status(job_id):
    log("Polling scan status (every 30s)...")
    poll_interval = 30
    max_polls = 240

    for i in range(max_polls):
        resp = requests.get(
            f"{BASE_URL}/api/scanner/scan/status/{job_id}",
            timeout=10
        )
        data = safe_json(resp)

        if not data.get("success"):
            log(f"Status check failed: {data.get('error')}")
            sys.exit(1)

        job = data["data"]
        status = job["status"]
        log(f"Status: {status}")

        if status == "completed":
            log("Scan + ingestion completed successfully.")
            return True

        if status == "failed":
            log("Scan FAILED.")
            log(f"Error  : {job.get('error')}")
            if job.get("scanner_stderr"):
                log(f"Stderr : {job['scanner_stderr'][-800:]}")
            if job.get("scanner_stdout"):
                log(f"Stdout : {job['scanner_stdout'][-500:]}")
            sys.exit(1)

        if status in ("queued", "scanning"):
            log(f"Waiting {poll_interval}s...")
            time.sleep(poll_interval)
        elif status == "ingesting":
            log("Ingesting into DB — waiting 10s...")
            time.sleep(10)
        else:
            time.sleep(poll_interval)

    log("Timed out waiting for scan to complete.")
    sys.exit(1)


def test_verify_db(engagement_id):
    log("Verifying counts via finalize endpoint...")
    resp = requests.post(
        f"{BASE_URL}/api/scanner/engagement/{engagement_id}/finalize",
        timeout=30
    )
    data = safe_json(resp)

    if not data.get("success"):
        log(f"Finalize failed: {data.get('error')}")
        return

    counts = data["data"]
    print("")
    print("  DB Verification Results:")
    print(f"  {'Total APIs':<20} : {counts.get('total_apis', 0)}")
    print(f"  {'Inbound':<20} : {counts.get('inbound', 0)}")
    print(f"  {'Outbound':<20} : {counts.get('outbound', 0)}")
    print(f"  {'Valid':<20} : {counts.get('valid', 0)}")
    print(f"  {'Shadow':<20} : {counts.get('shadow', 0)}")
    print(f"  {'New':<20} : {counts.get('new', 0)}")
    print(f"  {'Rogue':<20} : {counts.get('rogue', 0)}")
    print(f"  {'Secrets':<20} : {counts.get('secrets', 0)}")
    print(f"  {'OWASP Findings':<20} : {counts.get('owasp_findings', 0)}")
    print(f"  {'CVE Findings':<20} : {counts.get('cve_findings', 0)}")
    print("")

    if counts.get("total_apis", 0) > 0:
        log("PASS — Data is in the database.")
    else:
        log("WARN — total_apis is 0. Scan may have produced no endpoints.")


def test_list_jobs():
    log("Listing all existing jobs...")
    resp = requests.get(f"{BASE_URL}/api/scanner/scan/jobs", timeout=5)
    data = safe_json(resp)
    if data.get("success"):
        jobs = data["data"]
        log(f"Total jobs so far: {len(jobs)}")
        for j in jobs:
            print(f"  job={j['job_id'][:8]}... | eng={j['engagement_id']} | status={j['status']} | domain={j['domain']}")


if __name__ == "__main__":
    print("=" * 60)
    print("  API Discovery Platform — Full Test")
    print("=" * 60)
    print("")

    test_health()
    test_db_connection()
    test_list_jobs()

    job_id, engagement_id = test_start_scan()
    test_poll_status(job_id)
    test_verify_db(engagement_id)

    print("=" * 60)
    print("  All tests passed.")
    print("=" * 60)