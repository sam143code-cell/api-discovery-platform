import os


BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR       = os.path.join(BASE_DIR, "scans")
WORDLIST_PATH   = os.path.join(BASE_DIR, "wordlists", "combined.txt")
REPO_CLONE_ROOT = os.path.join(BASE_DIR, "Repository")


def build_cfg(
    scan_id:     str,
    domain:      str,
    repo_path:   str | None,
    client_name: str,
    app_name:    str,
    has_pcap:    bool = False,
) -> dict:
    scan_dir     = os.path.join(SCANS_DIR, scan_id)
    inputs_dir   = os.path.join(scan_dir, "inputs")
    output_dir   = os.path.join(scan_dir, "output")
    domains_file = os.path.join(inputs_dir, "domains.txt")
    repos_file   = os.path.join(inputs_dir, "repos.txt")
    pcap_dir     = os.path.join(inputs_dir, "pcap")
    spec_dir     = os.path.join(inputs_dir, "openapi_specs")

    os.makedirs(inputs_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    with open(domains_file, "w") as f:
        f.write(domain.strip() + "\n")

    if repo_path:
        with open(repos_file, "w") as f:
            f.write(repo_path.strip() + "\n")

    has_openapi_specs = os.path.isdir(spec_dir) and bool(os.listdir(spec_dir))

    return {
        "inputs": {
            "domains_file":        domains_file,
            "repos_file":          repos_file if repo_path else "",
            "gateway_exports_dir": os.path.join(inputs_dir, "gateway_exports"),
            "openapi_specs_dir":   spec_dir,
            "logs_dir":            os.path.join(inputs_dir, "logs"),
            "pcap_dir":            pcap_dir,
            "baseline_file":       os.path.join(inputs_dir, "baseline.json"),
        },
        "scan": {
            "mode":                "passive",
            "concurrency":         20,
            "timeout":             12,
            "max_pages":           300,
            "wordlist":            WORDLIST_PATH if os.path.exists(WORDLIST_PATH) else "",
            "js_crawl":            True,
            "subdomain_discovery": True,
            "user_agent":          "Mozilla/5.0 (compatible; APIDiscovery/1.0)",
            "brute_force": {
                "enabled":            True,
                "concurrency":        10,
                "max_paths":          50000,
                "exclude_extensions": [".htm", ".html", ".htaccess", ".htpasswd", ".htc", ".hts", ".hta"],
                "exclude_prefixes":   ["/.ht", "/.htm", "/.html"],
            },
        },
        "pipeline": {
            "external_scan":    True,
            "source_scan":      bool(repo_path),
            "log_analysis":     False,
            "traffic_analysis": has_pcap,
            "gateway_query":    False,
            "classifier":       True,
            "owasp":            True,
            "enrichment":       True,
            "reporter":         True,
        },
        "agent": {
            "enabled": False,
        },
        "gateways": {},
        "source_scan": {
            "repo_paths":      [repo_path] if repo_path else [],
            "run_semgrep":     False,
            "run_secret_scan": True,
            "clone_depth":     1,
        },
        "owasp": {
            "test_bola":             True,
            "test_broken_auth":      True,
            "test_mass_assignment":  False,
            "test_rate_limit":       False,
            "test_bfla":             False,
            "test_ssrf":             False,
            "test_misconfiguration": True,
            "test_inventory":        True,
            "active_delay_ms":       500,
        },
        "classification": {
            "use_gateway_export": True,
            "use_openapi_specs":  has_openapi_specs,
            "use_baseline_json":  True,
            "new_api_since":      "",
            "rogue_patterns": [
                "/debug", "/internal", "/admin",
                "/.env", "/actuator", "/phpinfo",
            ],
        },
        "output": {
            "directory":               output_dir,
            "json":                    True,
            "pdf":                     False,
            "word":                    False,
            "client_name":             client_name,
            "app_name":                app_name,
            "engagement_name":         "API Discovery & Security Evaluation",
            "scan_target_environment": "unknown",
        },
    }