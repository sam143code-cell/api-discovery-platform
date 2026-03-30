import asyncio
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from store.store import APIStore
from pipeline.p01_external_scan.scanner import ExternalScanner
from pipeline.p02_source_scan.scanner   import SourceScanner
from pipeline.p03_log_analysis.scanner  import LogAnalyzer
from pipeline.p04_traffic_analysis.scanner import TrafficAnalyzer
from pipeline.p05_gateway_query.scanner import GatewayScanner
from pipeline.p06_classifier.classifier import Classifier
from pipeline.p07_owasp.scanner         import OWASPScanner
from pipeline.p08_enrichment.enricher   import Enricher
from pipeline.p09_reporter.reporter     import Reporter


async def run_pipeline(cfg: dict) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()
    pipeline   = cfg.get("pipeline", {})
    mode       = cfg.get("scan", {}).get("mode", "passive")
    domains_file = cfg.get("inputs", {}).get("domains_file", "")

    print(f"\n[pipeline] starting  mode={mode}  started={started_at}")

    store = APIStore()

    domains = []
    if os.path.exists(domains_file):
        with open(domains_file) as f:
            domains = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if pipeline.get("external_scan", True) and domains:
        print(f"[1/9] External Scan ({len(domains)} domain(s))")
        scan_cfg = {
            **cfg.get("scan", {}),
            "wordlist": cfg.get("scan", {}).get("wordlist", ""),
        }
        for domain in domains:
            print(f"      target: {domain}")
            scanner = ExternalScanner(domain, store, scan_cfg)
            await scanner.run()
    else:
        print("[1/9] External Scan — skipped")

    if pipeline.get("source_scan", True):
        print("\n[2/9] Source Code Scan")
        scanner = SourceScanner(store, cfg)
        await scanner.run()
    else:
        print("\n[2/9] Source Code Scan — skipped")

    if pipeline.get("log_analysis", True):
        print("\n[3/9] Log Analysis")
        log_cfg  = {"logs_dir": cfg.get("inputs", {}).get("logs_dir", "")}
        analyzer = LogAnalyzer(store, log_cfg)
        await analyzer.run()
    else:
        print("\n[3/9] Log Analysis — skipped")

    if pipeline.get("traffic_analysis", True):
        print("\n[4/9] Traffic Analysis")
        traffic_cfg = {
            "pcap_dir": cfg.get("inputs", {}).get("pcap_dir", ""),
            "agent":    cfg.get("agent", {}),
        }
        analyzer = TrafficAnalyzer(store, traffic_cfg)
        await analyzer.run()
    else:
        print("\n[4/9] Traffic Analysis — skipped")

    if pipeline.get("gateway_query", True):
        print("\n[5/9] Gateway Interrogation")
        gw_cfg = {
            "gateways": cfg.get("gateways", {}),
            "inputs":   cfg.get("inputs", {}),
        }
        scanner = GatewayScanner(store, gw_cfg)
        await scanner.run()
    else:
        print("\n[5/9] Gateway Interrogation — skipped")

    counts_before = store.count()
    print(f"\n      discovery complete: {counts_before['total']} endpoints found")

    if pipeline.get("classifier", True):
        print("\n[6/9] Classification")
        classifier = Classifier(store, cfg)
        await classifier.run()
    else:
        print("\n[6/9] Classification — skipped")

    if pipeline.get("owasp", True):
        print(f"\n[7/9] OWASP Assessment [mode={mode}]")
        owasp = OWASPScanner(store, cfg)
        await owasp.run()
    else:
        print("\n[7/9] OWASP Assessment — skipped")

    if pipeline.get("enrichment", True):
        print("\n[8/9] Enrichment")
        enricher = Enricher(store, cfg)
        await enricher.run()
    else:
        print("\n[8/9] Enrichment — skipped")

    if pipeline.get("reporter", True):
        print("\n[9/9] Generating Reports")
        reporter = Reporter(store, cfg)
        await reporter.run()
    else:
        print("\n[9/9] Reporter — skipped")

    counts       = store.count()
    output_dir   = cfg.get("output", {}).get("directory", "output")
    completed_at = datetime.now(timezone.utc).isoformat()

    output_files = {}
    for fname in (
        "api_discovery_full.json",
        "shadow_rogue_register.json",
        "secrets_findings.json",
        "outbound_api_inventory.json",
    ):
        fpath = os.path.join(output_dir, fname)
        if os.path.exists(fpath):
            output_files[fname] = fpath

    summary = {
        "total_endpoints":         counts.get("total", 0),
        "valid":                   counts.get("Valid", 0),
        "shadow":                  counts.get("Shadow", 0),
        "rogue":                   counts.get("Rogue", 0),
        "new":                     counts.get("New", 0),
        "secrets_found":           len(getattr(store, "secrets_found", [])),
        "outbound_apis":           len(getattr(store, "outbound_api_inventory", [])),
        "high_critical_risk":      sum(1 for e in store.all() if e.risk_score >= 50),
        "owasp_findings":          sum(len(e.owasp_flags) for e in store.all()),
        "cve_findings":            sum(len(e.cve_findings) for e in store.all()),
        "started_at":              started_at,
        "completed_at":            completed_at,
    }

    print(f"\n[pipeline] done  completed={completed_at}")
    return {"summary": summary, "output_files": output_files}
