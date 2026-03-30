import asyncio
import argparse
import os
import sys
from datetime import datetime

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from store.store import APIStore
from pipeline.p01_external_scan.scanner import ExternalScanner
from pipeline.p02_source_scan.scanner import SourceScanner
from pipeline.p03_log_analysis.scanner import LogAnalyzer
from pipeline.p04_traffic_analysis.scanner import TrafficAnalyzer
from pipeline.p05_gateway_query.scanner import GatewayScanner
from pipeline.p06_classifier.classifier import Classifier
from pipeline.p07_owasp.scanner import OWASPScanner
from pipeline.p08_enrichment.enricher import Enricher
from pipeline.p09_reporter.reporter import Reporter


def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        print(f"Config file not found: {path}")
        print("Create config.yaml or use --config to specify path")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def load_domains(cfg: dict) -> list:
    domains_file = cfg.get("inputs", {}).get("domains_file", "inputs/domains.txt")
    if not os.path.exists(domains_file):
        return []
    with open(domains_file) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


async def run(cfg: dict, mode_override: str = None):
    if mode_override:
        cfg.setdefault("scan", {})["mode"] = mode_override

    mode = cfg.get("scan", {}).get("mode", "passive")
    client = cfg.get("output", {}).get("client_name", "Client")
    engagement = cfg.get("output", {}).get("engagement_name", "API Discovery")
    pipeline = cfg.get("pipeline", {})

    print(f"\n{'='*65}")
    print(f"  API Discovery Platform")
    print(f"  Engagement : {engagement}")
    print(f"  Client     : {client}")
    print(f"  Mode       : {mode.upper()}")
    print(f"  Started    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*65}\n")

    store = APIStore()
    domains = load_domains(cfg)

    
    if pipeline.get("external_scan", True) and domains:
        print(f"[1/9] External Scan ({len(domains)} domain(s))")
        scan_cfg = {
            **cfg.get("scan", {}),
            "wordlist": cfg.get("scan", {}).get("wordlist", "wordlists/combined.txt"),
        }
        for domain in domains:
            print(f"  Target: {domain}")
            scanner = ExternalScanner(domain, store, scan_cfg)
            await scanner.run()
    elif pipeline.get("external_scan", True):
        print("[1/9] External Scan — no domains in inputs/domains.txt, skipping")
    else:
        print("[1/9] External Scan — disabled")

   
    if pipeline.get("source_scan", True):
        print("\n[2/9] Source Code Scan")
        source_cfg = {**cfg.get("source_scan", {}),
                      "repos_file": cfg.get("inputs", {}).get("repos_file", "inputs/repos.txt")}
        scanner = SourceScanner(store, source_cfg)
        await scanner.run()
    else:
        print("\n[2/9] Source Code Scan — disabled")

    
    if pipeline.get("log_analysis", True):
        print("\n[3/9] Log Analysis")
        log_cfg = {"logs_dir": cfg.get("inputs", {}).get("logs_dir", "inputs/logs")}
        analyzer = LogAnalyzer(store, log_cfg)
        await analyzer.run()
    else:
        print("\n[3/9] Log Analysis — disabled")

 
    if pipeline.get("traffic_analysis", True):
        print("\n[4/9] Traffic Analysis (PCAP + Live Agent)")
        traffic_cfg = {
            "pcap_dir": cfg.get("inputs", {}).get("pcap_dir", "inputs/pcap"),
            "agent": cfg.get("agent", {}),
        }
        analyzer = TrafficAnalyzer(store, traffic_cfg)
        await analyzer.run()
    else:
        print("\n[4/9] Traffic Analysis — disabled")

   
    if pipeline.get("gateway_query", True):
        print("\n[5/9] Gateway & Infrastructure Interrogation")
        gw_cfg = {
            "gateways": cfg.get("gateways", {}),
            "inputs": cfg.get("inputs", {}),
        }
        scanner = GatewayScanner(store, gw_cfg)
        await scanner.run()
    else:
        print("\n[5/9] Gateway Interrogation — disabled")

    counts_before = store.count()
    print(f"\n  Discovery complete: {counts_before['total']} total endpoints found")
    print(f"  Sources: external_scan, source_code, logs, traffic, gateways\n")

   
    if pipeline.get("classifier", True):
        print("[6/9] Classification (Valid / Shadow / New / Rogue)")
        classifier = Classifier(store, cfg)
        await classifier.run()
    else:
        print("[6/9] Classification — disabled")

    
    if pipeline.get("owasp", True):
        print(f"\n[7/9] OWASP API Top 10 Assessment [mode={mode}]")
        owasp = OWASPScanner(store, cfg)
        await owasp.run()
    else:
        print("\n[7/9] OWASP Assessment — disabled")

    
    if pipeline.get("enrichment", True):
        print("\n[8/9] Enrichment (auth, sensitivity, CVE, risk scoring)")
        enricher = Enricher(store, cfg)
        await enricher.run()
    else:
        print("\n[8/9] Enrichment — disabled")

   
    if pipeline.get("reporter", True):
        print("\n[9/9] Generating Reports (JSON + PDF + Word)")
        reporter = Reporter(store, cfg)
        await reporter.run()
    else:
        print("\n[9/9] Reporter — disabled")


def main():
    parser = argparse.ArgumentParser(
        description="API Discovery Platform "
    )
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("--mode", choices=["passive", "active"], default=None,
                        help="Override scan mode: passive (safe) or active (full OWASP testing)")
    parser.add_argument("--domain", default=None,
                        help="Single domain to scan (overrides inputs/domains.txt)")
    parser.add_argument("--disable-phase", nargs="+", default=[],
                        help="Disable pipeline phases e.g. --disable-phase owasp traffic_analysis")
    args = parser.parse_args()

    cfg = load_config(args.config)

    
    if args.domain:
        domains_file = cfg.get("inputs", {}).get("domains_file", "inputs/domains.txt")
        os.makedirs(os.path.dirname(domains_file) or ".", exist_ok=True)
        with open(domains_file, "w") as f:
            f.write(args.domain + "\n")

    
    for phase in args.disable_phase:
        cfg.setdefault("pipeline", {})[phase] = False

    asyncio.run(run(cfg, mode_override=args.mode))


if __name__ == "__main__":
    main()
