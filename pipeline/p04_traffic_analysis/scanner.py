import os
import re
import asyncio
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"}
API_INDICATORS = ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", "/rpc", "/query", "/data/", "/_api"]


def _is_api_path(path: str) -> bool:
    p = path.lower()
    return any(ind in p for ind in API_INDICATORS)


def _parse_http_from_bytes(data: bytes) -> Optional[Dict]:
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n" if "\r\n" in text else "\n")
        if not lines:
            return None
        first = lines[0].strip()
        parts = first.split(" ")
        if len(parts) < 2:
            return None
        if parts[0].upper() in HTTP_METHODS:
            method = parts[0].upper()
            path = parts[1].split("?")[0]
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.lower()] = v
            return {
                "method": method,
                "path": path,
                "host": headers.get("host", ""),
                "auth": headers.get("authorization", ""),
                "content_type": headers.get("content-type", ""),
                "user_agent": headers.get("user-agent", ""),
            }
    except Exception:
        pass
    return None


class PCAPParser:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg

    async def run(self):
        pcap_dir = self.cfg.get("pcap_dir", "inputs/pcap")
        if not os.path.exists(pcap_dir):
            print("    No PCAP directory — skipping traffic analysis")
            return

        pcap_files = [
            os.path.join(pcap_dir, f)
            for f in os.listdir(pcap_dir)
            if f.endswith((".pcap", ".pcapng", ".cap"))
        ]

        if not pcap_files:
            print("    No PCAP files found — skipping traffic analysis")
            return

        print(f"    Parsing {len(pcap_files)} PCAP file(s)...")
        total = 0
        for fpath in pcap_files:
            found = await asyncio.get_event_loop().run_in_executor(
                None, self._parse_pcap, fpath
            )
            total += found

        print(f"    PCAP analysis: {total} API endpoints extracted")

    def _parse_pcap(self, fpath: str) -> int:
        found = 0
        # Try pyshark first (wraps tshark — best HTTPS support with keylog)
        try:
            import pyshark
            keylog = self.cfg.get("agent", {}).get("keylog_file", "")
            override_prefs = {}
            if keylog and os.path.exists(keylog):
                override_prefs["tls.keylog_file"] = keylog

            cap = pyshark.FileCapture(
                fpath,
                display_filter="http || http2",
                override_prefs=override_prefs if override_prefs else None,
            )
            for pkt in cap:
                try:
                    entry = self._extract_pyshark(pkt)
                    if entry:
                        import asyncio
                        loop = asyncio.new_event_loop()
                        try:
                            loop.run_until_complete(
                                self.store.upsert(
                                    entry["path"], entry["method"], "pcap_analysis",
                                    evidence={
                                        "pcap_file": os.path.basename(fpath),
                                        "host": entry.get("host", ""),
                                        "auth_header": entry.get("auth", ""),
                                    },
                                    tags=["from_pcap"],
                                )
                            )
                            found += 1
                        finally:
                            loop.close()
                except Exception:
                    pass
            cap.close()
            return found

        except ImportError:
            pass

        # Fallback: scapy raw parsing
        try:
            from scapy.all import rdpcap, TCP, Raw
            pkts = rdpcap(fpath)
            for pkt in pkts:
                if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                    continue
                entry = _parse_http_from_bytes(bytes(pkt[Raw]))
                if not entry or not _is_api_path(entry.get("path", "")):
                    continue
                path = entry["path"]
                host = entry.get("host", "")
                full = f"http://{host}{path}" if host else path
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(
                        self.store.upsert(
                            full, entry["method"], "pcap_scapy",
                            evidence={"pcap_file": os.path.basename(fpath)},
                            tags=["from_pcap"],
                        )
                    )
                    found += 1
                finally:
                    loop.close()
            return found

        except ImportError:
            print("    Install pyshark or scapy for PCAP analysis: pip install pyshark scapy")
            return 0
        except Exception as e:
            print(f"    PCAP parse error {os.path.basename(fpath)}: {e}")
            return 0

    def _extract_pyshark(self, pkt) -> Optional[Dict]:
        try:
            if hasattr(pkt, "http"):
                layer = pkt.http
                method = getattr(layer, "request_method", None)
                if not method:
                    return None
                path = getattr(layer, "request_uri", "/")
                host = getattr(layer, "host", "")
                auth = getattr(layer, "authorization", "")
                full = f"http://{host}{path}" if host else path
                if not _is_api_path(path):
                    return None
                return {"method": method.upper(), "path": full, "host": host, "auth": auth}
            if hasattr(pkt, "http2"):
                layer = pkt.http2
                method = getattr(layer, "headers_method", None)
                if not method:
                    return None
                path = getattr(layer, "headers_path", "/")
                auth = getattr(layer, "headers_authorization", "")
                host = getattr(layer, "headers_authority", "")
                full = f"https://{host}{path}" if host else path
                if not _is_api_path(path):
                    return None
                return {"method": method.upper(), "path": full, "host": host, "auth": auth}
        except Exception:
            pass
        return None


class LiveAgent:
    """
    Live traffic sniffing agent.
    TLS modes:
      mirror   — receives already-decrypted traffic from LB mirror port
      keylog   — uses NSS TLS key log file for decryption
      http_only — only captures cleartext HTTP
    Run as: python -m pipeline.p04_traffic_analysis.scanner --live
    """

    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg
        self.agent_cfg = cfg.get("agent", {})
        self._running = False

    async def run(self):
        if not self.agent_cfg.get("enabled", False):
            return

        tls_mode = self.agent_cfg.get("tls_mode", "http_only")
        interface = self.agent_cfg.get("interface", "eth0")
        interval = self.agent_cfg.get("output_interval_seconds", 30)

        print(f"    Live agent starting: interface={interface} tls_mode={tls_mode}")
        self._running = True

        if tls_mode == "mirror":
            await self._sniff_mirror(interface, interval)
        elif tls_mode == "keylog":
            await self._sniff_keylog(interface, interval)
        else:
            await self._sniff_http_only(interface, interval)

    async def _sniff_http_only(self, interface: str, interval: int):
        try:
            import pyshark
            loop = asyncio.get_event_loop()

            def _callback(pkt):
                try:
                    if hasattr(pkt, "http"):
                        method = getattr(pkt.http, "request_method", None)
                        if not method:
                            return
                        path = getattr(pkt.http, "request_uri", "/")
                        host = getattr(pkt.http, "host", "")
                        full = f"http://{host}{path}" if host else path
                        if _is_api_path(path):
                            asyncio.run_coroutine_threadsafe(
                                self.store.upsert(full, method.upper(), "live_agent_http",
                                                  tags=["live_traffic"]),
                                loop
                            )
                except Exception:
                    pass

            cap = pyshark.LiveCapture(interface=interface, display_filter="http")
            cap.apply_on_packets(_callback)

        except ImportError:
            print("    pyshark required for live agent: pip install pyshark")
        except Exception as e:
            print(f"    Live agent error: {e}")

    async def _sniff_mirror(self, interface: str, interval: int):
        # Mirror mode: LB sends decrypted copy here — same as HTTP sniffing
        # but we also watch for HTTP/2 on the mirror port
        await self._sniff_http_only(interface, interval)

    async def _sniff_keylog(self, interface: str, interval: int):
        try:
            import pyshark
            keylog = self.agent_cfg.get("keylog_file", "")
            loop = asyncio.get_event_loop()

            def _callback(pkt):
                try:
                    for proto in ["http", "http2"]:
                        if hasattr(pkt, proto):
                            layer = getattr(pkt, proto)
                            method = getattr(layer, "request_method", None) or \
                                     getattr(layer, "headers_method", None)
                            if not method:
                                return
                            path = getattr(layer, "request_uri", None) or \
                                   getattr(layer, "headers_path", "/")
                            host = getattr(layer, "host", None) or \
                                   getattr(layer, "headers_authority", "")
                            scheme = "https" if proto == "http2" else "http"
                            full = f"{scheme}://{host}{path}" if host else path
                            if _is_api_path(path):
                                asyncio.run_coroutine_threadsafe(
                                    self.store.upsert(full, method.upper(), "live_agent_tls",
                                                      tags=["live_traffic", "tls_decrypted"]),
                                    loop
                                )
                except Exception:
                    pass

            override = {"tls.keylog_file": keylog} if keylog else {}
            cap = pyshark.LiveCapture(
                interface=interface,
                display_filter="http || http2 || tls",
                override_prefs=override,
            )
            cap.apply_on_packets(_callback)

        except ImportError:
            print("    pyshark required for live agent: pip install pyshark")
        except Exception as e:
            print(f"    Live agent TLS error: {e}")


class TrafficAnalyzer:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg
        self.pcap = PCAPParser(store, cfg)
        self.agent = LiveAgent(store, cfg)

    async def run(self):
        await self.pcap.run()
        await self.agent.run()
