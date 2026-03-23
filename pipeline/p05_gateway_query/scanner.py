import os
import re
import json
import asyncio
from typing import Dict, List, Optional
import requests

requests.packages.urllib3.disable_warnings()


class GatewayScanner:
    def __init__(self, store, cfg: dict):
        self.store = store
        self.cfg = cfg
        self.gateway_cfg = cfg.get("gateways", {})

    async def run(self):
        tasks = []
        if self.gateway_cfg.get("kong", {}).get("enabled"):
            tasks.append(self._scan_kong())
        if self.gateway_cfg.get("aws_apigw", {}).get("enabled"):
            tasks.append(self._scan_aws())
        if self.gateway_cfg.get("apigee", {}).get("enabled"):
            tasks.append(self._scan_apigee())
        if self.gateway_cfg.get("azure_apim", {}).get("enabled"):
            tasks.append(self._scan_azure())

        # Always try file-based sources
        tasks.append(self._scan_gateway_exports())
        tasks.append(self._scan_nginx_configs())
        tasks.append(self._scan_k8s_manifests())

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_kong(self):
        cfg = self.gateway_cfg.get("kong", {})
        admin_url = cfg.get("admin_url", "http://kong:8001")
        token = cfg.get("token", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        print(f"    Querying Kong Admin API: {admin_url}")
        try:
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: requests.get(f"{admin_url}/routes", headers=headers,
                                     verify=False, timeout=10)
            )
            if resp.status_code == 200:
                data = resp.json()
                routes = data.get("data", [])
                for route in routes:
                    paths = route.get("paths") or ["/"]
                    methods = route.get("methods") or ["GET"]
                    service_name = route.get("service", {}).get("name", "unknown")
                    for path in paths:
                        for method in methods:
                            await self.store.upsert(
                                path, method, "kong_gateway",
                                baseline_status="in_gateway",
                                owner=service_name,
                                tags=["gateway_registered"],
                                evidence={"gateway": "kong", "route_id": route.get("id", "")},
                            )
                print(f"    Kong: {len(routes)} routes found")
        except Exception as e:
            print(f"    Kong query failed: {e}")

    async def _scan_aws(self):
        cfg = self.gateway_cfg.get("aws_apigw", {})
        print(f"    Querying AWS API Gateway...")
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=cfg.get("access_key"),
                aws_secret_access_key=cfg.get("secret_key"),
                region_name=cfg.get("region", "ap-south-1"),
            )
            client = session.client("apigateway")
            apis = client.get_rest_apis().get("items", [])
            for api in apis:
                api_id = api["id"]
                resources = client.get_resources(restApiId=api_id).get("items", [])
                for res in resources:
                    path = res.get("path", "/")
                    for method in (res.get("resourceMethods") or {}).keys():
                        await self.store.upsert(
                            path, method, "aws_api_gateway",
                            baseline_status="in_gateway",
                            tags=["gateway_registered"],
                            evidence={"gateway": "aws_apigw", "api_id": api_id,
                                      "api_name": api.get("name", "")},
                        )
            print(f"    AWS API GW: {len(apis)} APIs scanned")
        except ImportError:
            print("    boto3 required for AWS: pip install boto3")
        except Exception as e:
            print(f"    AWS query failed: {e}")

    async def _scan_apigee(self):
        cfg = self.gateway_cfg.get("apigee", {})
        org = cfg.get("org", "")
        token = cfg.get("token", "")
        print(f"    Querying Apigee: {org}")
        try:
            loop = asyncio.get_event_loop()
            headers = {"Authorization": f"Bearer {token}"}
            resp = await loop.run_in_executor(
                None,
                lambda: requests.get(
                    f"https://apigee.googleapis.com/v1/organizations/{org}/apis",
                    headers=headers, timeout=10
                )
            )
            if resp.status_code == 200:
                apis = resp.json().get("proxies", [])
                for api in apis:
                    name = api.get("name", "")
                    await self.store.upsert(
                        f"/apigee/{name}", "GET", "apigee_gateway",
                        baseline_status="in_gateway",
                        owner=name,
                        tags=["gateway_registered"],
                        evidence={"gateway": "apigee", "proxy": name},
                    )
                print(f"    Apigee: {len(apis)} API proxies found")
        except Exception as e:
            print(f"    Apigee query failed: {e}")

    async def _scan_azure(self):
        cfg = self.gateway_cfg.get("azure_apim", {})
        print(f"    Querying Azure API Management...")
        try:
            sub = cfg.get("subscription_id", "")
            rg = cfg.get("resource_group", "")
            svc = cfg.get("service_name", "")
            token = cfg.get("token", "")
            url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
                   f"/providers/Microsoft.ApiManagement/service/{svc}/apis?api-version=2022-08-01")
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
            )
            if resp.status_code == 200:
                apis = resp.json().get("value", [])
                for api in apis:
                    props = api.get("properties", {})
                    path = props.get("path", "/")
                    await self.store.upsert(
                        f"/{path}", "GET", "azure_apim",
                        baseline_status="in_gateway",
                        tags=["gateway_registered"],
                        evidence={"gateway": "azure_apim", "api_id": api.get("id", "")},
                    )
                print(f"    Azure APIM: {len(apis)} APIs found")
        except Exception as e:
            print(f"    Azure APIM query failed: {e}")

    async def _scan_gateway_exports(self):
        exports_dir = self.cfg.get("inputs", {}).get("gateway_exports_dir", "inputs/gateway_exports")
        if not os.path.exists(exports_dir):
            return
        files = [f for f in os.listdir(exports_dir) if f.endswith((".json", ".yaml", ".yml"))]
        for fname in files:
            fpath = os.path.join(exports_dir, fname)
            try:
                with open(fpath) as f:
                    if fname.endswith(".json"):
                        data = json.load(f)
                    else:
                        import yaml
                        data = yaml.safe_load(f)
                # OpenAPI format
                if "paths" in data:
                    for path, methods in data["paths"].items():
                        if isinstance(methods, dict):
                            for method in methods.keys():
                                if method.upper() in ["GET", "POST", "PUT", "DELETE",
                                                      "PATCH", "OPTIONS", "HEAD"]:
                                    await self.store.upsert(
                                        path, method.upper(), "gateway_export_file",
                                        baseline_status="in_gateway",
                                        tags=["gateway_registered"],
                                        evidence={"source_file": fname},
                                    )
                # Kong deck format
                elif "services" in data:
                    for svc in data.get("services", []):
                        for route in svc.get("routes", []):
                            for path in (route.get("paths") or ["/"]):
                                for method in (route.get("methods") or ["GET"]):
                                    await self.store.upsert(
                                        path, method, "kong_deck_export",
                                        baseline_status="in_gateway",
                                        owner=svc.get("name", ""),
                                        tags=["gateway_registered"],
                                        evidence={"source_file": fname},
                                    )
            except Exception as e:
                print(f"    Gateway export parse error {fname}: {e}")

    async def _scan_nginx_configs(self):
        for search_dir in ["inputs/gateway_exports", "inputs", "."]:
            for root, _, files in os.walk(search_dir):
                for fname in files:
                    if fname in ("nginx.conf", "default.conf") or fname.endswith(".nginx"):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath) as f:
                                content = f.read()
                            for m in re.finditer(r'location\s+([~*]*)\s*([^\s{]+)\s*\{', content):
                                path = m.group(2).strip()
                                if path.startswith("/"):
                                    await self.store.upsert(
                                        path, "GET", "nginx_config",
                                        baseline_status="in_gateway",
                                        tags=["nginx", "gateway_registered"],
                                        evidence={"config_file": fname},
                                    )
                        except Exception:
                            pass

    async def _scan_k8s_manifests(self):
        import yaml as _yaml
        for search_dir in ["inputs/gateway_exports", "inputs", "."]:
            for root, _, files in os.walk(search_dir):
                for fname in files:
                    if not fname.endswith((".yaml", ".yml")):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath) as f:
                            docs = list(_yaml.safe_load_all(f))
                        for doc in docs:
                            if not isinstance(doc, dict):
                                continue
                            kind = doc.get("kind", "")
                            # Kubernetes Ingress
                            if kind == "Ingress":
                                spec = doc.get("spec", {})
                                for rule in spec.get("rules", []):
                                    host = rule.get("host", "")
                                    for path_item in rule.get("http", {}).get("paths", []):
                                        path = path_item.get("path", "/")
                                        full = f"https://{host}{path}" if host else path
                                        await self.store.upsert(
                                            full, "GET", "k8s_ingress",
                                            baseline_status="in_gateway",
                                            tags=["kubernetes", "gateway_registered"],
                                            evidence={"manifest": fname, "host": host},
                                        )
                            # Istio VirtualService
                            elif kind == "VirtualService":
                                spec = doc.get("spec", {})
                                hosts = spec.get("hosts", [])
                                for http_route in spec.get("http", []):
                                    for match in http_route.get("match", []):
                                        uri = match.get("uri", {})
                                        path = (uri.get("exact") or uri.get("prefix") or
                                                uri.get("regex") or "/")
                                        for host in hosts:
                                            await self.store.upsert(
                                                f"https://{host}{path}", "GET", "istio_virtual_service",
                                                baseline_status="in_gateway",
                                                tags=["istio", "gateway_registered"],
                                                evidence={"manifest": fname},
                                            )
                    except Exception:
                        pass
