import os
import re
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from store.schema import APIEntry


def _risk_band(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    return "LOW"


def _crit_counts(entries: List[APIEntry]) -> Dict:
    return {
        lvl: sum(1 for e in entries if e.data_sensitivity == lvl)
        for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    }


_ML_EXTENSIONS = re.compile(r"\.(h5|pkl|pt|pth|onnx|pb|model|bin)$", re.I)
_FILE_PATH      = re.compile(r"^(\.\.[\\/]|[A-Za-z]:\\|/home/|/var/|/etc/|/mnt/)")
_MALFORMED_URL  = re.compile(r"^/(https?://)")
_MIDDLEWARE     = re.compile(r"^/?(use|next|req|res|done|:id|:zoneId|:siteId)$", re.I)

def _is_noise(entry: APIEntry) -> bool:
    ep     = entry.endpoint or ""
    method = (entry.method or "").upper()
    if method == "N/A":           return True
    if _FILE_PATH.match(ep):      return True
    if _ML_EXTENSIONS.search(ep): return True
    if _MALFORMED_URL.match(ep):  return True
    if _MIDDLEWARE.match(ep):     return True
    return False


_MODULE_MAP = [
    (r"auth|login|logout|session|sso|saml|oidc|oauth|token|register|signup",  "Authentication & Session"),
    (r"user|account|profile|member",                                           "User Management"),
    (r"admin|management|backoffice|back.office|permission|role",               "Administration"),
    (r"upload|import|ingest|intake|file|attachment|media|asset",               "Data Upload & Ingestion"),
    (r"search|find|lookup|query|filter|autocomplete|suggest",                  "Search & Lookup"),
    (r"report|export|download|generate|render",                                "Reporting & Export"),
    (r"notify|notification|alert|email|sms|push|webhook",                     "Notifications"),
    (r"payment|billing|invoice|order|transaction|checkout|cart",               "Payments & Commerce"),
    (r"health|ping|status|liveness|readiness|metrics|probes",                  "Health & Monitoring"),
    (r"config|setting|preference|setup",                                       "Configuration"),
    (r"log|audit|event|history|activity|trace",                                "Audit & Logging"),
    (r"device|sensor|asset|inventory|host|server",                             "Asset & Device Management"),
    (r"risk|score|vulnerability|vuln|cve|threat|finding",                      "Risk & Vulnerability"),
    (r"integration|webhook|sync|connect|bridge|proxy|gateway",                 "Integration & Gateway"),
    (r"workflow|pipeline|job|task|queue|worker|schedule",                      "Workflow & Jobs"),
    (r"dashboard|home|index|overview|summary|widget",                          "Dashboard"),
    (r"analytics|metric|stat|trend|chart|graph|insight",                       "Analytics"),
    (r"public|open|docs|swagger|openapi|spec",                                 "Public / Documentation"),
    (r"internal|private|debug|actuator|heapdump",                              "Internal / Diagnostic"),
    (r"cloud|storage|bucket|blob|s3|gcs|azure",                                "Cloud & Storage"),
]

def _infer_module(entry: APIEntry) -> str:
    file_path = (entry.evidence.get("file", "") if entry.evidence else "").lower()
    endpoint  = (entry.endpoint or "").lower()
    combined  = file_path + " " + endpoint
    for pattern, module in _MODULE_MAP:
        if re.search(pattern, combined):
            return module
    return "Uncategorized"


def _infer_version(endpoint: str) -> Optional[str]:
    m = re.search(r"/v(\d+)(?:/|$)", endpoint or "")
    return f"v{m.group(1)}" if m else None


def _infer_owasp_flags(entry: APIEntry) -> List[Dict]:
    flags         = list(entry.owasp_flags)
    existing_cats = {f.get("category") for f in flags}
    ep     = entry.endpoint or ""
    method = (entry.method or "").upper()
    auth   = entry.auth_type or "None detected"

    if "API2" not in existing_cats and auth in ("None detected", "UNKNOWN", "none", ""):
        flags.append({
            "category":    "API2",
            "name":        "Broken Authentication",
            "finding":     "No authentication mechanism detected on this endpoint.",
            "severity":    "HIGH",
            "source":      "inferred",
            "remediation": "Enforce authentication middleware. Use JWT/OAuth2 with short-lived tokens.",
        })

    if "API8" not in existing_cats and ep.startswith("http://"):
        flags.append({
            "category":    "API8",
            "name":        "Security Misconfiguration",
            "finding":     "Endpoint exposed over unencrypted HTTP.",
            "severity":    "MEDIUM",
            "source":      "inferred",
            "remediation": "Enforce HTTPS. Redirect all HTTP traffic to HTTPS.",
        })

    if "API9" not in existing_cats and entry.classification in ("Shadow", "Rogue"):
        flags.append({
            "category":    "API9",
            "name":        "Improper Inventory Management",
            "finding":     "Endpoint not present in any API registry or specification.",
            "severity":    "MEDIUM",
            "source":      "inferred",
            "remediation": "Register in API gateway. Create OpenAPI 3.0 spec. Conduct ownership review.",
        })

    if "API9" not in existing_cats and method in ("UNKNOWN", "", "N/A"):
        flags.append({
            "category":    "API9",
            "name":        "Improper Inventory Management",
            "finding":     "HTTP method undocumented — API contract unknown.",
            "severity":    "LOW",
            "source":      "inferred",
            "remediation": "Document the expected HTTP method and add to OpenAPI spec.",
        })

    if "API1" not in existing_cats and re.search(r"/:\w+|/\{[\w]+\}", ep):
        flags.append({
            "category":    "API1",
            "name":        "Broken Object Level Authorization (BOLA)",
            "finding":     "Parameterized endpoint detected — BOLA risk requires manual testing.",
            "severity":    "HIGH",
            "source":      "inferred",
            "remediation": "Validate object-level access per user on every request.",
        })

    if "API10" not in existing_cats:
        file_path = (entry.evidence.get("file", "") if entry.evidence else "").lower()
        if any(x in file_path for x in ("external", "third", "integration", "outbound")):
            flags.append({
                "category":    "API10",
                "name":        "Unsafe Consumption of APIs",
                "finding":     "Endpoint integrates with external third-party API.",
                "severity":    "MEDIUM",
                "source":      "inferred",
                "remediation": "Validate all external API responses. Implement circuit breakers.",
            })

    return flags


_OUTBOUND_PATTERNS = [
    (r"virustotal",                    "VirusTotal",            "Threat Intelligence",  "External"),
    (r"shodan",                        "Shodan",                "Threat Intelligence",  "External"),
    (r"manageengine|servicedesk",      "ITSM Platform",         "ITSM Integration",     "Internal"),
    (r"servicenow",                    "ServiceNow",            "ITSM Integration",     "Internal"),
    (r"jira|atlassian",                "Issue Tracker",         "Issue Tracking",       "Internal"),
    (r"ldap|activedirectory",          "Directory Service",     "Identity Provider",    "Internal"),
    (r"okta|auth0|onelogin",           "Identity Provider",     "Identity Provider",    "External"),
    (r"gcp|googleapis|google\.cloud",  "Google Cloud",          "Cloud Provider",       "External"),
    (r"amazonaws\.com|aws\.",          "AWS",                   "Cloud Provider",       "External"),
    (r"azure\.com|microsoftonline",    "Azure / Microsoft",     "Cloud Provider",       "External"),
    (r"smtp|sendgrid|mailgun",         "Email Service",         "Notification",         "External"),
    (r"twilio|nexmo|vonage",           "SMS Service",           "Notification",         "External"),
    (r"kafka|rabbitmq|amqp",           "Message Broker",        "Async Messaging",      "Internal"),
    (r"elasticsearch|opensearch",      "Search Engine",         "Data Store",           "Internal"),
    (r"redis",                         "Redis",                 "Cache",                "Internal"),
    (r"splunk",                        "SIEM Platform",         "Security Monitoring",  "Internal"),
    (r"grafana|prometheus",            "Monitoring Platform",   "Monitoring",           "Internal"),
    (r"stripe|braintree|paypal",       "Payment Gateway",       "Payments",             "External"),
    (r"github\.com|api\.github",       "GitHub",                "Source Control",       "External"),
    (r"slack\.com",                    "Slack",                 "Notification",         "External"),
]

def _extract_outbound_deps(entries: List[APIEntry]) -> List[Dict]:
    found    = {}
    all_text = []
    for e in entries:
        evidence = e.evidence or {}
        all_text.extend([
            e.endpoint or "",
            evidence.get("file", "") or "",
            evidence.get("match", "") or "",
        ])
        for tag in (e.tags or []):
            all_text.append(str(tag))
    combined = " ".join(all_text).lower()

    for pattern, name, category, exposure in _OUTBOUND_PATTERNS:
        if re.search(pattern, combined) and name not in found:
            found[name] = {
                "integration":   name,
                "category":      category,
                "exposure":      exposure,
                "risk":          "HIGH" if exposure == "External" else "MEDIUM",
                "recommendation": (
                    f"Validate all data from {name}. Rotate API keys. Implement circuit breakers."
                    if exposure == "External" else
                    f"Ensure {name} uses TLS. Use service account with least-privilege."
                ),
            }
    return list(found.values())


def _detect_tech_stack(entries: List[APIEntry], cfg: dict = None) -> Dict:
    scanner_stack = (cfg or {}).get("tech_stack", {})
    cfg_runtime   = scanner_stack.get("runtime", "")
    cfg_framework = scanner_stack.get("framework", "")

    files = []
    for e in entries:
        if e.evidence:
            f = (e.evidence.get("file", "") or "").lower()
            if f:
                files.append(f)
    combined = " ".join(files)

    if cfg_runtime:
        runtime = cfg_runtime
    elif any(f.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")) for f in files):
        runtime = "Node.js"
    elif any(f.endswith(".py") for f in files):
        runtime = "Python"
    elif any(f.endswith((".java", ".kt")) for f in files):
        runtime = "JVM"
    elif any(f.endswith(".cs") for f in files):
        runtime = ".NET"
    else:
        runtime = "Unknown"

    if cfg_framework and cfg_framework.lower() not in ("unknown", ""):
        framework = cfg_framework
    else:
        endpoint_sample    = " ".join(e.endpoint or "" for e in entries[:200]).lower()
        has_express_params = bool(re.search(r"/:\w+", endpoint_sample))
        has_express_files  = any("route" in f or "controller" in f or "middleware" in f for f in files)
        has_nest           = any("module.ts" in f or "controller.ts" in f for f in files)
        has_spring         = "spring" in combined or any(f.endswith((".java", ".kt")) for f in files)
        has_aspnet         = any(f.endswith(".cs") for f in files)
        has_flask          = "flask" in combined
        has_fastapi        = "fastapi" in combined

        if runtime == "Node.js" and has_nest:
            framework = "NestJS"
        elif runtime == "Node.js" and (has_express_params or has_express_files):
            framework = "Express.js"
        elif runtime == "Python" and has_fastapi:
            framework = "FastAPI"
        elif runtime == "Python" and (has_flask or any("route" in f for f in files)):
            framework = "Flask"
        elif runtime == "Python":
            framework = "Django / Python (framework not confirmed)"
        elif runtime == "JVM" and has_spring:
            framework = "Spring Boot"
        elif runtime == "JVM":
            framework = "JVM (framework not confirmed)"
        elif runtime == ".NET" and has_aspnet:
            framework = "ASP.NET Core"
        elif runtime == ".NET":
            framework = ".NET (framework not confirmed)"
        else:
            framework = f"{runtime} (framework not detected)" if runtime != "Unknown" else "Unknown"

    lang_map  = {
        "Node.js": "JavaScript/TypeScript",
        "Python":  "Python",
        "JVM":     "Java/Kotlin",
        ".NET":    "C#",
    }
    lang      = lang_map.get(runtime, "Unknown")
    has_react = any("component" in f or f.endswith((".tsx", ".jsx")) for f in files)
    frontend  = "React SPA" if has_react else "Unknown"
    indicators = []
    if has_express_params if 'has_express_params' in dir() else False:
        indicators.append("Express-style path parameters detected (/:id patterns)")
    if has_react:
        indicators.append("React component files (.tsx/.jsx) detected in source")
    if cfg_framework:
        indicators.append(f"Framework confirmed by scanner: {cfg_framework}")

    return {
        "runtime":    runtime,
        "language":   lang,
        "framework":  framework,
        "frontend":   frontend,
        "indicators": indicators,
    }


def _build_owasp_conformance(entries: List[APIEntry], all_flags: List[Dict]) -> List[Dict]:
    total     = len(entries)
    flag_cats = {}
    for f in all_flags:
        flag_cats.setdefault(f.get("category", ""), []).append(f)
    no_auth   = sum(1 for e in entries if (e.auth_type or "") in ("None detected", "UNKNOWN", "none", ""))
    shadow    = sum(1 for e in entries if e.classification in ("Shadow", "Rogue"))
    param_eps = sum(1 for e in entries if re.search(r"/:\w+|/\{[\w]+\}", e.endpoint or ""))

    return [
        {
            "owasp_id":         "API1",
            "name":             "Broken Object Level Authorization (BOLA)",
            "status":           "REQUIRES TESTING",
            "affected_count":   param_eps,
            "note":             f"{param_eps} parameterized endpoints — manual pen-test required.",
            "conformance_level": "Level 0 — Not Tested",
        },
        {
            "owasp_id":         "API2",
            "name":             "Broken Authentication",
            "status":           "FAIL" if no_auth > 0 else "PASS",
            "affected_count":   no_auth,
            "note":             f"{no_auth} of {total} endpoints have no detectable authentication.",
            "conformance_level": "Level 0 — Non-Conformant" if no_auth > 0 else "Level 2 — Conformant",
        },
        {
            "owasp_id":         "API3",
            "name":             "Broken Object Property Level Authorization",
            "status":           "NOT TESTED",
            "affected_count":   0,
            "note":             "Requires runtime testing.",
            "conformance_level": "Level 0 — Not Tested",
        },
        {
            "owasp_id":         "API4",
            "name":             "Unrestricted Resource Consumption",
            "status":           "NOT TESTED",
            "affected_count":   0,
            "note":             "Rate limiting not assessable without live traffic.",
            "conformance_level": "Level 0 — Not Tested",
        },
        {
            "owasp_id":         "API5",
            "name":             "Broken Function Level Authorization",
            "status":           "REQUIRES TESTING",
            "affected_count":   len(flag_cats.get("API5", [])),
            "note":             "Admin endpoints identified — role-based access validation required.",
            "conformance_level": "Level 0 — Not Tested",
        },
        {
            "owasp_id":         "API6",
            "name":             "Unrestricted Access to Sensitive Business Flows",
            "status":           "NOT TESTED",
            "affected_count":   0,
            "note":             "Requires business logic review and runtime testing.",
            "conformance_level": "Level 0 — Not Tested",
        },
        {
            "owasp_id":         "API7",
            "name":             "Server Side Request Forgery (SSRF)",
            "status":           "NOT TESTED",
            "affected_count":   0,
            "note":             "Active probing not performed in passive mode.",
            "conformance_level": "Level 0 — Not Tested",
        },
        {
            "owasp_id":         "API8",
            "name":             "Security Misconfiguration",
            "status":           "FAIL" if flag_cats.get("API8") else "PARTIAL",
            "affected_count":   len(flag_cats.get("API8", [])),
            "note":             f"{len(flag_cats.get('API8', []))} misconfiguration findings detected.",
            "conformance_level": "Level 1 — Partial",
        },
        {
            "owasp_id":         "API9",
            "name":             "Improper Inventory Management",
            "status":           "FAIL" if shadow > 0 else "PASS",
            "affected_count":   shadow,
            "note":             f"{shadow} unregistered endpoints discovered.",
            "conformance_level": "Level 0 — Non-Conformant" if shadow > 0 else "Level 2 — Conformant",
        },
        {
            "owasp_id":         "API10",
            "name":             "Unsafe Consumption of APIs",
            "status":           "REQUIRES REVIEW",
            "affected_count":   len(flag_cats.get("API10", [])),
            "note":             "External API integrations detected — consumption patterns require review.",
            "conformance_level": "Level 0 — Not Tested",
        },
    ]


def _build_inbound_outbound_summary(inbound_entries: List[APIEntry],
                                     outbound_inventory: List[Dict],
                                     app_name: str) -> Dict:
    inbound_by_sensitivity = _crit_counts(inbound_entries)
    inbound_by_method: Dict[str, int] = {}
    for e in inbound_entries:
        m = e.method or "UNKNOWN"
        inbound_by_method[m] = inbound_by_method.get(m, 0) + 1

    inbound_by_module: Dict[str, int] = {}
    for e in inbound_entries:
        mod = _infer_module(e)
        inbound_by_module[mod] = inbound_by_module.get(mod, 0) + 1

    clean_outbound = []
    for entry in outbound_inventory:
        clean = {k: v for k, v in entry.items() if not k.startswith("_")}
        clean_outbound.append(clean)

    outbound_by_exposure: Dict[str, int] = {}
    outbound_by_category: Dict[str, int] = {}
    outbound_by_auth: Dict[str, int]     = {}
    for entry in clean_outbound:
        exp  = entry.get("exposure", "Unknown")
        cat  = entry.get("category", "Unknown")
        auth = entry.get("auth_method", "unknown")
        outbound_by_exposure[exp]  = outbound_by_exposure.get(exp, 0) + 1
        outbound_by_category[cat]  = outbound_by_category.get(cat, 0) + 1
        outbound_by_auth[auth]     = outbound_by_auth.get(auth, 0) + 1

    hardcoded_key_count = sum(1 for e in clean_outbound if e.get("auth_method") == "hardcoded_key")
    external_outbound   = sum(1 for e in clean_outbound if e.get("exposure") == "External")
    internal_outbound   = sum(1 for e in clean_outbound if e.get("exposure") == "Internal")

    valid_count = sum(1 for e in inbound_entries if e.classification == "Valid")
    all_shadow  = valid_count == 0 and len(inbound_entries) > 0

    return {
        "inbound_apis": {
            "description":       f"APIs that {app_name} exposes — endpoints other systems or users call into {app_name}",
            "total":             len(inbound_entries),
            "by_sensitivity":    inbound_by_sensitivity,
            "by_method":         dict(sorted(inbound_by_method.items(), key=lambda x: -x[1])),
            "by_module":         dict(sorted(inbound_by_module.items(), key=lambda x: -x[1])[:10]),
            "governance_status": "No API registry or OpenAPI spec exists" if all_shadow else "Partial governance coverage",
        },
        "outbound_apis": {
            "description":           f"APIs that {app_name} calls out to — external and internal services {app_name} depends on",
            "total":                 len(clean_outbound),
            "external":              external_outbound,
            "internal":              internal_outbound,
            "hardcoded_credentials": hardcoded_key_count,
            "by_exposure":           outbound_by_exposure,
            "by_category":           outbound_by_category,
            "by_auth_method":        outbound_by_auth,
            "owasp_reference":       "API10 — Unsafe Consumption of Third-Party APIs",
            "risk_note": (
                f"{hardcoded_key_count} outbound API calls use hardcoded credentials — rotate immediately."
                if hardcoded_key_count > 0 else
                "No hardcoded credentials detected in outbound calls."
            ),
            "apis": clean_outbound,
        },
    }


def _build_executive_summary(entries: List[APIEntry], counts: Dict,
                               secrets: List[Dict], outbound: List[Dict],
                               outbound_inventory: List[Dict],
                               app_name: str) -> Dict:
    total           = counts.get("total", len(entries))
    shadow_count    = counts.get("Shadow", 0)
    rogue_count     = counts.get("Rogue", 0)
    valid_count     = counts.get("Valid", 0)
    crit_sens       = sum(1 for e in entries if e.data_sensitivity == "CRITICAL")
    high_risk       = sum(1 for e in entries if e.risk_score >= 50)
    secret_count    = len(secrets)
    no_auth         = sum(1 for e in entries
                          if (e.auth_type or "") in ("None detected", "UNKNOWN", "none", ""))
    cve_count       = sum(len(e.cve_findings) for e in entries)
    outbound_total  = len(outbound_inventory or [])
    outbound_ext    = sum(1 for o in (outbound_inventory or []) if o.get("exposure") == "External")

    risk_level = (
        "CRITICAL" if (crit_sens >= 10 or secret_count >= 5 or high_risk >= 100) else
        "HIGH"     if (high_risk >= 20 or secret_count >= 1) else
        "MEDIUM"
    )

    governance_note = (
        f"None of the {total} inbound endpoints were present in a formal API registry or "
        f"OpenAPI specification, resulting in all being classified as Shadow APIs — indicating a "
        f"complete absence of API governance controls. "
        if valid_count == 0 and total > 0 else
        f"{shadow_count} of {total} inbound endpoints are undocumented (Shadow/Rogue). "
        f"{valid_count} endpoints are formally registered. "
    )

    secret_sentence = (
        f"Static analysis revealed {secret_count} hardcoded credential findings including "
        f"tokens, private keys, and environment variables. "
        if secret_count > 0 else
        "Secret scanning was performed; no hardcoded credentials were found. "
    )
    cve_sentence = (
        f"{cve_count} CVE findings were identified in application dependencies. "
        if cve_count > 0 else ""
    )
    outbound_sentence = (
        f"{app_name} makes outbound calls to {outbound_total} external and internal APIs "
        f"({outbound_ext} external), which require formal security assessment. "
        if outbound_total > 0 else ""
    )

    narrative = (
        f"The API Discovery and Security Evaluation engagement for "
        f"{counts.get('client', app_name)} identified {total} inbound APIs exposed by "
        f"{app_name}, and {outbound_total} outbound API dependencies. "
        f"{governance_note}"
        f"{crit_sens} inbound endpoints handle CRITICAL sensitivity data and {high_risk} carry "
        f"High or Critical risk scores. "
        f"{secret_sentence}"
        f"{cve_sentence}"
        f"{outbound_sentence}"
        f"{no_auth} inbound endpoints show no detectable authentication mechanism. "
        f"The overall security posture for API governance is assessed as: {risk_level}."
    )

    top_recommendations = []
    priority = 1

    if secret_count > 0:
        top_recommendations.append({
            "priority":  priority,
            "action":    "Rotate all hardcoded credentials immediately",
            "rationale": f"{secret_count} secrets found in source code.",
            "effort":    "Low",
            "impact":    "CRITICAL",
        })
        priority += 1

    hardcoded_outbound = sum(1 for o in (outbound_inventory or []) if o.get("auth_method") == "hardcoded_key")
    if hardcoded_outbound > 0:
        top_recommendations.append({
            "priority":  priority,
            "action":    "Rotate hardcoded credentials in outbound API calls",
            "rationale": f"{hardcoded_outbound} outbound calls use hardcoded API keys.",
            "effort":    "Low",
            "impact":    "HIGH",
        })
        priority += 1

    if cve_count > 0:
        top_recommendations.append({
            "priority":  priority,
            "action":    "Patch vulnerable dependencies identified by CVE scan",
            "rationale": f"{cve_count} CVE findings in application packages.",
            "effort":    "Medium",
            "impact":    "HIGH",
        })
        priority += 1

    top_recommendations += [
        {
            "priority":  priority,
            "action":    "Create and enforce API inventory (OpenAPI spec + gateway registration)",
            "rationale": f"{shadow_count + rogue_count} inbound endpoints are unregistered.",
            "effort":    "High",
            "impact":    "CRITICAL",
        },
        {
            "priority":  priority + 1,
            "action":    "Implement authentication middleware across all API routes",
            "rationale": f"{no_auth} inbound endpoints accessible without authentication.",
            "effort":    "Medium",
            "impact":    "HIGH",
        },
        {
            "priority":  priority + 2,
            "action":    "Deploy API gateway with rate limiting and security policies",
            "rationale": "Centralised enforcement point required for auth, rate limiting, and logging.",
            "effort":    "High",
            "impact":    "HIGH",
        },
        {
            "priority":  priority + 3,
            "action":    "Assess and harden all outbound API integrations",
            "rationale": f"{app_name} calls {outbound_total} external/internal APIs with no formal security assessment.",
            "effort":    "Medium",
            "impact":    "HIGH",
        },
    ]

    return {
        "overall_risk":        risk_level,
        "narrative":           narrative,
        "key_metrics": {
            "inbound_apis_total":             total,
            "outbound_apis_total":            outbound_total,
            "outbound_apis_external":         outbound_ext,
            "shadow_apis":                    shadow_count,
            "rogue_apis":                     rogue_count,
            "valid_apis":                     valid_count,
            "critical_sensitivity_endpoints": crit_sens,
            "high_critical_risk_endpoints":   high_risk,
            "hardcoded_secrets":              secret_count,
            "endpoints_without_auth":         no_auth,
            "external_integrations":          len(outbound),
            "cve_findings":                   cve_count,
        },
        "top_recommendations": top_recommendations,
    }


def _remediation_for(entry: APIEntry) -> str:
    cls   = entry.classification
    sens  = entry.data_sensitivity
    auth  = entry.auth_type or "None detected"
    score = entry.risk_score
    parts = []
    if cls in ("Shadow", "Rogue"):
        parts.append("Register in API gateway or decommission. Assign owner, add to OpenAPI spec.")
    if auth in ("None detected", "UNKNOWN", "none", ""):
        parts.append("Implement authentication middleware (JWT/OAuth2).")
    if sens == "CRITICAL":
        parts.append("Apply field-level encryption. Restrict to authorized roles only.")
    if score >= 75:
        parts.append("Immediate remediation required — escalate to security team.")
    if not parts:
        parts.append("Review as part of routine API governance cycle.")
    return " ".join(parts)


class Reporter:
    def __init__(self, store, cfg: dict):
        self.store       = store
        self.cfg         = cfg
        out_cfg          = cfg.get("output", {})
        self.out_dir     = out_cfg.get("directory", "output")
        self.client_name = out_cfg.get("client_name", "Client")
        self.app_name    = out_cfg.get("app_name", self.client_name)
        self.engagement  = out_cfg.get("engagement_name", "API Discovery & Security Evaluation")
        self.do_json     = out_cfg.get("json", True)
        self.scan_env    = out_cfg.get("scan_target_environment", "unknown")
        os.makedirs(self.out_dir, exist_ok=True)

    async def run(self):
        all_entries = self.store.all()
        counts      = self.store.count()
        counts["client"] = self.client_name

        clean_entries = [e for e in all_entries if not _is_noise(e)]
        for e in clean_entries:
            e.owasp_flags = _infer_owasp_flags(e)

        secrets_findings = getattr(self.store, "secrets_found", []) or []
        for s in secrets_findings:
            if "severity" not in s:
                s["severity"] = "CRITICAL"

        package_deps          = getattr(self.store, "package_dependencies", [])
        outbound_api_inventory = getattr(self.store, "outbound_api_inventory", [])

        outbound_deps     = _extract_outbound_deps(all_entries)
        tech_stack        = _detect_tech_stack(clean_entries, self.cfg)
        all_owasp_flags   = [f for e in clean_entries for f in e.owasp_flags]
        owasp_conformance = _build_owasp_conformance(clean_entries, all_owasp_flags)

        inbound_outbound = _build_inbound_outbound_summary(
            clean_entries, outbound_api_inventory, self.app_name
        )

        exec_summary = _build_executive_summary(
            clean_entries, counts, secrets_findings, outbound_deps,
            outbound_api_inventory, self.app_name
        )

        print(f"    Secrets loaded from store: {len(secrets_findings)} findings")
        print(f"    Package deps loaded: {len(package_deps)} packages")
        print(f"    Outbound APIs loaded: {len(outbound_api_inventory)} entries")

        if self.do_json:
            self._write_json(
                clean_entries, counts, secrets_findings, package_deps,
                outbound_deps, tech_stack, owasp_conformance,
                exec_summary, all_owasp_flags, inbound_outbound,
            )

        self._print_summary(counts, clean_entries, secrets_findings, outbound_api_inventory)

    def _write_json(self, entries, counts, secrets, package_deps, outbound, tech_stack,
                    owasp_conformance, exec_summary, all_owasp_flags, inbound_outbound):

        def _enrich(e: APIEntry) -> Dict:
            d = e.to_dict()
            d["functional_module"] = _infer_module(e)
            d["api_version"]       = _infer_version(e.endpoint)
            d["source_file"]       = (e.evidence or {}).get("file", "unknown")
            d["inferred_owner"]    = e.inferred_owner or "Pending Triage - Application Owner"
            d["risk_band"]         = _risk_band(e.risk_score)
            d["owasp_flags"]       = e.owasp_flags
            d["cve_findings"]      = e.cve_findings
            d["remediation"]       = _remediation_for(e)
            return d

        by_class = {
            cls: [_enrich(e) for e in entries if e.classification == cls]
            for cls in ["Valid", "Shadow", "New", "Rogue", "UNCLASSIFIED"]
        }

        shadow_rogue = sorted(
            [_enrich(e) for e in entries if e.classification in ("Shadow", "Rogue")],
            key=lambda x: x.get("risk_score", 0), reverse=True,
        )

        owasp_findings_list = sorted(
            all_owasp_flags,
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", "LOW"), 3),
        )

        bom = self._build_bom(entries, tech_stack, outbound, package_deps)

        all_cves  = []
        seen_cves: set = set()
        for e in entries:
            for cve in e.cve_findings:
                cid = cve.get("cve", "")
                if cid not in seen_cves:
                    all_cves.append({
                        **cve,
                        "endpoint_count": sum(
                            1 for x in entries if any(c.get("cve") == cid for c in x.cve_findings)
                        ),
                    })
                    seen_cves.add(cid)
        all_cves.sort(key=lambda x: x.get("cvss", 0), reverse=True)

        output = {
            "schema_version":          "2.2",
            "engagement":              self.engagement,
            "client":                  self.client_name,
            "app_name":                self.app_name,
            "scan_target_environment": self.scan_env,
            "generated_at":            datetime.utcnow().isoformat() + "Z",

            "executive_summary": exec_summary,

            "summary": {
                **{k: v for k, v in counts.items() if k != "client"},
                "api_inventory_count":      len(entries),
                "noise_filtered_count":     counts.get("total", 0) - len(entries),
                "inbound_api_count":        len(entries),
                "outbound_api_count":       len(inbound_outbound["outbound_apis"]["apis"]),
                "outbound_external_count":  inbound_outbound["outbound_apis"]["external"],
                "outbound_internal_count":  inbound_outbound["outbound_apis"]["internal"],
                "secrets_count":            len(secrets),
                "external_integrations":    len(outbound),
                "data_sensitivity":         _crit_counts(entries),
                "owasp_findings_total":     len(owasp_findings_list),
                "inferred_owasp_findings":  sum(1 for f in owasp_findings_list if f.get("source") == "inferred"),
                "live_owasp_findings":      sum(1 for f in owasp_findings_list if f.get("source") != "inferred"),
                "cve_findings_total":       len(all_cves),
                "high_critical_risk_count": sum(1 for e in entries if e.risk_score >= 50),
                "endpoints_without_auth":   sum(
                    1 for e in entries
                    if (e.auth_type or "") in ("None detected", "UNKNOWN", "none", "")
                ),
            },

            "inbound_outbound_classification": inbound_outbound,
            "api_inventory":                   {cls: apis for cls, apis in by_class.items() if apis},
            "shadow_rogue_register":           shadow_rogue,
            "owasp_findings":                  owasp_findings_list,
            "owasp_conformance_summary":       owasp_conformance,
            "secrets_findings":                secrets,
            "cve_findings_summary":            all_cves,
            "outbound_dependencies":           outbound,
            "api_bom":                         bom,

            "all_endpoints": [
                _enrich(e)
                for e in sorted(entries, key=lambda x: x.risk_score, reverse=True)
            ],
        }

        path = os.path.join(self.out_dir, "api_discovery_full.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"    JSON: {path}")

        reg_path = os.path.join(self.out_dir, "shadow_rogue_register.json")
        with open(reg_path, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "engagement":   self.engagement,
                "client":       self.client_name,
                "app_name":     self.app_name,
                "total":        len(shadow_rogue),
                "shadow_count": sum(1 for e in shadow_rogue if e["classification"] == "Shadow"),
                "rogue_count":  sum(1 for e in shadow_rogue if e["classification"] == "Rogue"),
                "shadow":       [e for e in shadow_rogue if e["classification"] == "Shadow"],
                "rogue":        [e for e in shadow_rogue if e["classification"] == "Rogue"],
            }, f, indent=2)
        print(f"    JSON: {reg_path}")

        sec_path = os.path.join(self.out_dir, "secrets_findings.json")
        with open(sec_path, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total":        len(secrets),
                "findings":     secrets,
            }, f, indent=2)
        print(f"    JSON: {sec_path}")

        out_path = os.path.join(self.out_dir, "outbound_api_inventory.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "engagement":   self.engagement,
                "client":       self.client_name,
                "app_name":     self.app_name,
                "total":        len(inbound_outbound["outbound_apis"]["apis"]),
                "external":     inbound_outbound["outbound_apis"]["external"],
                "internal":     inbound_outbound["outbound_apis"]["internal"],
                "apis":         inbound_outbound["outbound_apis"]["apis"],
            }, f, indent=2)
        print(f"    JSON: {out_path}")

    def _build_bom(self, entries, tech_stack, outbound, package_deps=None) -> Dict:
        items = []
        for e in entries:
            items.append({
                "endpoint":          e.endpoint,
                "method":            e.method,
                "classification":    e.classification,
                "functional_module": _infer_module(e),
                "api_version":       _infer_version(e.endpoint),
                "auth_type":         e.auth_type,
                "data_sensitivity":  e.data_sensitivity,
                "exposure":          e.exposure,
                "environment":       e.environment or self.scan_env,
                "owner":             e.inferred_owner or e.owner or "Pending review",
                "risk_score":        e.risk_score,
                "risk_band":         _risk_band(e.risk_score),
                "owasp_categories":  [f.get("category") for f in e.owasp_flags],
                "cve_count":         len(e.cve_findings),
                "discovered_by":     e.discovered_by,
                "source_file":       (e.evidence or {}).get("file", "unknown"),
                "first_seen":        e.first_seen,
                "last_seen":         e.last_seen,
                "tags":              e.tags,
            })
        items.sort(key=lambda x: x["risk_score"], reverse=True)
        return {
            "tech_stack":                       tech_stack,
            "upstream_downstream_dependencies": outbound,
            "package_dependencies":             package_deps or [],
            "api_endpoints":                    items,
        }

    def _print_summary(self, counts, entries, secrets, outbound_inventory=None):
        high_risk      = sum(1 for e in entries if e.risk_score >= 50)
        owasp_count    = sum(len(e.owasp_flags) for e in entries)
        cve_count      = sum(len(e.cve_findings) for e in entries)
        outbound_count = len(outbound_inventory or [])
        outbound_ext   = sum(1 for o in (outbound_inventory or []) if o.get("exposure") == "External")

        print(f"\n{'='*70}")
        print(f"  {self.engagement}")
        print(f"  Client  : {self.client_name}")
        print(f"  App     : {self.app_name}")
        print(f"  Env     : {self.scan_env}")
        print(f"{'='*70}")
        print(f"  Inbound APIs (exposed by {self.app_name}) : {len(entries)}")
        print(f"  Outbound APIs (called by {self.app_name}) : {outbound_count} ({outbound_ext} external)")
        print(f"  Valid                          : {counts.get('Valid', 0)}")
        print(f"  Shadow                         : {counts.get('Shadow', 0)}")
        print(f"  New                            : {counts.get('New', 0)}")
        print(f"  Rogue                          : {counts.get('Rogue', 0)}")
        print(f"  High/Critical risk             : {high_risk}")
        print(f"  OWASP findings (incl.inferred) : {owasp_count}")
        print(f"  Hardcoded secrets              : {len(secrets)}")
        print(f"  CVE findings                   : {cve_count}")
        print(f"  Output directory               : {os.path.abspath(self.out_dir)}")
        print(f"{'='*70}\n")