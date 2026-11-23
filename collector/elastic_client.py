"""
Attack Correlation & Rapid Response Platform
Prototype Engine v16.2

Purpose
-------
Convert Sysmon/ECS telemetry into explainable attack stories and campaigns.

Design goals
------------
- Correlation is evidence-based, not host/time-only.
- Risk and confidence are independent.
- Confidence is aggregated from independent evidence categories.
- Negative/benign evidence can reduce confidence.
- Attack progression is sequence-aware.
- Campaigns are resistant to weak transitive grouping.
- Attack state is explicit.
- Response is advisory/simulation only.
- No autonomous containment or destructive action.

What's new in v16.2 (vs v16.1) - presentation/data-access layer ONLY,
no correlation, scoring, campaign-grouping, story-generation, MITRE,
IOC-extraction, or active-attack logic was touched
--------------------------------------------------------------------
1. Replaced build_investigation_view()/_build_story_investigation(),
   which embedded a full copy of every campaign's stories both inside
   each campaign dict AND in a separate top-level map (2x duplication
   of every story, which is a direct contributor to why
   campaign_results.json got too large to json.load() in one shot).
   export_campaigns_json() is back to its original v15/v16.1-shaped,
   lean payload (statistics + campaigns only, no embedded story/event
   bodies).
2. New export_analyst_view(): writes a separate, on-demand-friendly
   output directory instead - campaigns_index.json and
   stories_index.json stay small (summaries only), and each story's
   full detail (including its curated events) lives in its own
   stories/<story_id>.json file, so a UI/backend only ever reads the
   one story a user actually expands instead of the whole dataset.
3. New build_event_view(): curated, analyst-facing event fields
   (timestamp, process/parent process, network, dns, file, registry,
   correlation reasons) - only fields that actually have a value,
   nothing fabricated. Internal pipeline-only fields (_fingerprint,
   raw _correlation shape) are not exposed.
4. New summarize_progression_stages(): collapses runs of identical
   progression stages ("execution" x162) into a compact summary while
   the raw stage list stays available underneath.
5. New build_ioc_index(): reverse-indexes each IOC (ip/domain/sha256/
   file_path) to the story_ids and event_ids it was actually observed
   in - re-indexes extract_iocs()'s existing output, does not change
   IOC extraction.
6. New build_process_chain_view(): ordered, display-ready process
   chain (parent_pid resolved per step) for rendering as an arrow
   chain in a UI.

What's new in v16.1 (vs v15)
---------------------------
1. Orphan-event recovery: events whose owning process was never observed
   as part of a captured process-creation relationship no longer vanish
   from the analysis. They are correlated directly on IOC/network/host
   signals and can still form stories and join campaigns.
2. Context-aware allowlisting: known-good hosts/users (e.g. patch
   management accounts, backup servers) can be dampened via config,
   not just generic "common Windows process" name matching.
3. Fixed: destination-port match now records structured evidence like
   every other correlation rule (was score-only in v14).
4. All severity / attack-state / active-attack / response thresholds are
   now named, env-overridable constants instead of inline magic numbers.
5. Response urgency is now a distinct field from campaign severity, so
   the two can never look like a display bug when they (correctly)
   diverge.
6. Elasticsearch calls retry with backoff and fail cleanly instead of
   raising a raw traceback mid-demo.
7. Optional JSON export of campaign results, for the eventual
   FastAPI/dashboard layer.
8. DEMO_MODE: a self-contained synthetic MVP attack scenario
   (PowerShell -> credential access -> lateral movement) that runs with
   zero external dependencies, so a live demo never depends on a live
   Elasticsearch connection.
9. A companion test suite (test_attack_correlation_engine.py) that
   locks in the two guarantees that matter most: the anti-naive-grouping
   rule, and transitive campaign clustering.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from elasticsearch import Elasticsearch


# ============================================================
# CONFIGURATION
# ============================================================

ELASTIC_URL = os.getenv("ELASTIC_URL", "https://localhost:9200")
USERNAME = os.getenv("ELASTIC_USERNAME", "elastic")
PASSWORD = os.getenv("ELASTIC_PASSWORD")
HOST = os.getenv("TARGET_HOST", "")
SYSMON_INDEX = os.getenv("SYSMON_INDEX", "winlogbeat-*")

MAX_EVENTS = int(os.getenv("MAX_EVENTS", "10000"))
PAGE_SIZE = min(int(os.getenv("PAGE_SIZE", "500")), 1000)

CORRELATION_WINDOW_SECONDS = int(
    os.getenv("CORRELATION_WINDOW", "300")
)
STRONG_CORRELATION_SECONDS = int(
    os.getenv("STRONG_CORRELATION", "60")
)
CAMPAIGN_WINDOW_SECONDS = int(
    os.getenv("CAMPAIGN_WINDOW", "1800")
)

MIN_EVENT_RELATION_SCORE = int(os.getenv("MIN_EVENT_RELATION_SCORE", "45"))
MIN_EVENT_STORY_SCORE = int(os.getenv("MIN_EVENT_STORY_SCORE", "50"))
MIN_CAMPAIGN_RELATION_SCORE = int(os.getenv("MIN_CAMPAIGN_RELATION_SCORE", "50"))

ACTIVE_RECENCY_SECONDS = int(
    os.getenv("ACTIVE_RECENCY_SECONDS", "600")
)

VERIFY_CERTS = os.getenv("VERIFY_CERTS", "false").lower() == "true"
CA_CERTS = os.getenv("CA_CERTS")

RELEVANT_EVENT_CODES = {"1", "3", "5", "11", "13", "22"}

EVENT_NAMES = {
    "1": "Process Creation",
    "3": "Network Connection",
    "5": "Process Termination",
    "11": "File Creation",
    "13": "Registry Value Set",
    "22": "DNS Query",
}

# --- Severity thresholds (campaign situation severity) ---
SEVERITY_CRITICAL_RISK = int(os.getenv("SEVERITY_CRITICAL_RISK", "85"))
SEVERITY_CRITICAL_CONFIDENCE = int(os.getenv("SEVERITY_CRITICAL_CONFIDENCE", "75"))
SEVERITY_HIGH_RISK = int(os.getenv("SEVERITY_HIGH_RISK", "65"))
SEVERITY_HIGH_CONFIDENCE = int(os.getenv("SEVERITY_HIGH_CONFIDENCE", "55"))
SEVERITY_MEDIUM_RISK = int(os.getenv("SEVERITY_MEDIUM_RISK", "40"))

# --- Attack state thresholds ---
STATE_HIGH_CONFIDENCE_RISK = int(os.getenv("STATE_HIGH_CONFIDENCE_RISK", "80"))
STATE_HIGH_CONFIDENCE_CONFIDENCE = int(os.getenv("STATE_HIGH_CONFIDENCE_CONFIDENCE", "65"))
STATE_CORRELATED_RISK = int(os.getenv("STATE_CORRELATED_RISK", "55"))
STATE_CORRELATED_CONFIDENCE = int(os.getenv("STATE_CORRELATED_CONFIDENCE", "55"))

# --- Active-attack detection thresholds ---
ACTIVE_RISK_GATE = int(os.getenv("ACTIVE_RISK_GATE", "75"))
ACTIVE_CONFIDENCE_GATE = int(os.getenv("ACTIVE_CONFIDENCE_GATE", "70"))
ACTIVE_PROGRESSION_GATE = int(os.getenv("ACTIVE_PROGRESSION_GATE", "20"))
ACTIVE_ATTACK_SCORE_THRESHOLD = int(os.getenv("ACTIVE_ATTACK_SCORE_THRESHOLD", "60"))
ACTIVE_ATTACK_PROGRESSION_MIN = int(os.getenv("ACTIVE_ATTACK_PROGRESSION_MIN", "15"))
ACTIVE_ATTACK_CONFIDENCE_MIN = int(os.getenv("ACTIVE_ATTACK_CONFIDENCE_MIN", "55"))

# --- Response tier thresholds ---
RESPONSE_CRITICAL_RISK = int(os.getenv("RESPONSE_CRITICAL_RISK", "85"))
RESPONSE_CRITICAL_CONFIDENCE = int(os.getenv("RESPONSE_CRITICAL_CONFIDENCE", "75"))
RESPONSE_HIGH_RISK = int(os.getenv("RESPONSE_HIGH_RISK", "70"))
RESPONSE_HIGH_CONFIDENCE = int(os.getenv("RESPONSE_HIGH_CONFIDENCE", "60"))
RESPONSE_MEDIUM_RISK = int(os.getenv("RESPONSE_MEDIUM_RISK", "40"))

# --- Context allowlist (dampens, never fully silences, known-good context) ---
ALLOWLISTED_HOSTS = {
    h.strip().lower()
    for h in os.getenv("ALLOWLISTED_HOSTS", "").split(",")
    if h.strip()
}
ALLOWLISTED_USERS = {
    u.strip().lower()
    for u in os.getenv("ALLOWLISTED_USERS", "").split(",")
    if u.strip()
}
ALLOWLIST_DAMPENING = int(os.getenv("ALLOWLIST_DAMPENING", "15"))

# --- Output / operating mode ---
EXPORT_JSON = os.getenv("EXPORT_JSON", "true").lower() == "true"
EXPORT_JSON_PATH = os.getenv("EXPORT_JSON_PATH", "campaign_results.json")
ANALYST_VIEW_DIR = os.getenv("ANALYST_VIEW_DIR", "analyst_view")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

INCIDENT_API_ENABLED = os.getenv(
    "INCIDENT_API_ENABLED", "false"
).lower() == "true"
INCIDENT_API_URL = os.getenv(
    "INCIDENT_API_URL",
    "http://127.0.0.1:8001/ingest/analysis-result"
)
INCIDENT_API_TIMEOUT = int(os.getenv("INCIDENT_API_TIMEOUT", "30"))
ES_RETRY_ATTEMPTS = int(os.getenv("ES_RETRY_ATTEMPTS", "3"))
ES_RETRY_BACKOFF_SECONDS = float(os.getenv("ES_RETRY_BACKOFF_SECONDS", "2"))


# ============================================================
# PROCESS / BEHAVIOR INTELLIGENCE
# ============================================================

COMMON_LEGITIMATE_PROCESSES = {
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "wininit.exe", "winlogon.exe", "smss.exe", "csrss.exe",
    "dwm.exe", "taskhostw.exe", "searchhost.exe",
    "searchindexer.exe", "runtimebroker.exe", "spoolsv.exe",
}

PROCESS_MITRE = {
    "powershell.exe": ("T1059.001", "PowerShell", 18),
    "pwsh.exe": ("T1059.001", "PowerShell", 18),
    "cmd.exe": ("T1059.003", "Windows Command Shell", 10),
    "wscript.exe": ("T1059.005", "Visual Basic", 14),
    "cscript.exe": ("T1059.005", "Visual Basic", 14),
    "rundll32.exe": ("T1218.011", "Rundll32", 20),
    "regsvr32.exe": ("T1218.010", "Regsvr32", 20),
    "mshta.exe": ("T1218.005", "Mshta", 22),
    "reg.exe": ("T1112", "Modify Registry", 14),
    "schtasks.exe": ("T1053.005", "Scheduled Task/Job", 20),
    "wmic.exe": ("T1047", "Windows Management Instrumentation", 18),
    "certutil.exe": ("T1105", "Ingress Tool Transfer", 18),
    "bitsadmin.exe": ("T1105", "Ingress Tool Transfer", 18),
}

COMMAND_PATTERNS = [
    (re.compile(r"\b-encodedcommand\b|\s-enc(?:odedcommand)?\s", re.I),
     "T1059.001", "PowerShell", 25,
     "Encoded PowerShell command", 90),
    (re.compile(r"frombase64string", re.I),
     "T1140", "Deobfuscate/Decode Files or Information", 20,
     "Base64 decoding behavior", 85),
    (re.compile(r"invoke-expression|\biex\s", re.I),
     "T1059.001", "PowerShell", 18,
     "Dynamic PowerShell execution", 80),
    (re.compile(r"downloadstring|downloadfile|webclient|invoke-webrequest|\biwr\s", re.I),
     "T1105", "Ingress Tool Transfer", 22,
     "Remote content/tool download", 85),
    (re.compile(r"start-bitstransfer|bitsadmin", re.I),
     "T1105", "Ingress Tool Transfer", 18,
     "BITS transfer activity", 85),
    (re.compile(r"certutil(?:\.exe)?\s+.*(?:-urlcache|-decode|-decodehex)", re.I),
     "T1105", "Ingress Tool Transfer", 20,
     "Certutil transfer/decode behavior", 85),
    (re.compile(r"\breg(?:\.exe)?\s+add\b", re.I),
     "T1112", "Modify Registry", 18,
     "Registry modification via command line", 85),
    (re.compile(r"schtasks(?:\.exe)?\s+.*(?:/create|-create)", re.I),
     "T1053.005", "Scheduled Task/Job", 22,
     "Scheduled task creation", 90),
    (re.compile(r"wmic(?:\.exe)?\s+.*(?:process|/node:)", re.I),
     "T1047", "Windows Management Instrumentation", 20,
     "WMI execution behavior", 85),
    (re.compile(r"rundll32(?:\.exe)?\s+.*(?:javascript:|url\.dll|shell32)", re.I),
     "T1218.011", "Rundll32", 22,
     "Suspicious Rundll32 invocation", 85),
    (re.compile(r"mshta(?:\.exe)?\s+.*(?:https?://|javascript:|vbscript:)", re.I),
     "T1218.005", "Mshta", 25,
     "Remote/scripted Mshta execution", 90),
    (re.compile(r"regsvr32(?:\.exe)?\s+.*(?:/s|/u|scrobj|https?://)", re.I),
     "T1218.010", "Regsvr32", 22,
     "Suspicious Regsvr32 execution", 85),
]

SUSPICIOUS_PATH_PARTS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "/tmp/",
    "/var/tmp/",
)

SUSPICIOUS_COMMAND_MARKERS = (
    "-enc", "download", "javascript:", "http://", "https://",
    "frombase64string", "invoke-expression", "iex ",
)

# Sequence categories used by progression/state analysis.
CODE_STAGE = {
    "1": "execution",
    "3": "network",
    "5": "termination",
    "11": "file",
    "13": "persistence",
    "22": "dns",
}

# Stronger behavioral progression patterns.
PROGRESSION_PATTERNS = [
    (("execution", "network"), 12, "Execution followed by network activity"),
    (("execution", "dns"), 8, "Execution followed by DNS activity"),
    (("execution", "file"), 8, "Execution followed by file creation"),
    (("execution", "persistence"), 14, "Execution followed by persistence-related activity"),
    (("network", "execution"), 8, "Network activity followed by execution"),
    (("file", "execution"), 10, "File creation followed by execution"),
]

# Correlation-evidence types strong enough to justify linking two
# ORPHAN events (events with no process-lineage backbone). Same-host /
# same-time alone is deliberately excluded here too, for the same
# reason it is excluded in story_similarity.
STRONG_ORPHAN_EVIDENCE_TYPES = {
    "shared_hash", "shared_file_path", "shared_domain",
    "shared_destination_ip", "process_identity", "parent_child",
}


# ============================================================
# ELASTIC CLIENT
# ============================================================
#
# v15 fix: v14 constructed the Elasticsearch client eagerly at import
# time. That crashes on import whenever ELASTIC_PASSWORD isn't set
# (elasticsearch-py tries to base64-encode the auth header immediately,
# and a None password isn't a valid string) - which meant the module
# couldn't even be imported for DEMO_MODE or for unit tests without a
# real password in the environment. The client is now built lazily, on
# first actual use.

_es_client: Optional[Elasticsearch] = None


def get_client() -> Elasticsearch:
    global _es_client

    if _es_client is None:
        if not PASSWORD:
            raise RuntimeError(
                "ELASTIC_PASSWORD environment variable is not set."
            )

        client_kwargs: Dict[str, Any] = {
            "basic_auth": (USERNAME, PASSWORD),
            "verify_certs": VERIFY_CERTS,
        }

        if CA_CERTS:
            client_kwargs["ca_certs"] = CA_CERTS

        _es_client = Elasticsearch(ELASTIC_URL, **client_kwargs)

    return _es_client


# ============================================================
# UTILITIES
# ============================================================

def safe_lower(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def parse_timestamp(value: Any) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def delta_seconds(a: Any, b: Any) -> float:
    return abs((parse_timestamp(a) - parse_timestamp(b)).total_seconds())


def get_nested(source: Dict[str, Any], *keys: str) -> Any:
    current: Any = source
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def unique_list(values: List[Any]) -> List[Any]:
    output = []
    seen = set()

    for value in values:
        key = (
            json.dumps(value, sort_keys=True, default=str)
            if isinstance(value, (dict, list))
            else str(value)
        )
        if key not in seen:
            seen.add(key)
            output.append(value)

    return output


def stable_hash(*parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(raw.encode(errors="ignore")).hexdigest()[:16]


def is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False

    try:
        address = ipaddress.ip_address(str(ip))
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
        )
    except ValueError:
        return str(ip).lower() in {"localhost", "::1"}


def ip_is_public(ip: Optional[str]) -> bool:
    return bool(ip) and not is_private_ip(ip)


def clamp(value: float, low: float = 0, high: float = 100) -> int:
    return int(max(low, min(high, round(value))))


def make_json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: make_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [make_json_safe(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_event(hit: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize ECS, flat Raw Sysmon, and nested Winlogbeat/Sysmon documents
    into the canonical event model consumed by the correlation engine.
    """
    source = hit.get("_source", {}) or {}
    event = source.get("event", {}) or {}
    process = source.get("process", {}) or {}
    parent = process.get("parent", {}) or {}

    # Some Winlogbeat pipelines store Sysmon EventData as:
    #   winlog.event_data.Image
    # while other pipelines flatten EventData directly into _source.
    winlog = source.get("winlog", {}) or {}
    event_data = (
        winlog.get("event_data", {})
        if isinstance(winlog.get("event_data", {}), dict)
        else {}
    )

    def first(*values: Any) -> Any:
        for value in values:
            if value is not None and value != "":
                return value
        return None

    def nested(obj: Dict[str, Any], *keys: str) -> Any:
        value: Any = obj
        for key in keys:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
        return value

    def raw(*names: str) -> Any:
        for name in names:
            value = source.get(name)
            if value is not None and value != "":
                return value
            value = event_data.get(name)
            if value is not None and value != "":
                return value
        return None

    def as_int(value: Any) -> Any:
        if value is None or value == "":
            return None
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            try:
                return int(value)
            except (TypeError, ValueError):
                return value

    timestamp = first(
        source.get("@timestamp"),
        source.get("timestamp"),
        raw("UtcTime", "Timestamp"),
    )

    event_code = first(
        event.get("code"),
        winlog.get("event_id"),
        raw("EventID", "event_id"),
    )
    event_code = str(event_code) if event_code is not None else ""

    event_action = first(
        event.get("action"),
        raw("EventAction", "Action"),
    )

    host = first(
        nested(source, "host", "name"),
        raw("Computer", "Hostname"),
    )

    user = first(
        nested(source, "user", "name"),
        raw("User", "TargetUserName"),
    )

    process_name = first(
        process.get("name"),
        raw("Image", "ProcessName"),
    )

    process_executable = first(
        process.get("executable"),
        raw("Image", "ProcessPath"),
    )

    process_pid = first(
        process.get("pid"),
        raw("ProcessId", "NewProcessId"),
    )

    process_entity_id = first(
        process.get("entity_id"),
        raw("ProcessGuid", "ProcessGUID"),
    )

    process_command_line = first(
        process.get("command_line"),
        raw("CommandLine"),
    )

    parent_name = first(
        nested(source, "process", "parent", "name"),
        raw("ParentImage", "ParentProcessName"),
    )

    parent_executable = first(
        nested(source, "process", "parent", "executable"),
        raw("ParentImage", "ParentProcessPath"),
    )

    parent_pid = first(
        nested(source, "process", "parent", "pid"),
        raw("ParentProcessId"),
    )

    parent_entity_id = first(
        nested(source, "process", "parent", "entity_id"),
        raw("ParentProcessGuid", "ParentProcessGUID"),
    )

    parent_command_line = first(
        nested(source, "process", "parent", "command_line"),
        raw("ParentCommandLine"),
    )

    source_ip = first(
        nested(source, "source", "ip"),
        raw("SourceIp", "SourceIP"),
    )

    source_port = first(
        nested(source, "source", "port"),
        raw("SourcePort"),
    )

    destination_ip = first(
        nested(source, "destination", "ip"),
        raw("DestinationIp", "DestinationIP"),
    )

    destination_port = first(
        nested(source, "destination", "port"),
        raw("DestinationPort"),
    )

    dns_query = first(
        nested(source, "dns", "question", "name"),
        raw("QueryName", "Query"),
    )

    file_name = first(
        nested(source, "file", "name"),
        raw("TargetFilename", "FileName"),
    )

    file_path = first(
        nested(source, "file", "path"),
        raw("TargetFilename", "FilePath"),
    )

    sha256 = nested(source, "file", "hash", "sha256")
    if not sha256:
        hashes = raw("Hashes")
        if hashes:
            match = re.search(
                r"(?:^|[,;\s])SHA256=([A-Fa-f0-9]{64})(?:$|[,;\s])",
                str(hashes),
                re.IGNORECASE,
            )
            if match:
                sha256 = match.group(1)

    registry_path = first(
        nested(source, "registry", "path"),
        raw("TargetObject", "RegistryPath"),
    )

    image = first(process_executable, process_name, raw("Image"))

    return {
        "id": hit.get("_id"),
        "timestamp": timestamp,
        "event_code": event_code,
        "event_action": event_action,
        "host": host,
        "user": user,
        "process": {
            "name": process_name,
            "pid": as_int(process_pid),
            "entity_id": process_entity_id,
            "executable": process_executable,
            "command_line": process_command_line,
        },
        "parent": {
            "name": parent_name,
            "pid": as_int(parent_pid),
            "entity_id": parent_entity_id,
            "executable": parent_executable,
            "command_line": parent_command_line,
        },
        "network": {
            "source_ip": source_ip,
            "source_port": as_int(source_port),
            "destination_ip": destination_ip,
            "destination_port": as_int(destination_port),
        },
        "dns": {
            "query": dns_query,
        },
        "file": {
            "name": file_name,
            "path": file_path,
            "sha256": sha256,
        },
        "registry": {
            "path": registry_path,
        },
        "image": image,
    }

def process_identity(
    process: Dict[str, Any],
    host: Optional[str] = None
) -> Optional[str]:

    entity_id = process.get("entity_id")
    host_key = safe_lower(host)

    if entity_id:
        return f"entity:{host_key}:{entity_id}"

    pid = process.get("pid")
    name = safe_lower(process.get("name"))

    if host and pid is not None and name:
        return f"fallback:{host_key}:{pid}:{name}"

    return None


def process_name(process: Dict[str, Any]) -> str:
    return safe_lower(process.get("name"))


def build_process_lifetimes(
    events: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:

    lifetimes: Dict[str, Dict[str, Any]] = {}

    for event in events:
        identity = process_identity(
            event["process"],
            event.get("host")
        )
        if not identity:
            continue

        timestamp = parse_timestamp(event.get("timestamp"))
        record = lifetimes.setdefault(
            identity,
            {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "termination_seen": False,
            },
        )

        record["first_seen"] = min(record["first_seen"], timestamp)
        record["last_seen"] = max(record["last_seen"], timestamp)

        if event["event_code"] == "5":
            record["termination_seen"] = True

    return lifetimes


def event_within_process_lifetime(
    event: Dict[str, Any],
    identity: Optional[str],
    lifetimes: Dict[str, Dict[str, Any]]
) -> bool:

    if not identity:
        return False

    lifetime = lifetimes.get(identity)
    if not lifetime:
        return True

    current = parse_timestamp(event.get("timestamp")).timestamp()
    start = lifetime["first_seen"].timestamp() - 2
    end = lifetime["last_seen"].timestamp() + 2

    return start <= current <= end


# ============================================================
# ELASTICSEARCH
# ============================================================

def check_elasticsearch() -> None:
    print("[*] Checking Elasticsearch connection...")
    client = get_client()

    if not client.ping():
        raise RuntimeError("Elasticsearch ping failed.")

    info = client.info()
    version = get_nested(info, "version", "number") or "unknown"
    print(f"[+] Elasticsearch connected (version {version})")


def _search_with_retry(body: Dict[str, Any]) -> Dict[str, Any]:
    last_error: Optional[Exception] = None
    client = get_client()

    for attempt in range(1, ES_RETRY_ATTEMPTS + 1):
        try:
            return client.search(index=SYSMON_INDEX, body=body)
        except Exception as exc:  # noqa: BLE001 - deliberately broad, this is I/O
            last_error = exc
            print(
                f"[!] Elasticsearch query failed "
                f"(attempt {attempt}/{ES_RETRY_ATTEMPTS}): {exc}"
            )
            if attempt < ES_RETRY_ATTEMPTS:
                time.sleep(ES_RETRY_BACKOFF_SECONDS * attempt)

    raise RuntimeError(
        f"Elasticsearch query failed after {ES_RETRY_ATTEMPTS} attempts"
    ) from last_error


def get_security_events() -> List[Dict[str, Any]]:
    """
    Collect both ECS and Raw Sysmon/Winlogbeat telemetry.

    The query deliberately accepts either event.code or EventID.
    _source contains both ECS paths and common flat/nested Sysmon fields.
    """
    fields = [
        "@timestamp",
        "timestamp",
        "event",
        "host",
        "user",
        "process",
        "source",
        "destination",
        "dns",
        "file",
        "registry",
        "winlog",

        # Flat Raw Sysmon / common Winlogbeat fields.
        "EventID",
        "EventRecordID",
        "UtcTime",
        "Computer",
        "User",
        "Image",
        "ParentImage",
        "ProcessId",
        "ProcessGuid",
        "CommandLine",
        "ParentProcessId",
        "ParentProcessGuid",
        "ParentCommandLine",
        "DestinationIp",
        "DestinationPort",
        "SourceIp",
        "SourcePort",
        "QueryName",
        "TargetFilename",
        "Hashes",
        "TargetObject",
        "RegistryPath",
        "ProcessName",
    ]

    filters: List[Dict[str, Any]] = [
        {
            "bool": {
                "should": [
                    {"exists": {"field": "event.code"}},
                    {"exists": {"field": "EventID"}},
                    {"exists": {"field": "winlog.event_id"}},
                ],
                "minimum_should_match": 1,
            }
        }
    ]

    events: List[Dict[str, Any]] = []
    search_after = None

    while len(events) < MAX_EVENTS:
        body: Dict[str, Any] = {
            "size": min(PAGE_SIZE, MAX_EVENTS - len(events)),
            "_source": fields,
            "query": {
                "bool": {
                    "filter": filters,
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc", "missing": "_first"}},
                {"_shard_doc": {"order": "asc"}},
            ],
        }

        if search_after is not None:
            body["search_after"] = search_after

        response = _search_with_retry(body)
        hits = response.get("hits", {}).get("hits", [])

        if not hits:
            break

        # Keep Elasticsearch hits raw here.
        # analyze() is the single normalization boundary so DEMO_MODE
        # and live Elasticsearch ingestion follow exactly the same path.
        events.extend(hits)

        next_sort = hits[-1].get("sort")
        if not next_sort:
            break

        search_after = next_sort

        if len(hits) < body["size"]:
            break

    return events[:MAX_EVENTS]

def extract_iocs(events: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    iocs = {
        "ip": set(),
        "domain": set(),
        "sha256": set(),
        "file_path": set(),
    }

    for event in events:
        for field in ("source_ip", "destination_ip"):
            value = event["network"].get(field)
            if value:
                iocs["ip"].add(safe_lower(value))

        domain = event["dns"].get("query")
        if domain:
            iocs["domain"].add(safe_lower(domain))

        sha256 = event["file"].get("sha256")
        if sha256:
            iocs["sha256"].add(safe_lower(sha256))

        file_path = event["file"].get("path")
        if file_path:
            iocs["file_path"].add(safe_lower(file_path))

    return iocs


# ============================================================
# CONTEXT ALLOWLIST
# ============================================================

def apply_known_good_context(
    event: Dict[str, Any],
    risk: int,
    evidence: List[Dict[str, Any]],
) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Dampens (never zeroes out) risk for events whose host or user is on
    an operator-supplied allowlist (ALLOWLISTED_HOSTS / ALLOWLISTED_USERS
    env vars). This is deliberately narrower than "suppress the alert":
    it is a negative evidence item like any other, so it still shows up
    in the explanation and still pulls confidence down via the existing
    negative-evidence mechanism - it does not hide anything.
    """
    host = safe_lower(event.get("host"))
    user = safe_lower(event.get("user"))

    if host not in ALLOWLISTED_HOSTS and user not in ALLOWLISTED_USERS:
        return risk, evidence

    dampened = max(0, risk - ALLOWLIST_DAMPENING)
    updated_evidence = list(evidence) + [{
        "type": "known_good_context",
        "negative": True,
        "weight": ALLOWLIST_DAMPENING,
        "description": (
            f"Host/user matches operational allowlist "
            f"(host={event.get('host')}, user={event.get('user')})"
        ),
    }]
    return dampened, updated_evidence


# ============================================================
# EVENT RISK / CONFIDENCE
# ============================================================

def analyze_behavior(event: Dict[str, Any]) -> Dict[str, Any]:
    risk = 0
    evidence: List[Dict[str, Any]] = []
    mitre: List[Dict[str, Any]] = []

    process = event["process"]
    name = process_name(process)
    command_line = safe_lower(process.get("command_line"))
    executable = safe_lower(process.get("executable"))

    # Process name: weak-to-medium evidence.
    if name in PROCESS_MITRE:
        technique, technique_name, base_risk = PROCESS_MITRE[name]
        risk += base_risk

        evidence.append({
            "type": "process_name",
            "weight": 10,
            "description": f"Security-sensitive process: {name}",
        })

        mitre.append({
            "technique": technique,
            "name": technique_name,
            "process": process.get("name"),
            "source": "process_name",
        })

    # Command-line patterns: stronger evidence.
    for pattern, technique, technique_name, pattern_risk, reason, confidence in COMMAND_PATTERNS:
        if not pattern.search(command_line):
            continue

        risk += pattern_risk

        evidence.append({
            "type": "command_line",
            "weight": min(confidence, 30),
            "description": reason,
        })

        mitre.append({
            "technique": technique,
            "name": technique_name,
            "process": process.get("name"),
            "source": "command_line",
        })

    if executable and any(part in executable for part in SUSPICIOUS_PATH_PARTS):
        risk += 10
        evidence.append({
            "type": "suspicious_path",
            "weight": 18,
            "description": "Executable launched from a commonly abused writable/user path",
        })

    # Benign evidence is explicitly represented.
    if (
        name in COMMON_LEGITIMATE_PROCESSES
        and not any(marker in command_line for marker in SUSPICIOUS_COMMAND_MARKERS)
    ):
        risk = max(0, risk - 6)
        evidence.append({
            "type": "benign_process_context",
            "negative": True,
            "weight": 12,
            "description": "Common Windows process; name alone is weak evidence",
        })

    return {
        "risk": clamp(risk),
        "evidence": evidence,
        "mitre": unique_list(mitre),
    }


def calculate_event_risk(event: Dict[str, Any]) -> Dict[str, Any]:
    code = event["event_code"]

    behavior = (
        analyze_behavior(event)
        if code == "1"
        else {"risk": 0, "evidence": [], "mitre": []}
    )

    risk = behavior["risk"]
    evidence = list(behavior["evidence"])
    mitre = list(behavior["mitre"])

    if code == "3":
        ip = event["network"].get("destination_ip")
        port = event["network"].get("destination_port")

        if ip:
            increment = 5 if is_private_ip(str(ip)) else 12
            risk += increment

            evidence.append({
                "type": "network",
                "weight": 12 if ip_is_public(str(ip)) else 6,
                "description": (
                    f"Network connection to {ip}"
                    + (f":{port}" if port else "")
                ),
            })

            if ip_is_public(str(ip)):
                evidence.append({
                    "type": "public_destination",
                    "weight": 10,
                    "description": "Connection targets a public IP",
                })

    elif code == "11":
        path = safe_lower(event["file"].get("path"))
        risk += 8

        evidence.append({
            "type": "file_creation",
            "weight": 8,
            "description": "File creation observed",
        })

        if event["file"].get("sha256"):
            risk += 5
            evidence.append({
                "type": "file_hash",
                "weight": 10,
                "description": "File SHA256 available",
            })

        if any(part in path for part in SUSPICIOUS_PATH_PARTS):
            risk += 8
            evidence.append({
                "type": "suspicious_file_path",
                "weight": 15,
                "description": "File created in writable/suspicious path",
            })

    elif code == "13":
        risk += 14

        evidence.append({
            "type": "registry_modification",
            "weight": 12,
            "description": "Registry value modification observed",
        })

        registry_path = safe_lower(event["registry"].get("path"))
        if registry_path:
            persistence_keys = (
                "\\run", "\\runonce", "\\winlogon", "\\userinit"
            )

            if any(key in registry_path for key in persistence_keys):
                risk += 12
                evidence.append({
                    "type": "persistence_registry",
                    "weight": 22,
                    "description": "Registry path may provide persistence",
                })

    elif code == "22":
        domain = event["dns"].get("query")
        if domain:
            risk += 4
            evidence.append({
                "type": "dns",
                "weight": 5,
                "description": f"DNS query: {domain}",
            })

    elif code == "5":
        risk += 1
        evidence.append({
            "type": "process_termination",
            "weight": 1,
            "description": "Process termination observed",
        })

    # Context allowlist: known-good host/user dampens risk like any
    # other negative evidence, applied before confidence is derived so
    # it also pulls confidence down through the normal mechanism below.
    risk, evidence = apply_known_good_context(event, risk, evidence)

    # Independent evidence categories.
    categories = {item["type"] for item in evidence}
    positive = [
        item for item in evidence
        if not item.get("negative")
    ]
    negative = [
        item for item in evidence
        if item.get("negative")
    ]

    raw_confidence = (
        min(len(categories) * 10, 35)
        + min(sum(item.get("weight", 0) for item in positive), 60)
        - min(sum(item.get("weight", 0) for item in negative), 20)
    )

    confidence = clamp(raw_confidence)

    return {
        "risk": clamp(risk),
        "confidence": confidence,
        "evidence": unique_list(evidence),
        "mitre": unique_list(mitre),
    }


# ============================================================
# PROCESS GRAPH
# ============================================================

def build_process_relationships(
    events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    relationships = []

    for event in events:
        if event["event_code"] != "1":
            continue

        child = event["process"]
        parent = event["parent"]

        child_id = process_identity(child, event.get("host"))
        parent_id = process_identity(parent, event.get("host"))

        if not child_id or not parent_id or child_id == parent_id:
            continue

        relationships.append({
            "type": "PROCESS_PARENT_CHILD",
            "timestamp": event.get("timestamp"),
            "host": event.get("host"),
            "user": event.get("user"),
            "parent_id": parent_id,
            "child_id": child_id,
            "parent": parent,
            "child": child,
            "event": event,
        })

    seen = set()
    output = []

    for relationship in sorted(
        relationships,
        key=lambda item: parse_timestamp(item["timestamp"])
    ):
        key = (
            relationship["parent_id"],
            relationship["child_id"],
            relationship.get("host"),
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(relationship)

    return output


def build_process_index(
    events: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:

    index: Dict[str, Dict[str, Any]] = {}

    for event in events:
        for key in ("process", "parent"):
            process = event[key]
            identity = process_identity(process, event.get("host"))

            if not identity:
                continue

            candidate = {
                **process,
                "host": event.get("host"),
                "user": event.get("user"),
                "timestamp": event.get("timestamp"),
            }

            existing = index.get(identity)
            if existing is None:
                index[identity] = candidate
                continue

            for field, value in candidate.items():
                if not existing.get(field) and value:
                    existing[field] = value

            if parse_timestamp(candidate.get("timestamp")) < parse_timestamp(
                existing.get("timestamp")
            ):
                existing["timestamp"] = candidate.get("timestamp")

    return index


def build_process_chains(
    events: List[Dict[str, Any]]
) -> List[List[Dict[str, Any]]]:

    relationships = build_process_relationships(events)
    if not relationships:
        return []

    process_index = build_process_index(events)

    children = defaultdict(list)
    child_ids = set()
    all_nodes = set()

    for relationship in relationships:
        parent_id = relationship["parent_id"]
        child_id = relationship["child_id"]

        children[parent_id].append(relationship)
        child_ids.add(child_id)
        all_nodes.update((parent_id, child_id))

    roots = sorted(set(children) - child_ids)
    if not roots:
        roots = sorted(all_nodes)

    chains = []

    def walk(
        current_id: str,
        path_ids: List[str],
        last_timestamp: Optional[str]
    ) -> None:

        if current_id in path_ids:
            return

        node = process_index.get(current_id)
        if not node:
            return

        current_path = path_ids + [current_id]
        valid_children = []

        for relationship in children.get(current_id, []):
            timestamp = relationship.get("timestamp")

            if (
                last_timestamp is not None
                and delta_seconds(last_timestamp, timestamp)
                > CORRELATION_WINDOW_SECONDS
            ):
                continue

            valid_children.append(relationship)

        if not valid_children:
            if len(current_path) >= 2:
                chains.append([
                    process_index[pid]
                    for pid in current_path
                    if pid in process_index
                ])
            return

        for relationship in valid_children:
            walk(
                relationship["child_id"],
                current_path,
                relationship.get("timestamp"),
            )

    for root in roots:
        walk(root, [], None)

    # Only emit root-to-leaf paths. Walking every internal node again
    # creates duplicate suffix chains (e.g. PowerShell -> reg.exe in
    # addition to explorer -> PowerShell -> reg.exe).

    unique_chains = []
    seen = set()

    for chain in chains:
        identities = tuple(
            process_identity(process, process.get("host"))
            for process in chain
        )

        if identities in seen:
            continue

        seen.add(identities)
        unique_chains.append(chain)

    return unique_chains


# ============================================================
# EVENT CORRELATION
# ============================================================

def event_relationship(
    a: Dict[str, Any],
    b: Dict[str, Any]
) -> Tuple[int, List[str], List[Dict[str, Any]]]:

    score = 0
    reasons: List[str] = []
    evidence: List[Dict[str, Any]] = []

    if delta_seconds(a.get("timestamp"), b.get("timestamp")) > CORRELATION_WINDOW_SECONDS:
        return 0, [], []

    a_id = process_identity(a["process"], a.get("host"))
    b_id = process_identity(b["process"], b.get("host"))
    b_parent_id = process_identity(b["parent"], b.get("host"))

    if a_id and a_id == b_id:
        score += 35
        reasons.append("Same process identity")
        evidence.append({"type": "process_identity", "weight": 35})

    if a_id and a_id == b_parent_id:
        score += 50
        reasons.append("Direct parent-child process relationship")
        evidence.append({"type": "parent_child", "weight": 50})

    if a.get("host") and a.get("host") == b.get("host"):
        score += 8
        reasons.append("Same host")
        evidence.append({"type": "same_host", "weight": 8})

    if a.get("user") and a.get("user") == b.get("user"):
        score += 6
        reasons.append("Same user")
        evidence.append({"type": "same_user", "weight": 6})

    a_ip = a["network"].get("destination_ip")
    b_ip = b["network"].get("destination_ip")

    if a_ip and b_ip and safe_lower(a_ip) == safe_lower(b_ip):
        score += 18
        reasons.append("Same destination IP")
        evidence.append({"type": "shared_destination_ip", "weight": 18})

    a_port = a["network"].get("destination_port")
    b_port = b["network"].get("destination_port")

    if (
        a_ip and b_ip
        and safe_lower(a_ip) == safe_lower(b_ip)
        and a_port and b_port
        and str(a_port) == str(b_port)
    ):
        score += 5
        reasons.append("Same destination port")
        # v15 fix: this rule previously scored without a matching
        # structured evidence entry, unlike every other rule here.
        evidence.append({"type": "shared_destination_port", "weight": 5})

    a_hash = safe_lower(a["file"].get("sha256"))
    b_hash = safe_lower(b["file"].get("sha256"))

    if a_hash and b_hash and a_hash == b_hash:
        score += 30
        reasons.append("Same file SHA256")
        evidence.append({"type": "shared_hash", "weight": 30})

    a_path = safe_lower(a["file"].get("path"))
    b_path = safe_lower(b["file"].get("path"))

    if a_path and b_path and a_path == b_path:
        score += 15
        reasons.append("Same file path")
        evidence.append({"type": "shared_file_path", "weight": 15})

    a_domain = safe_lower(a["dns"].get("query"))
    b_domain = safe_lower(b["dns"].get("query"))

    if a_domain and b_domain and a_domain == b_domain:
        score += 12
        reasons.append("Same DNS query")
        evidence.append({"type": "shared_domain", "weight": 12})

    time_delta = delta_seconds(a.get("timestamp"), b.get("timestamp"))

    if time_delta <= STRONG_CORRELATION_SECONDS:
        score += 10
        reasons.append("Within strong temporal window")
        evidence.append({"type": "temporal_strong", "weight": 10})
    else:
        score += 5
        reasons.append("Within correlation window")
        evidence.append({"type": "temporal", "weight": 5})

    return clamp(score), unique_list(reasons), unique_list(evidence)


def build_story_relationships(
    events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    ordered = sorted(
        events,
        key=lambda event: parse_timestamp(event.get("timestamp"))
    )

    output = []

    # Limit pairwise explosion.
    for index, first in enumerate(ordered):
        for second in ordered[index + 1:]:
            if delta_seconds(
                first.get("timestamp"),
                second.get("timestamp")
            ) > CORRELATION_WINDOW_SECONDS:
                break

            score, reasons, evidence = event_relationship(first, second)

            if score < MIN_EVENT_RELATION_SCORE:
                continue

            output.append({
                "from": first.get("id"),
                "to": second.get("id"),
                "score": score,
                "reasons": reasons,
                "evidence": evidence,
            })

    return output


# ============================================================
# ATTACK PROGRESSION
# ============================================================

def analyze_attack_progression(
    events: List[Dict[str, Any]]
) -> Dict[str, Any]:

    ordered = sorted(
        events,
        key=lambda event: parse_timestamp(event.get("timestamp"))
    )

    stages = [
        CODE_STAGE.get(event["event_code"])
        for event in ordered
        if event["event_code"] in CODE_STAGE
    ]

    stages = [stage for stage in stages if stage]

    bonus = 0
    reasons = []
    matched_patterns = []

    for first, second, value, reason in [
        (a, b, value, reason)
        for (a, b), value, reason in PROGRESSION_PATTERNS
    ]:
        found = False
        for i in range(len(stages) - 1):
            if stages[i] == first:
                for j in range(i + 1, len(stages)):
                    if stages[j] == second:
                        found = True
                        break
            if found:
                break

        if found:
            bonus += value
            reasons.append(reason)
            matched_patterns.append(f"{first}->{second}")

    distinct = set(stages)

    if len(distinct) >= 3:
        bonus += 10
        reasons.append("Three or more telemetry behavior categories observed")

    if len(distinct) >= 4:
        bonus += 10
        reasons.append("Multi-stage telemetry progression")

    return {
        "score": clamp(min(bonus, 50)),
        "reasons": unique_list(reasons),
        "stages": stages,
        "matched_patterns": unique_list(matched_patterns),
    }


# ============================================================
# STORY SCORING
# ============================================================

def severity_for(risk: int, confidence: int) -> str:
    if risk >= SEVERITY_CRITICAL_RISK and confidence >= SEVERITY_CRITICAL_CONFIDENCE:
        return "CRITICAL"
    if risk >= SEVERITY_HIGH_RISK and confidence >= SEVERITY_HIGH_CONFIDENCE:
        return "HIGH"
    if risk >= SEVERITY_MEDIUM_RISK:
        return "MEDIUM"
    return "LOW"


def build_attack_story(
    chain: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    number: int
) -> Dict[str, Any]:

    events = sorted(
        events,
        key=lambda event: parse_timestamp(event.get("timestamp"))
    )

    if not events:
        return {
            "chain_number": number,
            "story_id": stable_hash("story", number, "empty"),
            "start_time": None,
            "end_time": None,
            "event_count": 0,
            "risk_score": 0,
            "confidence": 0,
            "severity": "LOW",
            "mitre_techniques": [],
            "reasons": [],
            "evidence": [],
            "relationships": [],
            "events": [],
            "process_chain": chain,
            "iocs": {"ip": [], "domain": [], "sha256": [], "file_path": []},
            "progression": {},
        }

    assessments = [calculate_event_risk(event) for event in events]

    event_risks = [item["risk"] for item in assessments]

    reasons: List[str] = []
    evidence: List[Dict[str, Any]] = []
    mitre: List[Dict[str, Any]] = []

    for item in assessments:
        evidence.extend(item["evidence"])
        mitre.extend(item["mitre"])
        for ev in item["evidence"]:
            reasons.append(ev["description"])

    relationships = build_story_relationships(events)
    progression = analyze_attack_progression(events)
    reasons.extend(progression["reasons"])

    unique_mitre = {
        item["technique"]: item
        for item in mitre
        if item.get("technique")
    }

    iocs = extract_iocs(events)

    # Risk: strongest evidence dominates, secondary evidence contributes,
    # progression and impact add context.
    sorted_risks = sorted(event_risks, reverse=True)

    event_component = sorted_risks[0]
    if len(sorted_risks) > 1:
        event_component += int(sorted_risks[1] * 0.35)
    if len(sorted_risks) > 2:
        event_component += int(sorted_risks[2] * 0.15)

    relationship_component = min(
        sum(r["score"] for r in relationships) * 0.08,
        18
    )

    chain_component = min(max(len(chain) - 1, 0) * 4, 12)

    mitre_component = min(len(unique_mitre) * 5, 15)

    ioc_component = min(
        len(iocs["ip"]) * 3
        + len(iocs["sha256"]) * 5
        + len(iocs["domain"]) * 2,
        15
    )

    risk = clamp(
        event_component
        + relationship_component
        + chain_component
        + mitre_component
        + ioc_component
        + progression["score"] * 0.35
    )

    # Confidence uses independent categories rather than max().
    strong_relationships = [
        r for r in relationships if r["score"] >= 60
    ]

    confidence_components = {
        "event_count": min(len(events) * 4, 16),
        "strong_relationships": min(len(strong_relationships) * 8, 24),
        "process_chain": min(max(len(chain) - 1, 0) * 7, 21),
        "mitre_diversity": min(len(unique_mitre) * 6, 18),
        "telemetry_diversity": min(
            len({event["event_code"] for event in events}) * 5,
            15
        ),
    }

    if any(
        event["process"].get("entity_id")
        for event in events
    ):
        confidence_components["stable_process_identity"] = 8

    confidence = clamp(sum(confidence_components.values()))

    # Negative/benign evidence lowers confidence, not just risk.
    benign_evidence = sum(
        item.get("weight", 0)
        for item in evidence
        if item.get("negative")
    )
    confidence = clamp(confidence - min(benign_evidence // 2, 15))

    severity = severity_for(risk, confidence)

    story_id = stable_hash(
        "story",
        events[0].get("timestamp"),
        events[-1].get("timestamp"),
        *sorted(
            process_identity(
                process,
                process.get("host")
            ) or ""
            for process in chain
        ),
    )

    return {
        "chain_number": number,
        "story_id": story_id,
        "start_time": events[0].get("timestamp"),
        "end_time": events[-1].get("timestamp"),
        "event_count": len(events),
        "risk_score": risk,
        "confidence": confidence,
        "severity": severity,
        "mitre_techniques": list(unique_mitre.values()),
        "reasons": unique_list(reasons),
        "evidence": unique_list(evidence),
        "relationships": relationships,
        "events": events,
        "process_chain": chain,
        "iocs": {
            key: sorted(values)
            for key, values in iocs.items()
        },
        "progression": progression,
        "confidence_components": confidence_components,
    }


# ============================================================
# ORPHAN EVENT RECOVERY  (new in v15)
# ============================================================

def build_orphan_stories(
    events: List[Dict[str, Any]],
    start_number: int,
) -> List[Dict[str, Any]]:
    """
    build_process_chains() only ever sees processes that appear in a
    captured process-CREATION event (event code 1). A process that was
    already running before collection started - or whose creation event
    Sysmon/the collector missed - never becomes a chain node, so any
    event tied to it (a beacon, a suspicious DNS query, a dropped file)
    used to be silently dropped from every downstream story and
    campaign in v14.

    This recovers those events: anything NOT already claimed by a
    process-chain story (no "_correlation" tag) is correlated directly
    on IOC / network signals via the same event_relationship() used
    elsewhere, clustered with the same union-find approach used for
    campaigns, and turned into its own story so it can still surface on
    its own or link into a campaign through shared IOCs/MITRE/host.

    Same-host/same-time alone is deliberately NOT enough to cluster two
    orphan events - there is no process lineage to lean on here, so the
    bar for merging them has to be at least as strict as
    story_similarity's "strong_link" rule, not looser.
    """
    orphans = [
        event for event in events
        if "_correlation" not in event
        and event["event_code"] in RELEVANT_EVENT_CODES
    ]

    if not orphans:
        return []

    orphans = sorted(
        orphans,
        key=lambda event: parse_timestamp(event.get("timestamp"))
    )

    count = len(orphans)
    parent = list(range(count))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(count):
        for j in range(i + 1, count):
            if delta_seconds(
                orphans[i].get("timestamp"),
                orphans[j].get("timestamp"),
            ) > CORRELATION_WINDOW_SECONDS:
                break

            score, _reasons, evidence = event_relationship(orphans[i], orphans[j])

            if score < MIN_EVENT_RELATION_SCORE:
                continue

            evidence_types = {item["type"] for item in evidence}
            if not (evidence_types & STRONG_ORPHAN_EVIDENCE_TYPES):
                continue

            union(i, j)

    groups = defaultdict(list)
    for i in range(count):
        groups[find(i)].append(i)

    stories = []
    number = start_number

    for members in groups.values():
        cluster_events = [orphans[i] for i in members]
        story = build_attack_story([], cluster_events, number)

        # Keep the story if it shows real individual risk, or if it is
        # a genuine multi-event corroborated cluster. This drops the
        # inevitable flood of zero-risk singleton DNS/network noise
        # without re-introducing the original silent-drop problem for
        # anything that actually matters.
        if story["events"] and (story["risk_score"] > 0 or story["event_count"] > 1):
            story["orphan"] = True
            stories.append(story)
            number += 1

    return stories


# ============================================================
# CAMPAIGN CORRELATION
# ============================================================

def story_similarity(
    first: Dict[str, Any],
    second: Dict[str, Any]
) -> Tuple[int, List[str], List[Dict[str, Any]]]:

    if not first.get("start_time") or not second.get("start_time"):
        return 0, [], []

    distance = min(
        delta_seconds(first["end_time"], second["start_time"]),
        delta_seconds(second["end_time"], first["start_time"]),
    )

    if distance > CAMPAIGN_WINDOW_SECONDS:
        return 0, [], []

    score = 0
    reasons = []
    evidence = []

    first_iocs = first.get("iocs", {})
    second_iocs = second.get("iocs", {})

    shared_hash = bool(
        set(first_iocs.get("sha256", []))
        & set(second_iocs.get("sha256", []))
    )
    shared_ip = bool(
        set(first_iocs.get("ip", []))
        & set(second_iocs.get("ip", []))
    )
    shared_domain = bool(
        set(first_iocs.get("domain", []))
        & set(second_iocs.get("domain", []))
    )

    first_hosts = {
        event.get("host")
        for event in first["events"]
        if event.get("host")
    }
    second_hosts = {
        event.get("host")
        for event in second["events"]
        if event.get("host")
    }

    first_users = {
        event.get("user")
        for event in first["events"]
        if event.get("user")
    }
    second_users = {
        event.get("user")
        for event in second["events"]
        if event.get("user")
    }

    first_mitre = {
        item["technique"]
        for item in first.get("mitre_techniques", [])
    }
    second_mitre = {
        item["technique"]
        for item in second.get("mitre_techniques", [])
    }

    shared_mitre = bool(first_mitre & second_mitre)
    shared_host = bool(first_hosts & second_hosts)
    shared_user = bool(first_users & second_users)

    if shared_hash:
        score += 40
        reasons.append("Shared file hash")
        evidence.append({"type": "shared_hash", "weight": 40})

    if shared_ip:
        score += 30
        reasons.append("Shared IP")
        evidence.append({"type": "shared_ip", "weight": 30})

    if shared_domain:
        score += 25
        reasons.append("Shared domain")
        evidence.append({"type": "shared_domain", "weight": 25})

    if shared_mitre and shared_host:
        score += 22
        reasons.append("Shared host and ATT&CK technique")
        evidence.append({"type": "shared_host_mitre", "weight": 22})

    if shared_user and shared_mitre:
        score += 20
        reasons.append("Shared user and ATT&CK technique")
        evidence.append({"type": "shared_user_mitre", "weight": 20})

    if shared_host:
        score += 6
        reasons.append("Shared host")
    elif shared_user:
        score += 5
        reasons.append("Shared user")

    if distance <= STRONG_CORRELATION_SECONDS:
        score += 12
        reasons.append("Stories occur within strong temporal window")
        evidence.append({"type": "strong_temporal", "weight": 12})
    else:
        score += 5
        reasons.append("Stories occur within campaign window")

    # Cross-host movement is meaningful only when IOC-level or identity
    # evidence backs it up. A shared ATT&CK technique alone (e.g. two
    # unrelated hosts both merely running powershell.exe, which is
    # extremely common in any enterprise) is deliberately NOT enough on
    # its own to claim lateral movement between them - that claim is
    # the highest-stakes one this engine makes and deserves the
    # strictest bar, not the loosest. (Found via test_a_links_b_links_c:
    # v15 initially let two hosts merge on cross_host + shared_mitre
    # alone.)
    cross_host = bool(first_hosts and second_hosts and first_hosts != second_hosts)
    if cross_host and (shared_user or shared_ip or shared_domain or shared_hash):
        score += 12
        reasons.append("Cross-host activity with supporting evidence")
        evidence.append({"type": "cross_host", "weight": 12})

    # Critical rule: time + same host/user alone cannot create a campaign.
    # Shared ATT&CK technique only counts when it's paired with shared
    # host or shared user - never as a cross-host link by itself.
    strong_link = (
        shared_hash
        or shared_ip
        or shared_domain
        or (shared_host and shared_mitre)
        or (shared_user and shared_mitre)
        or (cross_host and (shared_user or shared_ip or shared_domain or shared_hash))
    )

    if not strong_link:
        return 0, [], []

    return clamp(score), unique_list(reasons), unique_list(evidence)


def build_campaigns(
    stories: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:

    if not stories:
        return []

    count = len(stories)
    parent = list(range(count))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    edges = []

    for i in range(count):
        for j in range(i + 1, count):
            score, reasons, evidence = story_similarity(stories[i], stories[j])

            if score < MIN_CAMPAIGN_RELATION_SCORE:
                continue

            edges.append((i, j, score, reasons, evidence))
            union(i, j)

    groups = defaultdict(list)
    for i in range(count):
        groups[find(i)].append(i)

    campaigns = []

    for campaign_number, members in enumerate(groups.values(), 1):
        member_stories = [stories[i] for i in members]
        campaign_edges = [
            edge for edge in edges
            if edge[0] in members and edge[1] in members
        ]

        # Risk combines strongest story, attack progression, impact and corroboration.
        max_story_risk = max(s["risk_score"] for s in member_stories)
        progression_bonus = max(
            (
                s.get("progression", {}).get("score", 0)
                for s in member_stories
            ),
            default=0
        )

        hosts = {
            event.get("host")
            for story in member_stories
            for event in story["events"]
            if event.get("host")
        }

        users = {
            event.get("user")
            for story in member_stories
            for event in story["events"]
            if event.get("user")
        }

        techniques = {
            item["technique"]
            for story in member_stories
            for item in story.get("mitre_techniques", [])
        }

        risk = clamp(
            max_story_risk
            + min(max(len(hosts) - 1, 0) * 5, 15)
            + min(max(len(techniques) - 1, 0) * 4, 12)
            + progression_bonus * 0.20
            + min(len(campaign_edges) * 3, 12)
        )

        # Confidence requires corroboration, not merely campaign size.
        member_confidences = [
            s["confidence"] for s in member_stories
        ]

        edge_strength = (
            sum(edge[2] for edge in campaign_edges)
            / len(campaign_edges)
            if campaign_edges else 0
        )

        confidence = clamp(
            max(member_confidences)
            + min(edge_strength * 0.20, 15)
            + min(max(len(member_stories) - 1, 0) * 4, 12)
        )

        progression = analyze_attack_progression([
            event
            for story in member_stories
            for event in story["events"]
        ])

        active = detect_active_attack(
            events=[
                event
                for story in member_stories
                for event in story["events"]
            ],
            risk=risk,
            confidence=confidence,
            progression=progression,
        )

        state = determine_attack_state(
            risk=risk,
            confidence=confidence,
            active=active,
            events=[
                event
                for story in member_stories
                for event in story["events"]
            ],
        )

        campaign_id = stable_hash(
            "campaign",
            *sorted(s["story_id"] for s in member_stories)
        )

        reasons = []
        for _, _, _, edge_reasons, _ in campaign_edges:
            reasons.extend(edge_reasons)

        reasons.extend(progression["reasons"])
        reasons.extend(active["reasons"])

        return_campaign = {
            "campaign_id": campaign_id,
            "campaign_number": campaign_number,
            "story_ids": [s["story_id"] for s in member_stories],
            "story_numbers": [s["chain_number"] for s in member_stories],
            "orphan_story_count": sum(
                1 for s in member_stories if s.get("orphan")
            ),
            "risk_score": risk,
            "confidence": confidence,
            "severity": severity_for(risk, confidence),
            "attack_state": state,
            "active_attack": active["active"],
            "active_score": active["score"],
            "affected_hosts": sorted(hosts),
            "affected_users": sorted(users),
            "mitre_techniques": sorted(techniques),
            "progression": progression,
            "relationships": [
                {
                    "from": stories[i]["story_id"],
                    "to": stories[j]["story_id"],
                    "score": score,
                    "reasons": edge_reasons,
                    "evidence": edge_evidence,
                }
                for i, j, score, edge_reasons, edge_evidence
                in campaign_edges
            ],
            "reasons": unique_list(reasons),
        }

        return_campaign["response"] = determine_response(return_campaign)
        campaigns.append(return_campaign)

    return campaigns


# ============================================================
# ACTIVE ATTACK / STATE MACHINE
# ============================================================

def detect_active_attack(
    events: List[Dict[str, Any]],
    risk: int,
    confidence: int,
    progression: Dict[str, Any],
) -> Dict[str, Any]:

    if not events:
        return {"active": False, "score": 0, "reasons": []}

    ordered = sorted(
        events,
        key=lambda event: parse_timestamp(event.get("timestamp"))
    )

    latest = parse_timestamp(ordered[-1].get("timestamp"))
    now = datetime.now(timezone.utc)

    # For historical replay/demo data, "now" may be far away.
    # In that case, activity recency is measured relative to the last event.
    recent_activity = True
    if latest != datetime.min.replace(tzinfo=timezone.utc):
        age = (now - latest).total_seconds()
        if age > ACTIVE_RECENCY_SECONDS:
            recent_activity = False

    score = 0
    reasons = []

    if risk >= ACTIVE_RISK_GATE:
        score += 25
        reasons.append("High campaign risk")

    if confidence >= ACTIVE_CONFIDENCE_GATE:
        score += 20
        reasons.append("High analytical confidence")

    if progression.get("score", 0) >= ACTIVE_PROGRESSION_GATE:
        score += 25
        reasons.append("Multi-stage attack progression")

    if len({
        event.get("host")
        for event in events
        if event.get("host")
    }) >= 2:
        score += 15
        reasons.append("Activity spans multiple hosts")

    if recent_activity:
        score += 15
        reasons.append("Recent activity observed")

    active = (
        score >= ACTIVE_ATTACK_SCORE_THRESHOLD
        and progression.get("score", 0) >= ACTIVE_ATTACK_PROGRESSION_MIN
        and confidence >= ACTIVE_ATTACK_CONFIDENCE_MIN
    )

    return {
        "active": active,
        "score": clamp(score),
        "reasons": unique_list(reasons),
        "recent_activity": recent_activity,
    }


def determine_attack_state(
    risk: int,
    confidence: int,
    active: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> str:

    if active["active"]:
        return "ACTIVE_ATTACK"

    if risk >= STATE_HIGH_CONFIDENCE_RISK and confidence >= STATE_HIGH_CONFIDENCE_CONFIDENCE:
        return "HIGH_CONFIDENCE"

    if risk >= STATE_CORRELATED_RISK or confidence >= STATE_CORRELATED_CONFIDENCE:
        return "CORRELATED"

    if events:
        return "SUSPICIOUS"

    return "NEW"


# ============================================================
# RESPONSE
# ============================================================

def determine_response(campaign: Dict[str, Any]) -> Dict[str, Any]:
    risk = campaign["risk_score"]
    confidence = campaign["confidence"]
    state = campaign["attack_state"]
    hosts = campaign.get("affected_hosts", [])

    if (
        state == "ACTIVE_ATTACK"
        and risk >= RESPONSE_CRITICAL_RISK
        and confidence >= RESPONSE_CRITICAL_CONFIDENCE
    ):
        return {
            # Deliberately not called "severity": a campaign can be
            # situation-severity CRITICAL (severity_for()) without yet
            # meeting the higher, state-gated bar for a CRITICAL
            # response. Using one shared field name for two different
            # gates is what made v14 look like it had a display bug
            # whenever they disagreed - they were always allowed to.
            "response_urgency": "CRITICAL",
            "action": "IMMEDIATE_SOC_INTERVENTION",
            "approval_required": True,
            "simulation_only": True,
            "recommended_containment": (
                f"Consider isolating affected host(s): {', '.join(hosts)}"
                if hosts
                else "Consider host isolation after analyst validation"
            ),
            "recommendations": [
                "Validate process lineage and attack progression",
                "Pivot on all associated IPs, domains and hashes",
                "Check for lateral movement on affected hosts",
                "Preserve forensic evidence",
                "Require human approval before any containment",
            ],
        }

    if risk >= RESPONSE_HIGH_RISK and confidence >= RESPONSE_HIGH_CONFIDENCE:
        return {
            "response_urgency": "HIGH",
            "action": "SOC_INVESTIGATION",
            "approval_required": True,
            "simulation_only": True,
            "recommended_containment": "Prepare containment recommendation",
            "recommendations": [
                "Investigate complete process chains",
                "Validate command-line behavior",
                "Pivot on IOCs",
                "Check persistence and lateral movement evidence",
            ],
        }

    if risk >= RESPONSE_MEDIUM_RISK:
        return {
            "response_urgency": "MEDIUM",
            "action": "MONITOR_AND_INVESTIGATE",
            "approval_required": False,
            "simulation_only": True,
            "recommended_containment": None,
            "recommendations": [
                "Review related telemetry",
                "Validate user and host context",
                "Search for additional indicators",
            ],
        }

    return {
        "response_urgency": "LOW",
        "action": "MONITOR",
        "approval_required": False,
        "simulation_only": True,
        "recommended_containment": None,
        "recommendations": [
            "Continue monitoring and validate if required"
        ],
    }


# ============================================================
# PIPELINE
# ============================================================

def assign_events_to_chains(
    events: List[Dict[str, Any]],
    chains: List[List[Dict[str, Any]]],
    lifetimes: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:

    stories = []

    for number, chain in enumerate(chains, 1):
        chain_ids = {
            process_identity(process, process.get("host"))
            for process in chain
        }

        chain_events = []

        for event in events:
            event_id = process_identity(
                event["process"],
                event.get("host")
            )
            parent_id = process_identity(
                event["parent"],
                event.get("host")
            )

            score = 0
            reasons = []

            if event_id and event_id in chain_ids:
                if event_within_process_lifetime(
                    event,
                    event_id,
                    lifetimes
                ):
                    score += 55
                    reasons.append("Same process identity")
                else:
                    continue

            if parent_id and parent_id in chain_ids:
                score += 45
                reasons.append("Event process is child of chain process")

            if event.get("host") and any(
                process.get("host") == event.get("host")
                for process in chain
            ):
                score += 5

            if score >= MIN_EVENT_STORY_SCORE:
                event["_correlation"] = {
                    "score": clamp(score),
                    "reasons": unique_list(reasons),
                }
                chain_events.append(event)

        # A process chain itself must have at least one event.
        if chain_events:
            stories.append(
                build_attack_story(
                    chain,
                    chain_events,
                    number,
                )
            )

    return stories


def analyze(hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    events = [normalize_event(hit) for hit in hits]

    # Detect schema/normalization failures early instead of silently
    # collapsing thousands of documents into one empty fingerprint.
    usable = [
        event for event in events
        if event.get("event_code")
        or event.get("timestamp")
        or event.get("host")
        or event.get("process", {}).get("name")
    ]

    if events and not usable:
        raise RuntimeError(
            "Normalization produced no usable events. "
            "The Elasticsearch documents do not match ECS, flat Sysmon, "
            "or nested Winlogbeat mappings."
        )

    # Deduplicate by Elastic document ID / stable event fingerprint.
    deduped = []
    seen = set()

    for event in usable:
        fingerprint = event.get("id") or stable_hash(
            event.get("timestamp"),
            event.get("event_code"),
            event.get("host"),
            event.get("user"),
            event["process"].get("entity_id"),
            event["process"].get("pid"),
            event["process"].get("name"),
            event["process"].get("command_line"),
            event["parent"].get("entity_id"),
            event["parent"].get("pid"),
            event["network"].get("source_ip"),
            event["network"].get("source_port"),
            event["network"].get("destination_ip"),
            event["network"].get("destination_port"),
            event["dns"].get("query"),
            event["file"].get("path"),
            event["file"].get("sha256"),
            event["registry"].get("path"),
        )

        if fingerprint in seen:
            continue

        seen.add(fingerprint)
        event["_fingerprint"] = fingerprint
        deduped.append(event)

    events = sorted(
        deduped,
        key=lambda event: parse_timestamp(event.get("timestamp"))
    )

    lifetimes = build_process_lifetimes(events)
    relationships = build_process_relationships(events)
    chains = build_process_chains(events)
    stories = assign_events_to_chains(events, chains, lifetimes)

    orphan_stories = build_orphan_stories(
        events,
        start_number=len(stories) + 1,
    )
    stories = stories + orphan_stories

    campaigns = build_campaigns(stories)

    return {
        "events": events,
        "lifetimes": lifetimes,
        "process_relationships": relationships,
        "chains": chains,
        "stories": stories,
        "campaigns": campaigns,
        "statistics": {
            "events": len(events),
            "process_relationships": len(relationships),
            "process_chains": len(chains),
            "attack_stories": len(stories),
            "orphan_stories": len(orphan_stories),
            "campaigns": len(campaigns),
            "event_distribution": dict(
                Counter(event["event_code"] for event in events)
            ),
        },
    }

def _event_id_for_investigation(event: Dict[str, Any]) -> str:
    return str(
        event.get("id")
        or event.get("_fingerprint")
        or stable_hash(
            event.get("timestamp"),
            event.get("event_code"),
            event.get("host"),
            event.get("user"),
            event.get("process", {}).get("entity_id"),
            event.get("process", {}).get("pid"),
            event.get("process", {}).get("name"),
            event.get("process", {}).get("command_line"),
            event.get("parent", {}).get("entity_id"),
            event.get("parent", {}).get("pid"),
            event.get("network", {}).get("source_ip"),
            event.get("network", {}).get("source_port"),
            event.get("network", {}).get("destination_ip"),
            event.get("network", {}).get("destination_port"),
            event.get("dns", {}).get("query"),
            event.get("file", {}).get("path"),
            event.get("file", {}).get("sha256"),
            event.get("registry", {}).get("path"),
        )
    )


def summarize_progression_stages(stages: List[str]) -> List[Dict[str, Any]]:
    """
    Collapse consecutive identical progression stages into
    {"stage": "execution", "count": 162}-style summary entries instead
    of repeating the same stage hundreds of times. The raw stage list
    itself is untouched and still available (analyze_attack_progression's
    output is never modified) - this only affects how it is presented.
    """
    if not stages:
        return []

    summary: List[Dict[str, Any]] = []
    current = stages[0]
    count = 1

    for stage in stages[1:]:
        if stage == current:
            count += 1
        else:
            summary.append({"stage": current, "count": count})
            current = stage
            count = 1

    summary.append({"stage": current, "count": count})
    return summary


def build_event_view(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Curated, analyst-facing view of ONE event. Only includes fields
    that actually have a value on this event - never fabricates a
    field the schema doesn't have (e.g. there is no authentication/
    logon data anywhere in this pipeline, so it is simply never shown,
    not displayed as a fake "N/A" section). Internal pipeline-only
    fields (_fingerprint, _correlation's internal shape) are translated
    into a small "correlation" summary rather than exposed raw.
    """

    def present(value: Any) -> Any:
        if value in (None, "", [], {}):
            return None
        return value

    def section(fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cleaned = {k: v for k, v in fields.items() if present(v) is not None}
        return cleaned or None

    process = event.get("process", {}) or {}
    parent = event.get("parent", {}) or {}
    network = event.get("network", {}) or {}
    dns = event.get("dns", {}) or {}
    file_ = event.get("file", {}) or {}
    registry = event.get("registry", {}) or {}
    correlation = event.get("_correlation", {}) or {}

    view: Dict[str, Any] = {
        "event_id": _event_id_for_investigation(event),
        "timestamp": present(event.get("timestamp")),
        "event_code": present(event.get("event_code")),
        "event_name": EVENT_NAMES.get(str(event.get("event_code")), None),
        "event_action": present(event.get("event_action")),
        "host": present(event.get("host")),
        "user": present(event.get("user")),
        "process": section({
            "name": process.get("name"),
            "executable": process.get("executable"),
            "pid": process.get("pid"),
            "entity_id": process.get("entity_id"),
            "command_line": process.get("command_line"),
        }),
        "parent_process": section({
            "name": parent.get("name"),
            "executable": parent.get("executable"),
            "pid": parent.get("pid"),
            "entity_id": parent.get("entity_id"),
            "command_line": parent.get("command_line"),
        }),
        "network": section({
            "source_ip": network.get("source_ip"),
            "source_port": network.get("source_port"),
            "destination_ip": network.get("destination_ip"),
            "destination_port": network.get("destination_port"),
        }),
        "dns": section({"query": dns.get("query")}),
        "file": section({
            "name": file_.get("name"),
            "path": file_.get("path"),
            "sha256": file_.get("sha256"),
        }),
        "registry": section({"path": registry.get("path")}),
        "correlation": section({
            "score": correlation.get("score"),
            "reasons": correlation.get("reasons"),
        }),
    }

    return {k: v for k, v in view.items() if v is not None}


def build_process_chain_view(chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ordered, display-ready process chain (renders as an arrow chain
    in the UI: WINWORD.EXE -> powershell.exe -> cmd.exe -> ...)."""
    view = []

    for index, process in enumerate(chain):
        view.append({
            "order": index,
            "name": process.get("name"),
            "pid": process.get("pid"),
            "parent_pid": chain[index - 1].get("pid") if index > 0 else None,
            "entity_id": process.get("entity_id"),
            "executable": process.get("executable"),
            "command_line": process.get("command_line"),
            "user": process.get("user"),
            "host": process.get("host"),
        })

    return view


def _event_carries_ioc(event: Dict[str, Any], ioc_type: str, value: str) -> bool:
    network = event.get("network", {}) or {}

    if ioc_type == "ip":
        return value in {
            safe_lower(network.get("source_ip")),
            safe_lower(network.get("destination_ip")),
        }
    if ioc_type == "domain":
        return value == safe_lower((event.get("dns", {}) or {}).get("query"))
    if ioc_type == "sha256":
        return value == safe_lower((event.get("file", {}) or {}).get("sha256"))
    if ioc_type == "file_path":
        return value == safe_lower((event.get("file", {}) or {}).get("path"))
    return False


def build_ioc_index(
    story_iocs_by_id: Dict[str, Dict[str, Any]],
    events_by_id: Dict[str, Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Reverse-indexes the IOCs that extract_iocs() already produced per
    story (spec: "For each IOC, show where it was observed"). Does not
    change IOC extraction logic - purely re-indexes its output.
    """
    buckets: Dict[str, Dict[str, Dict[str, Any]]] = {
        "ip": {}, "domain": {}, "sha256": {}, "file_path": {},
    }

    for story_id, info in story_iocs_by_id.items():
        iocs = info.get("iocs", {}) or {}
        event_ids = info.get("event_ids", [])

        for ioc_type in buckets:
            for value in iocs.get(ioc_type, []) or []:
                entry = buckets[ioc_type].setdefault(value, {
                    "value": value, "type": ioc_type,
                    "story_ids": set(), "event_ids": set(),
                })
                entry["story_ids"].add(story_id)

                for event_id in event_ids:
                    event = events_by_id.get(event_id)
                    if event and _event_carries_ioc(event, ioc_type, value):
                        entry["event_ids"].add(event_id)

    return {
        ioc_type: [
            {
                "value": entry["value"],
                "type": entry["type"],
                "story_ids": sorted(entry["story_ids"]),
                "event_ids": sorted(entry["event_ids"]),
            }
            for entry in sorted(values.values(), key=lambda e: e["value"])
        ]
        for ioc_type, values in buckets.items()
    }


def build_campaign_summary(campaign: Dict[str, Any]) -> Dict[str, Any]:
    """The primary campaign view (spec section 1): every field an
    analyst needs to answer 'what is this, how dangerous, is it active,
    why was it correlated' - WITHOUT embedding story/event bodies. Those
    are reached via story_ids -> one file per story, on demand."""
    progression = campaign.get("progression", {}) or {}

    return {
        "campaign_id": campaign.get("campaign_id"),
        "campaign_number": campaign.get("campaign_number"),
        "risk_score": campaign.get("risk_score"),
        "confidence": campaign.get("confidence"),
        "severity": campaign.get("severity"),
        "attack_state": campaign.get("attack_state"),
        "active_attack": campaign.get("active_attack"),
        "active_score": campaign.get("active_score"),
        "affected_hosts": campaign.get("affected_hosts", []),
        "affected_users": campaign.get("affected_users", []),
        "mitre_techniques": campaign.get("mitre_techniques", []),
        "progression": {
            "score": progression.get("score", 0),
            "reasons": progression.get("reasons", []),
            "matched_patterns": progression.get("matched_patterns", []),
            "stage_summary": summarize_progression_stages(progression.get("stages", [])),
        },
        "story_count": len(campaign.get("story_ids", [])),
        "story_ids": campaign.get("story_ids", []),
        "story_numbers": campaign.get("story_numbers", []),
        "orphan_story_count": campaign.get("orphan_story_count", 0),
        "relationships": campaign.get("relationships", []),
        "reasons": campaign.get("reasons", []),
        "response": campaign.get("response", {}),
    }


def build_story_detail(story: Dict[str, Any], campaign_id: Optional[str]) -> Dict[str, Any]:
    """
    Full analyst-facing story detail - the payload for one
    stories/<story_id>.json file, opened only when an analyst expands
    that specific story (spec section 3 + 4).
    """
    events = story.get("events", []) or []
    event_views = [build_event_view(event) for event in events]
    progression = story.get("progression", {}) or {}
    stages = progression.get("stages", [])

    return {
        "story_id": story.get("story_id"),
        "story_number": story.get("chain_number"),
        "campaign_id": campaign_id,
        "orphan": bool(story.get("orphan", False)),
        "start_time": story.get("start_time"),
        "end_time": story.get("end_time"),
        "event_count": story.get("event_count", len(events)),
        "risk_score": story.get("risk_score", 0),
        "confidence": story.get("confidence", 0),
        "severity": story.get("severity", "LOW"),
        "mitre_techniques": story.get("mitre_techniques", []),
        "reasons": story.get("reasons", []),
        "evidence": story.get("evidence", []),
        "iocs": story.get("iocs", {}),
        "process_chain": build_process_chain_view(story.get("process_chain", [])),
        "relationships": story.get("relationships", []),
        "progression": {
            "score": progression.get("score", 0),
            "reasons": progression.get("reasons", []),
            "matched_patterns": progression.get("matched_patterns", []),
            "stage_summary": summarize_progression_stages(stages),
            "raw_stage_count": len(stages),
        },
        "events": event_views,
    }


# ============================================================
# JSON EXPORT  (v15-compatible - unchanged shape, no investigation
# data embedded here anymore; see export_analyst_view for that)
# ============================================================

def export_campaigns_json(result: Dict[str, Any], path: str) -> None:
    payload = {
        "schema_version": "16.2",
        "statistics": result["statistics"],
        "campaigns": result["campaigns"],
    }

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(make_json_safe(payload), handle, indent=2, default=str)

    print(f"[+] Exported campaign results to {path}")


# ============================================================
# ANALYST VIEW EXPORT  (new: replaces the old duplicating
# build_investigation_view/_build_story_investigation)
# ============================================================

def export_analyst_view(result: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """
    Writes an on-demand-friendly analyst presentation layer, structured
    so a backend never has to load the whole dataset to answer one
    request:

        <output_dir>/campaigns_index.json    - all campaign summaries (small)
        <output_dir>/stories_index.json      - lightweight story listing (small)
        <output_dir>/stories/<story_id>.json - one file per story, full detail
        <output_dir>/iocs_index.json         - IOC -> story/event reverse index
        <output_dir>/statistics.json         - engine run statistics

    Each story is written to its OWN file instead of being embedded
    inside every campaign that references it (v16.1's build_investigation_view
    duplicated full story bodies into every campaign's "investigation"
    key AND into a top-level map - this writes each story's detail
    exactly once). This is purely a re-shaping of the same analysis
    result - no re-analysis, no changed scores, no changed correlation.

    Returns the campaigns_index list (handy for tests/callers that want
    the in-memory result without re-reading the files).
    """
    os.makedirs(output_dir, exist_ok=True)
    stories_dir = os.path.join(output_dir, "stories")
    os.makedirs(stories_dir, exist_ok=True)

    story_by_id = {story["story_id"]: story for story in result.get("stories", [])}

    story_to_campaign: Dict[str, str] = {}
    for campaign in result.get("campaigns", []):
        for story_id in campaign.get("story_ids", []):
            story_to_campaign[story_id] = campaign.get("campaign_id")

    campaigns_index = [build_campaign_summary(c) for c in result.get("campaigns", [])]

    stories_index = []
    story_iocs_by_id: Dict[str, Dict[str, Any]] = {}
    events_by_id: Dict[str, Dict[str, Any]] = {}

    for story_id, story in story_by_id.items():
        campaign_id = story_to_campaign.get(story_id)
        detail = build_story_detail(story, campaign_id)

        with open(os.path.join(stories_dir, f"{story_id}.json"), "w", encoding="utf-8") as handle:
            json.dump(make_json_safe(detail), handle, indent=2, default=str)

        stories_index.append({
            "story_id": story_id,
            "campaign_id": campaign_id,
            "story_number": detail["story_number"],
            "orphan": detail["orphan"],
            "risk_score": detail["risk_score"],
            "confidence": detail["confidence"],
            "severity": detail["severity"],
            "event_count": detail["event_count"],
            "start_time": detail["start_time"],
            "end_time": detail["end_time"],
        })

        event_ids = [_event_id_for_investigation(event) for event in story.get("events", [])]
        story_iocs_by_id[story_id] = {"iocs": story.get("iocs", {}), "event_ids": event_ids}

        for event in story.get("events", []):
            events_by_id[_event_id_for_investigation(event)] = event

    ioc_index = build_ioc_index(story_iocs_by_id, events_by_id)

    with open(os.path.join(output_dir, "campaigns_index.json"), "w", encoding="utf-8") as handle:
        json.dump(make_json_safe(campaigns_index), handle, indent=2, default=str)

    with open(os.path.join(output_dir, "stories_index.json"), "w", encoding="utf-8") as handle:
        json.dump(make_json_safe(stories_index), handle, indent=2, default=str)

    with open(os.path.join(output_dir, "iocs_index.json"), "w", encoding="utf-8") as handle:
        json.dump(make_json_safe(ioc_index), handle, indent=2, default=str)

    with open(os.path.join(output_dir, "statistics.json"), "w", encoding="utf-8") as handle:
        json.dump(make_json_safe(result.get("statistics", {})), handle, indent=2, default=str)

    print(
        f"[+] Exported analyst view to {output_dir}/ "
        f"({len(campaigns_index)} campaigns, {len(stories_index)} stories, "
        f"one file per story)"
    )

    return campaigns_index


# ============================================================
# DEMO SCENARIO  (new in v15 - no Elasticsearch required)
# ============================================================

def _demo_hit(
    doc_id: str,
    timestamp: str,
    event_code: str,
    host: str,
    user: str,
    process_name: str,
    process_pid: int,
    process_entity_id: str,
    parent_name: Optional[str] = None,
    parent_pid: Optional[int] = None,
    parent_entity_id: Optional[str] = None,
    command_line: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_port: Optional[int] = None,
    dns_query: Optional[str] = None,
    file_path: Optional[str] = None,
    file_sha256: Optional[str] = None,
    registry_path: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "_id": doc_id,
        "_source": {
            "@timestamp": timestamp,
            "event": {"code": event_code},
            "host": {"name": host},
            "user": {"name": user},
            "process": {
                "name": process_name,
                "pid": process_pid,
                "entity_id": process_entity_id,
                "executable": f"C:\\Windows\\System32\\{process_name}",
                "command_line": command_line,
                "parent": {
                    "name": parent_name,
                    "pid": parent_pid,
                    "entity_id": parent_entity_id,
                    "executable": (
                        f"C:\\Windows\\System32\\{parent_name}"
                        if parent_name else None
                    ),
                    "command_line": None,
                },
            },
            "source": {"ip": "10.10.10.50" if destination_ip else None},
            "destination": {
                "ip": destination_ip,
                "port": destination_port,
            },
            "dns": {"question": {"name": dns_query}} if dns_query else {},
            "file": {
                "path": file_path,
                "hash": {"sha256": file_sha256} if file_sha256 else {},
            },
            "registry": {"path": registry_path} if registry_path else {},
        },
    }


def generate_demo_scenario() -> List[Dict[str, Any]]:
    """
    Self-contained synthetic replay of the MVP attack scenario from the
    project brief: suspicious PowerShell -> credential access ->
    lateral movement to a second host, tied together by a shared C2 IP
    and a shared file hash. Runs with zero external dependencies, so a
    live demo never has to depend on a live Elasticsearch connection.
    """
    base = datetime(2026, 8, 19, 10, 0, 0, tzinfo=timezone.utc)

    # Build ISO timestamps relative to `base`.
    from datetime import timedelta

    def iso(seconds: int) -> str:
        return (base + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    c2_ip = "203.0.113.77"
    payload_hash = "44d88612fea8a8f36de82e1278abb02f" * 2  # fake 64-hex sha256

    hits = [
        # Stage 1: explorer.exe spawns encoded PowerShell on HOST-01
        _demo_hit(
            "demo-1", iso(0), "1", "HOST-01", "CORP\\jsmith",
            "powershell.exe", 4100, "proc-h1-ps1",
            parent_name="explorer.exe", parent_pid=3050, parent_entity_id="proc-h1-explorer",
            command_line="powershell.exe -nop -w hidden -encodedcommand SQBFAFgA...",
        ),
        # Stage 2: that PowerShell reaches out to the C2 IP
        _demo_hit(
            "demo-2", iso(20), "3", "HOST-01", "CORP\\jsmith",
            "powershell.exe", 4100, "proc-h1-ps1",
            destination_ip=c2_ip, destination_port=443,
        ),
        # Stage 3: PowerShell drops a payload with a known hash
        _demo_hit(
            "demo-3", iso(35), "11", "HOST-01", "CORP\\jsmith",
            "powershell.exe", 4100, "proc-h1-ps1",
            file_path="C:\\Users\\Public\\update.exe", file_sha256=payload_hash,
        ),
        # Stage 4: persistence via Run key
        _demo_hit(
            "demo-4", iso(50), "13", "HOST-01", "CORP\\jsmith",
            "powershell.exe", 4100, "proc-h1-ps1",
            registry_path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        ),
        # Stage 5: credential access - reg.exe dumping SAM-adjacent hive
        _demo_hit(
            "demo-5", iso(70), "1", "HOST-01", "CORP\\jsmith",
            "reg.exe", 4212, "proc-h1-reg",
            parent_name="powershell.exe", parent_pid=4100, parent_entity_id="proc-h1-ps1",
            command_line="reg.exe add HKLM\\SAM\\...",
        ),
        # Stage 6: lateral movement - second host, same C2 IP and same payload hash
        _demo_hit(
            "demo-6", iso(240), "1", "HOST-02", "CORP\\jsmith",
            "powershell.exe", 5200, "proc-h2-ps1",
            parent_name="wmiprvse.exe", parent_pid=5100, parent_entity_id="proc-h2-wmi",
            command_line="powershell.exe -nop -w hidden -encodedcommand SQBFAFgA...",
        ),
        _demo_hit(
            "demo-7", iso(255), "3", "HOST-02", "CORP\\jsmith",
            "powershell.exe", 5200, "proc-h2-ps1",
            destination_ip=c2_ip, destination_port=443,
        ),
        _demo_hit(
            "demo-8", iso(270), "11", "HOST-02", "CORP\\jsmith",
            "powershell.exe", 5200, "proc-h2-ps1",
            file_path="C:\\Users\\Public\\update.exe", file_sha256=payload_hash,
        ),
    ]

    return hits


# ============================================================
# CLI OUTPUT
# ============================================================

def print_campaigns(campaigns: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 100)
    print("ATTACK CAMPAIGNS")
    print("=" * 100)

    if not campaigns:
        print("[-] No attack campaigns generated.")
        return

    for campaign in campaigns:
        print()
        print(
            f"Campaign #{campaign['campaign_number']} "
            f"[{campaign['campaign_id']}]"
        )
        print(f"  Situation Severity : {campaign['severity']}")
        print(f"  Risk               : {campaign['risk_score']}/100")
        print(f"  Confidence         : {campaign['confidence']}%")
        print(f"  State              : {campaign['attack_state']}")
        print(f"  Active Attack      : {campaign['active_attack']}")
        print(f"  Active Score       : {campaign['active_score']}/100")
        print(f"  Hosts              : {', '.join(campaign['affected_hosts']) or 'N/A'}")
        print(f"  Users              : {', '.join(campaign['affected_users']) or 'N/A'}")
        print(
            f"  Techniques         : "
            f"{', '.join(campaign['mitre_techniques']) or 'N/A'}"
        )
        if campaign.get("orphan_story_count"):
            print(f"  Orphan stories     : {campaign['orphan_story_count']}")

        response = campaign["response"]
        print(f"  Response Urgency   : {response['response_urgency']}")
        print(f"  Response Action    : {response['action']}")

        for recommendation in response["recommendations"]:
            print(f"    -> {recommendation}")


def print_statistics(result: Dict[str, Any]) -> None:
    stats = result["statistics"]

    print("\n" + "=" * 100)
    print("ENGINE STATISTICS")
    print("=" * 100)
    print(f"Events               : {stats['events']}")
    print(f"Process relations    : {stats['process_relationships']}")
    print(f"Process chains       : {stats['process_chains']}")
    print(f"Attack stories       : {stats['attack_stories']}")
    print(f"  of which orphan    : {stats['orphan_stories']}")
    print(f"Campaigns            : {stats['campaigns']}")

    print("\nEVENT DISTRIBUTION")
    print("-" * 100)

    for code, count in sorted(
        stats["event_distribution"].items(),
        key=lambda item: int(item[0]) if item[0].isdigit() else 999
    ):
        print(
            f"  EID {code:<3} "
            f"{EVENT_NAMES.get(code, 'Unknown'):<28} "
            f"{count}"
        )


# ============================================================
# MAIN
# ============================================================

def send_to_incident_api(result: Dict[str, Any]) -> int:
    """Send the raw analysis result to the separate Incident API."""
    payload_data = {
        "stories": result.get("stories", []),
        "campaigns": result.get("campaigns", []),
    }

    payload = json.dumps(
        make_json_safe(payload_data),
        default=str,
    ).encode("utf-8")

    request = __import__("urllib.request", fromlist=["Request"]).Request(
        INCIDENT_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with __import__("urllib.request", fromlist=["urlopen"]).urlopen(
        request,
        timeout=INCIDENT_API_TIMEOUT,
    ) as response:
        response_data = json.loads(response.read().decode("utf-8"))

    if not isinstance(response_data, list):
        raise RuntimeError("Incident API returned an unexpected response")

    print(
        f"[+] Incident API ingestion successful: "
        f"{len(response_data)} incident(s)"
    )
    return len(response_data)


def main() -> None:
    print()
    print("=" * 100)
    print("ATTACK CORRELATION & RAPID RESPONSE PLATFORM v16.2")
    print("=" * 100)

    if DEMO_MODE:
        print("\n[*] DEMO_MODE enabled - synthetic MVP scenario, no Elasticsearch required.")
        hits = generate_demo_scenario()
        print(f"[+] Generated {len(hits)} synthetic events")
    else:
        if not PASSWORD:
            raise RuntimeError(
                "ELASTIC_PASSWORD environment variable is not set."
            )

        try:
            check_elasticsearch()
            print("\n[*] Collecting Sysmon security events...")
            hits = get_security_events()
            print(f"[+] Retrieved {len(hits)} Elasticsearch events")
            if hits:
                sample = normalize_event(hits[0])
                print(
                    "[+] Input schema check: "
                    f"EID={sample.get('event_code') or 'Unknown'}, "
                    f"host={sample.get('host') or 'Unknown'}, "
                    f"process={sample.get('process', {}).get('name') or 'Unknown'}"
                )
        except Exception as exc:  # noqa: BLE001
            print(f"\n[-] Could not complete Elasticsearch collection: {exc}")
            print("[-] Set DEMO_MODE=true to run against the synthetic scenario instead.")
            return

    if not hits:
        print("[-] No relevant Sysmon events found.")
        return

    result = analyze(hits)

    if INCIDENT_API_ENABLED:
        try:
            send_to_incident_api(result)
        except Exception as exc:
            print(f"[-] Incident API ingestion failed: {exc}")
            print("[-] Engine analysis and exports will continue.")

    print_statistics(result)
    print_campaigns(result["campaigns"])

    if EXPORT_JSON:
        export_campaigns_json(result, EXPORT_JSON_PATH)
        export_analyst_view(result, ANALYST_VIEW_DIR)

    print("\n" + "=" * 100)
    print("ANALYSIS COMPLETE")
    print("=" * 100)


if __name__ == "__main__":
    main()
