#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
======================================================================
INCIDENT MANAGER v4
======================================================================

What's new in v4 (vs v3) - project integration, no correlation/merge
logic changed
---------------------------------------------------------------------
1. ingest_analysis_result(manager, result) - the primary integration
   point: pass attack_correlation_engine_v16_2.analyze()'s return value
   straight in (same process). No schema adaptation needed - the raw
   story/campaign shape already matches what this manager expects.
2. ingest_from_analyst_view(manager, analyst_view_dir) - a second
   integration path for when the incident manager runs as a separate
   process/service from the engine, reading the exported
   analyst_view/campaigns_index.json + stories/<id>.json files
   (export_analyst_view()'s curated output) instead. A small adapter
   (_adapt_curated_story) normalizes the couple of field names that
   differ between the curated presentation shape and the raw one,
   then reuses the exact same ingestion path as option 1.
3. Incidents now carry three fields straight through from the
   correlation engine's own campaign-level determination (never
   re-derived here): source_campaign_active_attack,
   source_campaign_attack_state, and recommended_response (the
   engine's response_urgency/action/recommendations) - so an analyst
   working an incident sees the engine's read on the situation without
   cross-referencing the campaign separately.
4. orphan_evidence_count tracks how many ingested stories had no
   captured process-creation event (build_orphan_stories() in the
   engine) - lower-confidence attribution worth flagging to the
   analyst, not hidden.
5. incident_api.py (new, separate file): a FastAPI layer over this
   manager, mirroring analyst_api.py's conventions, with the named
   exceptions from v3 mapped to HTTP status codes (400/404/409).

======================================================================
INCIDENT MANAGER v3
======================================================================

Purpose
-------
Operational case-management layer between:

    Attack Stories -> Campaigns -> Incidents

Design
------
    Raw Events
        |
        v
    Correlation Engine
        |
        +--> Attack Stories
        |
        +--> Campaigns
                |
                v
        Incident Manager v3
                |
                +--> Correlation
                +--> Deduplication
                +--> Aggregation
                +--> Priority
                +--> Lifecycle / State Machine
                +--> Analyst Notes
                |
                v
        Incident Store (Elasticsearch, or in-memory for DEMO_MODE)
                |
                v
        Response Engine (future)

Important
---------
This module DOES NOT execute containment or destructive actions.
It is deliberately separated from the response layer.

What's new in v3 (vs v2)
-------------------------
1. Fixed: the "strong evidence" bypass (shared campaign / SHA256 /
   process lineage) was defined but never actually reachable, because
   a raw accumulated-score threshold was checked *before* it. A shared
   file hash 20 minutes apart - explicitly called out in the v2
   comments as decisive on its own - was silently rejected. The merge
   decision is now driven by an explicit `approved` flag that strong
   evidence can set directly, instead of being re-derived from a score
   comparison in two different places (the correlator AND the caller
   used to duplicate this check, which is how it went unnoticed).
2. Fixed: `contextual_path` (host + IP/domain/file_path) additionally
   required the two stories to be within 60 seconds of each other, on
   top of the score threshold - double-penalizing temporal distance.
   That extra gate is removed; the overall correlation window (already
   enforced earlier) is the only temporal bound left.
3. Fixed: not-found detection now catches `elasticsearch.NotFoundError`
   directly instead of string-comparing the exception class name.
4. Fixed: candidate search no longer unconditionally pulls up to 100
   open incidents on every ingest call. Campaign match short-circuits
   host search; host search short-circuits the open-incidents fallback.
5. Fixed: `main()` no longer pings Elasticsearch twice.
6. New: optimistic concurrency control. Incident get/save now carries
   Elasticsearch's seq_no/primary_term, and `ingest_story` retries the
   whole get -> correlate -> merge -> save cycle on a write conflict
   instead of silently losing one side of a concurrent update.
7. New: named exceptions (IncidentValidationError, IncidentNotFoundError,
   IncidentTransitionError, IncidentConflictError) instead of bare
   ValueError/KeyError, so a future FastAPI layer can map them to clean
   HTTP status codes without guessing what a caught ValueError meant.
   They still subclass the original builtins, so existing `except
   ValueError` call sites keep working unchanged.
8. New: DEMO_MODE with an InMemoryIncidentStore implementing the same
   interface as the Elasticsearch-backed store (including its own
   optimistic-concurrency check), so the whole manager - correlation,
   merging, lifecycle, concurrency retries - can be exercised and
   demoed with zero external dependencies.
9. New: a companion test suite (test_incident_manager.py) that locks
   in both original safety guarantees AND the two fixed bugs, plus a
   concurrency-conflict regression test.

Expected input
--------------
Attack Story dictionaries produced by the correlation engine.

    manager.ingest_story(story, campaign=None)
    manager.ingest_stories(stories, campaigns)

The Story/Campaign schema is intentionally tolerant so it can work
with v12/v13/v14/v15-style correlation output.

Environment
-----------
ELASTIC_URL=https://localhost:9200
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=...
INCIDENT_INDEX=security-incidents-v2
VERIFY_CERTS=false
CA_CERTS=/path/to/ca.crt

Optional:
INCIDENT_CORRELATION_WINDOW=1800
INCIDENT_MERGE_THRESHOLD=50
INCIDENT_SEARCH_SIZE=100
DEMO_MODE=true            # use the in-memory store, no ES required
INGEST_RETRY_ATTEMPTS=5   # optimistic-concurrency retry attempts
======================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Iterable, Set, Protocol
from collections import defaultdict
import hashlib
import ipaddress
import json
import os
import re
import time

from elasticsearch import Elasticsearch, NotFoundError, ConflictError


# ======================================================================
# CONFIG
# ======================================================================

ELASTIC_URL = os.getenv("ELASTIC_URL", "https://localhost:9200")
USERNAME = os.getenv("ELASTIC_USERNAME", "elastic")
PASSWORD = os.getenv("ELASTIC_PASSWORD")

INCIDENT_INDEX = os.getenv(
    "INCIDENT_INDEX",
    "security-incidents-v2",
)

INCIDENT_CORRELATION_WINDOW_SECONDS = int(
    os.getenv("INCIDENT_CORRELATION_WINDOW", "1800")
)

INCIDENT_MERGE_THRESHOLD = int(
    os.getenv("INCIDENT_MERGE_THRESHOLD", "50")
)

INCIDENT_SEARCH_SIZE = min(
    int(os.getenv("INCIDENT_SEARCH_SIZE", "100")),
    500,
)

VERIFY_CERTS = (
    os.getenv("VERIFY_CERTS", "false").lower() == "true"
)

CA_CERTS = os.getenv("CA_CERTS")

MAX_TIMELINE_ITEMS = int(
    os.getenv("MAX_TIMELINE_ITEMS", "500")
)

MAX_STORIES_PER_INCIDENT = int(
    os.getenv("MAX_STORIES_PER_INCIDENT", "250")
)

MAX_IOCS_PER_TYPE = int(
    os.getenv("MAX_IOCS_PER_TYPE", "500")
)

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

INGEST_RETRY_ATTEMPTS = int(os.getenv("INGEST_RETRY_ATTEMPTS", "5"))
INGEST_RETRY_BACKOFF_SECONDS = float(os.getenv("INGEST_RETRY_BACKOFF_SECONDS", "0.05"))


# ======================================================================
# EXCEPTIONS
# ======================================================================
#
# These still subclass the original builtin exception types, so any
# existing `except ValueError` / `except KeyError` call site keeps
# working unchanged. New callers - in particular a future FastAPI
# layer - can catch the specific type instead and map it to a clean
# HTTP status code (400 / 404 / 409) without having to guess what a
# bare ValueError meant.

class IncidentError(Exception):
    """Base class for all incident-manager errors."""


class IncidentValidationError(IncidentError, ValueError):
    """Input (story/campaign/note) failed validation."""


class IncidentNotFoundError(IncidentError, KeyError):
    """Referenced incident_id does not exist."""


class IncidentTransitionError(IncidentError, ValueError):
    """Requested lifecycle state transition is not allowed."""


class IncidentConflictError(IncidentError):
    """
    A concurrent write changed the incident between read and write, and
    the automatic retry budget (INGEST_RETRY_ATTEMPTS) was exhausted.
    """


# ======================================================================
# INCIDENT STATES
# ======================================================================

INCIDENT_STATES = {
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT",
    "RESOLVED",
    "FALSE_POSITIVE",
    "CLOSED",
}

# Explicit state machine.
#
# REOPENED is intentionally not used as a separate persisted state.
# A future implementation can add it if required.
ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    "NEW": {
        "TRIAGED",
        "FALSE_POSITIVE",
    },
    "TRIAGED": {
        "INVESTIGATING",
        "FALSE_POSITIVE",
    },
    "INVESTIGATING": {
        "CONTAINMENT",
        "RESOLVED",
        "FALSE_POSITIVE",
    },
    "CONTAINMENT": {
        "INVESTIGATING",
        "RESOLVED",
    },
    "RESOLVED": {
        "CLOSED",
    },
    "FALSE_POSITIVE": {
        "CLOSED",
    },
    "CLOSED": set(),
}


# ======================================================================
# CLIENT  (lazy - v2 built this eagerly at import time, which meant the
# module could not even be imported for DEMO_MODE or tests without a
# real ELASTIC_PASSWORD in the environment)
# ======================================================================

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


# ======================================================================
# UTILITIES
# ======================================================================

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_lower(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def parse_timestamp(value: Any) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    if isinstance(value, datetime):
        dt = value
    else:
        try:
            text = str(value).strip()

            if text.endswith("Z"):
                text = text[:-1] + "+00:00"

            dt = datetime.fromisoformat(text)
        except (ValueError, TypeError):
            return datetime.min.replace(tzinfo=timezone.utc)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def delta_seconds(a: Any, b: Any) -> float:
    return abs(
        (
            parse_timestamp(a)
            - parse_timestamp(b)
        ).total_seconds()
    )


def temporal_distance_seconds(
    first_start: Any,
    first_end: Any,
    second_start: Any,
    second_end: Any,
) -> float:
    """
    Correct temporal distance for intervals.

    If intervals overlap, distance is 0.

    Otherwise returns the gap between them.

        A: [10:00, 10:10]
        B: [10:05, 10:20]
             overlap => 0

        A: [10:00, 10:10]
        B: [10:15, 10:20]
             distance => 300 seconds
    """
    a_start = parse_timestamp(first_start)
    a_end = parse_timestamp(first_end or first_start)
    b_start = parse_timestamp(second_start)
    b_end = parse_timestamp(second_end or second_start)

    if a_start == datetime.min.replace(tzinfo=timezone.utc):
        return float("inf")

    if b_start == datetime.min.replace(tzinfo=timezone.utc):
        return float("inf")

    if a_end < a_start:
        a_end = a_start

    if b_end < b_start:
        b_end = b_start

    if a_end >= b_start and b_end >= a_start:
        return 0.0

    if a_end < b_start:
        return (b_start - a_end).total_seconds()

    return (a_start - b_end).total_seconds()


def unique_list(values: Iterable[Any]) -> List[Any]:
    result: List[Any] = []
    seen: Set[str] = set()

    for value in values:
        if isinstance(value, (dict, list, tuple)):
            key = json.dumps(
                value,
                sort_keys=True,
                default=str,
            )
        else:
            key = str(value)

        if key not in seen:
            seen.add(key)
            result.append(value)

    return result


def stable_hash(*parts: Any) -> str:
    raw = "|".join(
        str(part or "")
        for part in parts
    )

    return hashlib.sha1(
        raw.encode("utf-8", errors="ignore")
    ).hexdigest()[:16]


def normalize_path(value: Any) -> str:
    """
    Canonicalize a Windows-ish path without treating it like a generic
    lowercase IOC.
    """
    if value is None:
        return ""

    text = str(value).strip()

    if not text:
        return ""

    text = text.replace("/", "\\")
    text = re.sub(r"\\+", r"\\", text)
    text = re.sub(r"\s+", " ", text)

    return text.lower()


def normalize_domain(value: Any) -> str:
    text = safe_lower(value)

    if not text:
        return ""

    return text.rstrip(".")


def normalize_sha256(value: Any) -> str:
    text = safe_lower(value)

    if not text:
        return ""

    if not re.fullmatch(r"[0-9a-f]{64}", text):
        return text

    return text


def normalize_ip(value: Any) -> str:
    if value is None:
        return ""

    text = str(value).strip()

    if not text:
        return ""

    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


def is_public_ip(value: Any) -> bool:
    ip = normalize_ip(value)

    if not ip:
        return False

    try:
        address = ipaddress.ip_address(ip)

        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
        )
    except ValueError:
        return False


def clamp(value: Any, minimum: int = 0, maximum: int = 100) -> int:
    try:
        number = int(value)
    except (ValueError, TypeError):
        number = minimum

    return max(minimum, min(number, maximum))


def get_nested(source: Dict[str, Any], *keys: str) -> Any:
    current: Any = source

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current


# ======================================================================
# NORMALIZATION
# ======================================================================

def normalize_iocs(raw_iocs: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Normalize IOC containers safely.

    Important: a string is treated as ONE IOC, not as an iterable of
    characters.
    """
    result: Dict[str, List[str]] = {
        "ip": [],
        "domain": [],
        "sha256": [],
        "file_path": [],
    }

    if not isinstance(raw_iocs, dict):
        return result

    for key in result:
        values = raw_iocs.get(key, [])

        if isinstance(values, str):
            values = [values]
        elif isinstance(values, (set, tuple)):
            values = list(values)
        elif not isinstance(values, list):
            values = []

        normalized: List[str] = []

        for value in values:
            if value is None:
                continue

            if key == "ip":
                item = normalize_ip(value)
            elif key == "domain":
                item = normalize_domain(value)
            elif key == "sha256":
                item = normalize_sha256(value)
            elif key == "file_path":
                item = normalize_path(value)
            else:
                item = safe_lower(value)

            if item:
                normalized.append(item)

        result[key] = sorted(set(normalized))[:MAX_IOCS_PER_TYPE]

    return result


def normalize_mitre(raw: Any) -> List[Dict[str, Any]]:
    """Normalize MITRE technique objects while preserving useful metadata."""
    if raw is None:
        return []

    if isinstance(raw, dict):
        raw = [raw]

    if not isinstance(raw, list):
        return []

    result = []

    for item in raw:
        if isinstance(item, str):
            result.append({"technique": item, "name": "", "source": "unknown"})
            continue

        if not isinstance(item, dict):
            continue

        technique = item.get("technique") or item.get("id") or ""

        if not technique:
            continue

        result.append({
            "technique": str(technique),
            "name": item.get("name", ""),
            "process": item.get("process"),
            "source": item.get("source", "unknown"),
        })

    deduped = {}

    for item in result:
        key = (
            item.get("technique"),
            item.get("name"),
            item.get("process"),
            item.get("source"),
        )
        deduped[key] = item

    return list(deduped.values())


def normalize_process_chain(chain: Any) -> List[Dict[str, Any]]:
    if not isinstance(chain, list):
        return []

    result = []

    for process in chain:
        if not isinstance(process, dict):
            continue

        result.append({
            "name": process.get("name"),
            "pid": process.get("pid"),
            "entity_id": process.get("entity_id"),
            "executable": process.get("executable"),
            "command_line": process.get("command_line"),
            "timestamp": process.get("timestamp"),
            "user": process.get("user"),
            "host": process.get("host"),
        })

    return result


def process_identity_from_process(process: Dict[str, Any]) -> str:
    if not isinstance(process, dict):
        return ""

    host = safe_lower(process.get("host"))
    entity_id = process.get("entity_id")

    if entity_id:
        return f"entity:{host}:{entity_id}"

    pid = process.get("pid")
    name = safe_lower(process.get("name"))

    if host and pid is not None and name:
        timestamp = process.get("timestamp")
        bucket = (
            parse_timestamp(timestamp).replace(microsecond=0).isoformat()
            if timestamp else ""
        )
        return f"fallback:{host}:{pid}:{name}:{bucket}"

    return ""


def extract_story_hosts(story: Dict[str, Any]) -> List[str]:
    values = []

    for event in story.get("events", []):
        if isinstance(event, dict):
            host = event.get("host")
            if host:
                values.append(safe_lower(host))

    for process in story.get("process_chain", []):
        if isinstance(process, dict):
            host = process.get("host")
            if host:
                values.append(safe_lower(host))

    return sorted(set(v for v in values if v))


def extract_story_users(story: Dict[str, Any]) -> List[str]:
    values = []

    for event in story.get("events", []):
        if isinstance(event, dict):
            user = event.get("user")
            if user:
                values.append(safe_lower(user))

    for process in story.get("process_chain", []):
        if isinstance(process, dict):
            user = process.get("user")
            if user:
                values.append(safe_lower(user))

    return sorted(set(v for v in values if v))


def extract_story_process_ids(story: Dict[str, Any]) -> List[str]:
    values = []

    for process in story.get("process_chain", []):
        if not isinstance(process, dict):
            continue

        identity = process_identity_from_process(process)

        if identity:
            values.append(identity)

    return sorted(set(values))


def extract_story_event_count(story: Dict[str, Any]) -> int:
    events = story.get("events")

    if isinstance(events, list):
        return len(events)

    return int(story.get("event_count") or 0)


# ======================================================================
# INCIDENT IDENTITY
# ======================================================================

def deterministic_incident_id(
    story: Dict[str, Any],
    campaign: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Incident semantics:

        Campaign exists:  one operational incident per campaign
        No campaign:       story becomes the deterministic incident anchor

    This is intentionally deterministic so repeated ingestion of the same
    correlation result does not create a new incident every execution.
    """
    campaign_id = ""

    if isinstance(campaign, dict):
        campaign_id = campaign.get("campaign_id") or ""

    campaign_id = campaign_id or story.get("campaign_id") or ""

    if campaign_id:
        return "INC-" + stable_hash("incident", campaign_id).upper()

    story_id = story.get("story_id") or ""

    if story_id:
        return "INC-" + stable_hash("incident", story_id).upper()

    return "INC-" + stable_hash(
        "incident",
        story.get("start_time"),
        story.get("end_time"),
        *extract_story_hosts(story),
        *extract_story_process_ids(story),
    ).upper()


# ======================================================================
# INCIDENT PRIORITY
# ======================================================================

def calculate_priority(risk_score: int, confidence: int, severity: str) -> str:
    """
    Priority is derived from BOTH risk and confidence, so
    severity == HIGH never automatically means P2 on its own when
    risk/confidence are weak.
    """
    risk = clamp(risk_score)
    confidence = clamp(confidence)
    normalized_severity = safe_lower(severity).upper()

    if risk >= 85 and confidence >= 70:
        return "P1"

    if risk >= 75 and confidence >= 55:
        return "P2"

    if normalized_severity == "CRITICAL" and confidence >= 50:
        return "P2"

    if risk >= 55 and confidence >= 45:
        return "P3"

    if risk >= 35 or confidence >= 35:
        return "P3"

    return "P4"


def calculate_severity(risk_score: int, confidence: int) -> str:
    risk = clamp(risk_score)
    confidence = clamp(confidence)

    if risk >= 85 and confidence >= 70:
        return "CRITICAL"

    if risk >= 65 or (risk >= 55 and confidence >= 75):
        return "HIGH"

    if risk >= 35:
        return "MEDIUM"

    return "LOW"


# ======================================================================
# STORY -> INCIDENT DOCUMENT
# ======================================================================

def story_to_incident_fragment(
    story: Dict[str, Any],
    campaign: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Convert a correlation-engine story into an incident aggregation fragment."""
    risk = clamp(story.get("risk_score", 0))
    confidence = clamp(story.get("confidence", 0))
    severity = calculate_severity(risk, confidence)

    hosts = extract_story_hosts(story)
    users = extract_story_users(story)
    process_ids = extract_story_process_ids(story)

    mitre = normalize_mitre(story.get("mitre_techniques", []))
    iocs = normalize_iocs(story.get("iocs", {}))

    timeline = []

    for event in story.get("events", []):
        if not isinstance(event, dict):
            continue

        timeline.append({
            "timestamp": event.get("timestamp"),
            "event_code": event.get("event_code"),
            "event_action": event.get("event_action"),
            "host": event.get("host"),
            "user": event.get("user"),
            "process": (
                event.get("process", {})
                if isinstance(event.get("process"), dict) else {}
            ),
            "correlation": (
                event.get("_correlation", {})
                if isinstance(event.get("_correlation"), dict) else {}
            ),
        })

    process_chain = normalize_process_chain(story.get("process_chain", []))

    return {
        "story_id": story.get("story_id"),
        "story_number": story.get("chain_number"),
        "start_time": story.get("start_time"),
        "end_time": story.get("end_time"),
        "event_count": extract_story_event_count(story),
        "risk_score": risk,
        "confidence": confidence,
        "severity": severity,
        "priority": calculate_priority(risk, confidence, severity),
        "hosts": hosts,
        "users": users,
        "process_ids": process_ids,
        "mitre_techniques": mitre,
        "iocs": iocs,
        "timeline": timeline,
        "process_chains": [process_chain] if process_chain else [],
        "reasons": (
            list(story.get("reasons", []))
            if isinstance(story.get("reasons", []), list) else []
        ),
        "campaign_id": (
            campaign.get("campaign_id")
            if isinstance(campaign, dict) else story.get("campaign_id")
        ),
        "is_orphan_story": bool(story.get("orphan", False)),
        # Carried straight through from the correlation engine's own
        # campaign-level determination - this manager never re-derives
        # active_attack or the recommended response, only displays them.
        "source_campaign_active_attack": (
            campaign.get("active_attack") if isinstance(campaign, dict) else None
        ),
        "source_campaign_attack_state": (
            campaign.get("attack_state") if isinstance(campaign, dict) else None
        ),
        "recommended_response": (
            campaign.get("response") if isinstance(campaign, dict) else None
        ),
    }


# ======================================================================
# INCIDENT CORRELATOR
# ======================================================================

@dataclass
class CorrelationResult:
    score: int
    approved: bool
    reasons: List[str]
    strong_evidence: List[str]


class IncidentCorrelator:
    """
    Determines whether a new story belongs to an existing operational
    incident. Correlation is evidence-based - same host/time alone is
    never enough.

    v3: the merge decision is now an explicit `approved` boolean set
    directly by this method, rather than being re-derived from a raw
    score comparison by the caller (see CHANGELOG item 1). Evidence
    types that are decisive on their own (shared campaign, shared file
    hash, shared process lineage) approve a merge regardless of the
    accumulated score - that is the entire point of calling them
    "strong" evidence. Weaker contextual evidence (host + IP/domain/
    file_path) still needs the accumulated score to clear the merge
    threshold, but is no longer additionally required to fall within an
    arbitrary 60-second sub-window on top of that (item 2) - the overall
    correlation window, already enforced below, is the only temporal
    bound.
    """

    def __init__(
        self,
        merge_threshold: int = INCIDENT_MERGE_THRESHOLD,
        correlation_window_seconds: int = INCIDENT_CORRELATION_WINDOW_SECONDS,
    ):
        self.merge_threshold = merge_threshold
        self.window = correlation_window_seconds

    @staticmethod
    def _set_values(incident: Dict[str, Any], field_name: str) -> Set[str]:
        values = incident.get(field_name, [])

        if isinstance(values, str):
            return {values}

        if not isinstance(values, list):
            return set()

        return {str(value) for value in values if value}

    @staticmethod
    def _ioc_overlap(first: Dict[str, Any], second: Dict[str, Any], key: str) -> Set[str]:
        first_values = set(
            first.get("iocs", {}).get(key, [])
            if isinstance(first.get("iocs", {}), dict) else []
        )
        second_values = set(
            second.get("iocs", {}).get(key, [])
            if isinstance(second.get("iocs", {}), dict) else []
        )
        return first_values & second_values

    def correlate(
        self,
        incident: Dict[str, Any],
        story_fragment: Dict[str, Any],
    ) -> CorrelationResult:
        score = 0
        reasons: List[str] = []
        strong_evidence: List[str] = []

        # ---- Temporal gate: the only hard time bound in this method ----
        distance = temporal_distance_seconds(
            incident.get("start_time"),
            incident.get("end_time"),
            story_fragment.get("start_time"),
            story_fragment.get("end_time"),
        )

        if distance > self.window:
            return CorrelationResult(score=0, approved=False, reasons=[], strong_evidence=[])

        if distance == 0:
            score += 15
            reasons.append("Temporal overlap")
        elif distance <= 60:
            score += 15
            reasons.append("Within 60 seconds")
        else:
            score += 8
            reasons.append("Within incident correlation window")

        # ---- Campaign: strongest operational signal ----
        incident_campaign = incident.get("campaign_id")
        story_campaign = story_fragment.get("campaign_id")

        if incident_campaign and story_campaign and incident_campaign == story_campaign:
            score += 40
            reasons.append("Same campaign")
            strong_evidence.append("campaign")

        # ---- Host ----
        incident_hosts = self._set_values(incident, "hosts")
        story_hosts = set(story_fragment.get("hosts", []))

        if incident_hosts & story_hosts:
            score += 25
            reasons.append("Shared host")
            strong_evidence.append("host")

        # ---- IOC evidence: SHA256 > IP/domain > path ----
        if self._ioc_overlap(incident, story_fragment, "sha256"):
            score += 20
            reasons.append("Shared SHA256 IOC")
            strong_evidence.append("sha256")

        if self._ioc_overlap(incident, story_fragment, "ip"):
            score += 15
            reasons.append("Shared IP IOC")
            strong_evidence.append("ip")

        if self._ioc_overlap(incident, story_fragment, "domain"):
            score += 15
            reasons.append("Shared domain IOC")
            strong_evidence.append("domain")

        if self._ioc_overlap(incident, story_fragment, "file_path"):
            score += 7
            reasons.append("Shared file path")
            strong_evidence.append("file_path")

        # ---- Process lineage ----
        incident_processes = self._set_values(incident, "process_ids")
        story_processes = set(story_fragment.get("process_ids", []))

        if incident_processes & story_processes:
            score += 20
            reasons.append("Shared process lineage")
            strong_evidence.append("process")

        # ---- User ----
        incident_users = self._set_values(incident, "users")
        story_users = set(story_fragment.get("users", []))

        if incident_users & story_users:
            score += 10
            reasons.append("Shared user")

        # ---- MITRE ----
        incident_mitre = {
            item.get("technique")
            for item in incident.get("mitre_techniques", [])
            if isinstance(item, dict) and item.get("technique")
        }
        story_mitre = {
            item.get("technique")
            for item in story_fragment.get("mitre_techniques", [])
            if isinstance(item, dict) and item.get("technique")
        }

        if incident_mitre & story_mitre:
            score += 10
            reasons.append("Shared MITRE technique")

        score = min(score, 100)
        evidence_set = set(strong_evidence)

        # Decisive on their own: a shared campaign, file hash, or process
        # lineage does not need any other corroboration, only the
        # temporal window gate already enforced above.
        strong_path = bool({"campaign", "sha256", "process"} & evidence_set)

        # Contextual: host plus at least one IOC-level signal. Needs the
        # accumulated score to clear the threshold, but - unlike v2 - is
        # not additionally capped at a 60-second sub-window.
        contextual_path = (
            "host" in evidence_set
            and bool({"ip", "domain", "file_path"} & evidence_set)
        )

        if strong_path:
            return CorrelationResult(
                score=score,
                approved=True,
                reasons=unique_list(reasons + ["Decisive evidence: merge approved independent of score"]),
                strong_evidence=unique_list(strong_evidence),
            )

        if contextual_path and score >= self.merge_threshold:
            return CorrelationResult(
                score=score,
                approved=True,
                reasons=unique_list(reasons),
                strong_evidence=unique_list(strong_evidence),
            )

        return CorrelationResult(
            score=score,
            approved=False,
            reasons=unique_list(reasons + ["Merge blocked: insufficient strong evidence"]),
            strong_evidence=unique_list(strong_evidence),
        )


# ======================================================================
# INCIDENT STORE  (Elasticsearch-backed)
# ======================================================================

class IncidentStore:
    """
    Elasticsearch persistence layer.

    v3: get() also returns the document's seq_no/primary_term (via a
    small internal cache keyed by incident_id), and save()/update() use
    them for optimistic concurrency control - if the document changed
    since it was read, the write is rejected with IncidentConflictError
    instead of silently overwriting a concurrent update.
    """

    def __init__(self, client: Elasticsearch, index: str = INCIDENT_INDEX):
        self.es = client
        self.index = index

    def ensure_index(self) -> None:
        if self.es.indices.exists(index=self.index):
            return

        mappings = {
            "properties": {
                "incident_id": {"type": "keyword"},
                "title": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "status": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "priority": {"type": "keyword"},
                "risk_score": {"type": "integer"},
                "confidence": {"type": "integer"},
                "campaign_id": {"type": "keyword"},
                "story_ids": {"type": "keyword"},
                "hosts": {"type": "keyword"},
                "users": {"type": "keyword"},
                "process_ids": {"type": "keyword"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"},
                "start_time": {"type": "date"},
                "end_time": {"type": "date"},
            }
        }

        self.es.indices.create(index=self.index, mappings=mappings)

    def get(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Returns the incident with its optimistic-concurrency version
        embedded as the private "_optimistic_version" key. This
        travels with THIS specific fetched copy (not a store-wide
        cache keyed only by incident_id) so that two concurrent get()
        calls each hold their own version and a stale save() is
        rejected no matter how many other reads/writes happened in
        between - a shared cache keyed by ID alone would get clobbered
        by whichever save() happened most recently, silently defeating
        the whole point of optimistic locking.
        """
        try:
            response = self.es.get(index=self.index, id=incident_id)
        except NotFoundError:
            return None

        source = response.get("_source")

        if not isinstance(source, dict):
            return None

        result = dict(source)
        seq_no = response.get("_seq_no")
        primary_term = response.get("_primary_term")

        if seq_no is not None and primary_term is not None:
            result["_optimistic_version"] = [seq_no, primary_term]

        return result

    def save(self, incident: Dict[str, Any], create_only: bool = False) -> Dict[str, Any]:
        incident = dict(incident)
        version = incident.pop("_optimistic_version", None)
        incident_id = incident["incident_id"]

        index_kwargs: Dict[str, Any] = {
            "index": self.index,
            "id": incident_id,
            "document": incident,
            "refresh": "wait_for",
        }

        if create_only:
            index_kwargs["op_type"] = "create"
        elif version is not None:
            index_kwargs["if_seq_no"] = version[0]
            index_kwargs["if_primary_term"] = version[1]

        try:
            response = self.es.index(**index_kwargs)
        except ConflictError as exc:
            raise IncidentConflictError(
                f"Incident {incident_id} was modified concurrently."
            ) from exc

        result = dict(incident)
        seq_no = response.get("_seq_no")
        primary_term = response.get("_primary_term")

        if seq_no is not None and primary_term is not None:
            result["_optimistic_version"] = [seq_no, primary_term]

        return result

    def search_open(self, size: int = INCIDENT_SEARCH_SIZE) -> List[Dict[str, Any]]:
        response = self.es.search(
            index=self.index,
            size=size,
            query={
                "terms": {
                    "status": ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT"]
                }
            },
            sort=[{"updated_at": {"order": "desc"}}],
        )
        return self._hits_to_sources(response)

    def search_by_campaign(self, campaign_id: str) -> List[Dict[str, Any]]:
        if not campaign_id:
            return []

        response = self.es.search(
            index=self.index,
            size=INCIDENT_SEARCH_SIZE,
            query={"term": {"campaign_id": campaign_id}},
        )
        return self._hits_to_sources(response)

    def search_by_host(self, host: str) -> List[Dict[str, Any]]:
        if not host:
            return []

        response = self.es.search(
            index=self.index,
            size=INCIDENT_SEARCH_SIZE,
            query={"term": {"hosts": safe_lower(host)}},
        )
        return self._hits_to_sources(response)

    def update(self, incident_id: str, incident: Dict[str, Any]) -> Dict[str, Any]:
        return self.save(incident)

    @staticmethod
    def _hits_to_sources(response: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = response.get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits if isinstance(hit.get("_source"), dict)]


# ======================================================================
# INCIDENT STORE  (in-memory, for DEMO_MODE / tests - zero external deps)
# ======================================================================

class InMemoryIncidentStore:
    """
    Same interface as IncidentStore, backed by a plain dict. Implements
    the same optimistic-concurrency contract (a version counter instead
    of seq_no/primary_term) so DEMO_MODE and the test suite can exercise
    the *exact* retry/conflict behaviour of ingest_story() without a
    live Elasticsearch instance.
    """

    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}
        self._versions: Dict[str, int] = {}

    def ensure_index(self) -> None:
        return None

    def get(self, incident_id: str) -> Optional[Dict[str, Any]]:
        doc = self._data.get(incident_id)

        if doc is None:
            return None

        result = json.loads(json.dumps(doc, default=str))
        result["_optimistic_version"] = self._versions.get(incident_id, 0)
        return result

    def save(self, incident: Dict[str, Any], create_only: bool = False) -> Dict[str, Any]:
        incident = dict(incident)
        seen_version = incident.pop("_optimistic_version", None)
        incident_id = incident["incident_id"]
        current_version = self._versions.get(incident_id, 0)

        if create_only:
            if incident_id in self._data:
                raise IncidentConflictError(f"Incident {incident_id} already exists.")
        else:
            if incident_id in self._data and seen_version != current_version:
                raise IncidentConflictError(
                    f"Incident {incident_id} was modified concurrently."
                )

        self._data[incident_id] = json.loads(json.dumps(incident, default=str))
        new_version = current_version + 1
        self._versions[incident_id] = new_version

        result = dict(incident)
        result["_optimistic_version"] = new_version
        return result

    def search_open(self, size: int = INCIDENT_SEARCH_SIZE) -> List[Dict[str, Any]]:
        open_statuses = {"NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT"}
        results = [d for d in self._data.values() if d.get("status") in open_statuses]
        results.sort(key=lambda d: d.get("updated_at") or "", reverse=True)
        return [json.loads(json.dumps(d, default=str)) for d in results[:size]]

    def search_by_campaign(self, campaign_id: str) -> List[Dict[str, Any]]:
        if not campaign_id:
            return []
        return [
            json.loads(json.dumps(d, default=str))
            for d in self._data.values()
            if d.get("campaign_id") == campaign_id
        ]

    def search_by_host(self, host: str) -> List[Dict[str, Any]]:
        if not host:
            return []
        needle = safe_lower(host)
        return [
            json.loads(json.dumps(d, default=str))
            for d in self._data.values()
            if needle in (d.get("hosts") or [])
        ]

    def update(self, incident_id: str, incident: Dict[str, Any]) -> Dict[str, Any]:
        return self.save(incident)


# ======================================================================
# INCIDENT AGGREGATOR
# ======================================================================

class IncidentAggregator:
    """Merges story evidence into an incident without losing existing data."""

    @staticmethod
    def merge_strings(first: Iterable[Any], second: Iterable[Any], limit: Optional[int] = None) -> List[str]:
        values = []

        for value in list(first or []) + list(second or []):
            if value is None:
                continue
            text = str(value)
            if text:
                values.append(text)

        result = sorted(set(values))
        return result[:limit] if limit else result

    @staticmethod
    def merge_iocs(incident_iocs: Dict[str, Any], story_iocs: Dict[str, Any]) -> Dict[str, List[str]]:
        result = normalize_iocs(incident_iocs)
        incoming = normalize_iocs(story_iocs)

        for key in result:
            result[key] = sorted(set(result[key] + incoming[key]))[:MAX_IOCS_PER_TYPE]

        return result

    @staticmethod
    def merge_mitre(first: List[Dict[str, Any]], second: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return normalize_mitre(list(first or []) + list(second or []))

    @staticmethod
    def merge_timeline(first: List[Dict[str, Any]], second: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        combined = [item for item in list(first or []) + list(second or []) if isinstance(item, dict)]

        deduped = {}
        for item in combined:
            key = stable_hash(
                item.get("timestamp"),
                item.get("event_code"),
                item.get("host"),
                json.dumps(item.get("process", {}), sort_keys=True, default=str),
            )
            deduped[key] = item

        result = list(deduped.values())
        result.sort(key=lambda item: parse_timestamp(item.get("timestamp")))
        return result[-MAX_TIMELINE_ITEMS:]

    @staticmethod
    def merge_process_chains(first: List[Any], second: List[Any]) -> List[Any]:
        combined = list(first or []) + list(second or [])
        deduped = {}

        for chain in combined:
            if not isinstance(chain, list):
                continue

            identities = [
                process_identity_from_process(process)
                for process in chain
                if isinstance(process, dict) and process_identity_from_process(process)
            ]

            key = tuple(identities)
            if key:
                deduped[key] = chain

        return list(deduped.values())[-MAX_STORIES_PER_INCIDENT:]

    @staticmethod
    def merge_reasons(first: List[Any], second: List[Any]) -> List[str]:
        values = [str(reason) for reason in list(first or []) + list(second or []) if reason]
        return unique_list(values)

    def merge(
        self,
        incident: Dict[str, Any],
        fragment: Dict[str, Any],
        correlation: CorrelationResult,
    ) -> Dict[str, Any]:
        now = now_utc()

        old_risk = clamp(incident.get("risk_score", 0))
        old_confidence = clamp(incident.get("confidence", 0))
        new_risk = clamp(fragment.get("risk_score", 0))
        new_confidence = clamp(fragment.get("confidence", 0))

        story_count_before = len(incident.get("story_ids", []))

        merged_risk = min(
            100,
            max(old_risk, new_risk) + min(max(story_count_before, 0) * 2, 10),
        )

        merged_confidence = min(
            100,
            max(old_confidence, new_confidence) + (5 if story_count_before > 0 else 0),
        )

        severity = calculate_severity(merged_risk, merged_confidence)
        priority = calculate_priority(merged_risk, merged_confidence, severity)

        incident["risk_score"] = merged_risk
        incident["confidence"] = merged_confidence
        incident["severity"] = severity
        incident["priority"] = priority

        incident["story_ids"] = self.merge_strings(
            incident.get("story_ids", []), [fragment.get("story_id")], MAX_STORIES_PER_INCIDENT,
        )

        story_number = fragment.get("story_number")
        incident["story_numbers"] = sorted(
            set([*(incident.get("story_numbers", []) or []), story_number]) - {None}
        )

        incident["hosts"] = self.merge_strings(incident.get("hosts", []), fragment.get("hosts", []))
        incident["users"] = self.merge_strings(incident.get("users", []), fragment.get("users", []))
        incident["process_ids"] = self.merge_strings(
            incident.get("process_ids", []), fragment.get("process_ids", [])
        )
        incident["iocs"] = self.merge_iocs(incident.get("iocs", {}), fragment.get("iocs", {}))
        incident["mitre_techniques"] = self.merge_mitre(
            incident.get("mitre_techniques", []), fragment.get("mitre_techniques", [])
        )
        incident["timeline"] = self.merge_timeline(incident.get("timeline", []), fragment.get("timeline", []))
        incident["process_chains"] = self.merge_process_chains(
            incident.get("process_chains", []), fragment.get("process_chains", [])
        )
        incident["reasons"] = self.merge_reasons(incident.get("reasons", []), fragment.get("reasons", []))

        starts = [v for v in (incident.get("start_time"), fragment.get("start_time")) if v]
        ends = [v for v in (incident.get("end_time"), fragment.get("end_time")) if v]

        if starts:
            incident["start_time"] = min(starts, key=parse_timestamp)
        if ends:
            incident["end_time"] = max(ends, key=parse_timestamp)

        campaign_id = fragment.get("campaign_id") or incident.get("campaign_id")
        if campaign_id:
            incident["campaign_id"] = campaign_id

        if fragment.get("is_orphan_story"):
            incident["orphan_evidence_count"] = incident.get("orphan_evidence_count", 0) + 1

        # These describe the SOURCE campaign as the correlation engine
        # currently sees it, not something this manager computes -
        # always refreshed to the latest ingested story's campaign view
        # since a later ingest reflects more current engine state.
        if fragment.get("source_campaign_active_attack") is not None:
            incident["source_campaign_active_attack"] = fragment["source_campaign_active_attack"]
        if fragment.get("source_campaign_attack_state") is not None:
            incident["source_campaign_attack_state"] = fragment["source_campaign_attack_state"]
        if fragment.get("recommended_response") is not None:
            incident["recommended_response"] = fragment["recommended_response"]

        incident["title"] = build_incident_title(incident)

        incident["correlation_history"] = (
            incident.get("correlation_history", [])
            + [{
                "timestamp": now,
                "story_id": fragment.get("story_id"),
                "score": correlation.score,
                "approved": correlation.approved,
                "reasons": correlation.reasons,
                "strong_evidence": correlation.strong_evidence,
            }]
        )[-MAX_TIMELINE_ITEMS:]

        incident["updated_at"] = now

        return incident


# ======================================================================
# TITLE
# ======================================================================

def build_incident_title(incident: Dict[str, Any]) -> str:
    severity = incident.get("severity", "LOW")
    hosts = incident.get("hosts", [])
    host = hosts[0] if isinstance(hosts, list) and hosts else "unknown-host"

    mitre = incident.get("mitre_techniques", [])
    names = [str(item.get("name")) for item in mitre if isinstance(item, dict) and item.get("name")]

    preferred = [
        "PowerShell", "Ingress Tool Transfer", "Rundll32", "Regsvr32",
        "Mshta", "Scheduled Task/Job", "Modify Registry",
        "Windows Management Instrumentation",
    ]

    behavior = next((c for c in preferred if c in names), "")
    if not behavior and names:
        behavior = names[0]

    if behavior:
        return f"{severity} - Suspicious {behavior} Activity on {host}"

    return f"{severity} - Suspicious Security Activity on {host}"


# ======================================================================
# INCIDENT MANAGER
# ======================================================================

class IncidentManagerV2:  # name kept for backward compatibility with v2 callers
    """
    Main orchestration layer.

    v3: accepts an explicit `store` (any object implementing the
    IncidentStore/InMemoryIncidentStore interface) for dependency
    injection - used by DEMO_MODE and by tests. ingest_story() now
    retries the whole get -> correlate -> merge -> save cycle on a
    concurrent-write conflict instead of leaving the caller to handle
    IncidentConflictError itself.
    """

    def __init__(
        self,
        client: Optional[Elasticsearch] = None,
        index: str = INCIDENT_INDEX,
        merge_threshold: int = INCIDENT_MERGE_THRESHOLD,
        store: Optional[Any] = None,
        retry_attempts: int = INGEST_RETRY_ATTEMPTS,
    ):
        if store is not None:
            self.store = store
        elif DEMO_MODE:
            self.store = InMemoryIncidentStore()
        else:
            self.store = IncidentStore(client or get_client(), index)

        self.correlator = IncidentCorrelator(merge_threshold=merge_threshold)
        self.aggregator = IncidentAggregator()
        self.retry_attempts = max(1, retry_attempts)

    def ensure_ready(self, verbose: bool = False) -> None:
        if isinstance(self.store, IncidentStore):
            if not self.store.es.ping():
                raise RuntimeError("Elasticsearch ping failed.")

            if verbose:
                info = self.store.es.info()
                version = get_nested(info, "version", "number") or "unknown"
                print(f"[+] Elasticsearch connected (version {version})")

        self.store.ensure_index()

    # ------------------------------------------------------------------
    # VALIDATION
    # ------------------------------------------------------------------

    @staticmethod
    def validate_story(story: Dict[str, Any]) -> None:
        if not isinstance(story, dict):
            raise IncidentValidationError("Story must be a dictionary.")

        if not story.get("story_id"):
            raise IncidentValidationError("Story is missing story_id.")

        risk = story.get("risk_score", 0)
        confidence = story.get("confidence", 0)

        if not isinstance(risk, (int, float)):
            raise IncidentValidationError("risk_score must be numeric.")

        if not isinstance(confidence, (int, float)):
            raise IncidentValidationError("confidence must be numeric.")

        if not 0 <= risk <= 100:
            raise IncidentValidationError("risk_score must be between 0 and 100.")

        if not 0 <= confidence <= 100:
            raise IncidentValidationError("confidence must be between 0 and 100.")

    # ------------------------------------------------------------------
    # CANDIDATES
    # ------------------------------------------------------------------

    def _candidate_incidents(self, fragment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Staged candidate discovery (v3): a campaign match is definitive
        (see IncidentCorrelator.strong_path) so there is no reason to
        also fetch host matches or the open-incidents fallback once one
        is found. Host matches short-circuit the open-incidents
        fallback the same way. v2 always fetched all three, which meant
        every single ingest call pulled up to 100 open incidents and
        scored every one of them even when the answer was already
        obvious from the campaign match.
        """
        campaign_id = fragment.get("campaign_id")

        if campaign_id:
            candidates = {
                incident["incident_id"]: incident
                for incident in self.store.search_by_campaign(campaign_id)
            }
            if candidates:
                return list(candidates.values())

        candidates = {}
        for host in fragment.get("hosts", []):
            for incident in self.store.search_by_host(host):
                candidates[incident["incident_id"]] = incident

        if candidates:
            return list(candidates.values())

        return self.store.search_open()

    # ------------------------------------------------------------------
    # CREATE
    # ------------------------------------------------------------------

    def _create_incident(self, fragment: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
        timestamp = now_utc()

        risk = clamp(fragment.get("risk_score", 0))
        confidence = clamp(fragment.get("confidence", 0))
        severity = calculate_severity(risk, confidence)
        priority = calculate_priority(risk, confidence, severity)

        incident = {
            "incident_id": incident_id,
            "title": "",
            "status": "NEW",
            "severity": severity,
            "priority": priority,
            "risk_score": risk,
            "confidence": confidence,
            "campaign_id": fragment.get("campaign_id"),
            "story_ids": [],
            "story_numbers": [],
            "hosts": [],
            "users": [],
            "process_ids": [],
            "mitre_techniques": [],
            "iocs": {"ip": [], "domain": [], "sha256": [], "file_path": []},
            "process_chains": [],
            "timeline": [],
            "reasons": [],
            "orphan_evidence_count": 0,
            "source_campaign_active_attack": None,
            "source_campaign_attack_state": None,
            "recommended_response": None,
            "analyst_notes": [],
            "status_history": [{
                "timestamp": timestamp, "from": None, "to": "NEW",
                "reason": "Incident created", "author": "system",
            }],
            "correlation_history": [],
            "created_at": timestamp,
            "updated_at": timestamp,
            "start_time": fragment.get("start_time"),
            "end_time": fragment.get("end_time"),
        }

        incident = self.aggregator.merge(
            incident, fragment,
            CorrelationResult(
                score=100, approved=True,
                reasons=["Initial story created incident"],
                strong_evidence=["initial_story"],
            ),
        )

        incident["title"] = build_incident_title(incident)
        return incident

    # ------------------------------------------------------------------
    # INGEST
    # ------------------------------------------------------------------

    def _ingest_attempt(
        self,
        story: Dict[str, Any],
        campaign: Optional[Dict[str, Any]],
        deterministic_id: str,
    ) -> Dict[str, Any]:
        """One get -> correlate -> merge -> save cycle. May raise
        IncidentConflictError, which ingest_story() retries."""

        fragment = story_to_incident_fragment(story, campaign)

        existing_exact = self.store.get(deterministic_id)

        if existing_exact:
            correlation = CorrelationResult(
                score=100, approved=True,
                reasons=["Deterministic incident identity matched"],
                strong_evidence=["deterministic_id"],
            )
            merged = self.aggregator.merge(existing_exact, fragment, correlation)
            return self.store.update(deterministic_id, merged)

        candidates = self._candidate_incidents(fragment)

        best_incident = None
        best_result: Optional[CorrelationResult] = None

        for incident in candidates:
            if incident.get("status") in {"CLOSED", "FALSE_POSITIVE"}:
                continue

            result = self.correlator.correlate(incident, fragment)

            if not result.approved:
                continue

            if best_result is None or result.score > best_result.score:
                best_incident = incident
                best_result = result

        if best_incident is not None and best_result is not None:
            # Re-fetch by ID right before merging so we hold this
            # candidate's current seq_no/primary_term, not the possibly
            # stale copy gathered during candidate search.
            fresh = self.store.get(best_incident["incident_id"]) or best_incident
            merged = self.aggregator.merge(fresh, fragment, best_result)
            return self.store.update(best_incident["incident_id"], merged)

        incident = self._create_incident(fragment, deterministic_id)
        return self.store.save(incident, create_only=True)

    def ingest_story(
        self,
        story: Dict[str, Any],
        campaign: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.validate_story(story)

        deterministic_id = deterministic_incident_id(story, campaign)

        last_error: Optional[IncidentConflictError] = None

        for attempt in range(1, self.retry_attempts + 1):
            try:
                return self._ingest_attempt(story, campaign, deterministic_id)
            except IncidentConflictError as exc:
                last_error = exc
                if attempt < self.retry_attempts:
                    time.sleep(INGEST_RETRY_BACKOFF_SECONDS * attempt)

        raise IncidentConflictError(
            f"Could not ingest story {story.get('story_id')} after "
            f"{self.retry_attempts} attempts due to concurrent writes."
        ) from last_error

    def ingest_stories(
        self,
        stories: List[Dict[str, Any]],
        campaigns: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Ingest all stories, automatically associating campaign metadata."""
        campaigns = campaigns or []

        story_to_campaign: Dict[str, Dict[str, Any]] = {}

        for campaign in campaigns:
            if not isinstance(campaign, dict):
                continue

            campaign_id = campaign.get("campaign_id")
            if not campaign_id:
                continue

            for story_id in campaign.get("story_ids", []):
                story_to_campaign[str(story_id)] = campaign

        incidents = []

        for story in stories:
            campaign = story_to_campaign.get(str(story.get("story_id")))
            incidents.append(self.ingest_story(story, campaign))

        return incidents

    # ------------------------------------------------------------------
    # GET / SEARCH
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self.store.get(incident_id)

    def search_open_incidents(self) -> List[Dict[str, Any]]:
        return self.store.search_open()

    # ------------------------------------------------------------------
    # LIFECYCLE
    # ------------------------------------------------------------------

    def change_status(
        self,
        incident_id: str,
        new_status: str,
        reason: str = "",
        author: str = "analyst",
    ) -> Dict[str, Any]:
        new_status = str(new_status).upper().strip()

        if new_status not in INCIDENT_STATES:
            raise IncidentValidationError(f"Invalid incident state: {new_status}")

        incident = self.store.get(incident_id)

        if not incident:
            raise IncidentNotFoundError(f"Incident not found: {incident_id}")

        current_status = str(incident.get("status", "NEW")).upper()

        if current_status == new_status:
            return incident

        allowed = ALLOWED_TRANSITIONS.get(current_status, set())

        if new_status not in allowed:
            raise IncidentTransitionError(
                f"Invalid state transition: {current_status} -> {new_status}"
            )

        timestamp = now_utc()
        incident["status"] = new_status

        history = incident.get("status_history", [])
        if not isinstance(history, list):
            history = []

        history.append({
            "timestamp": timestamp, "from": current_status, "to": new_status,
            "reason": reason, "author": author,
        })

        incident["status_history"] = history[-MAX_TIMELINE_ITEMS:]
        incident["updated_at"] = timestamp

        return self.store.update(incident_id, incident)

    # ------------------------------------------------------------------
    # ANALYST NOTES
    # ------------------------------------------------------------------

    def add_note(self, incident_id: str, note: str, author: str = "analyst") -> Dict[str, Any]:
        if not isinstance(note, str):
            raise IncidentValidationError("note must be a string.")

        note = note.strip()
        if not note:
            raise IncidentValidationError("note cannot be empty.")

        incident = self.store.get(incident_id)
        if not incident:
            raise IncidentNotFoundError(f"Incident not found: {incident_id}")

        notes = incident.get("analyst_notes", [])
        if not isinstance(notes, list):
            notes = []

        notes.append({"timestamp": now_utc(), "note": note, "author": author})
        incident["analyst_notes"] = notes[-MAX_TIMELINE_ITEMS:]
        incident["updated_at"] = now_utc()

        return self.store.update(incident_id, incident)

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(incident: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "incident_id": incident.get("incident_id"),
            "title": incident.get("title"),
            "status": incident.get("status"),
            "severity": incident.get("severity"),
            "priority": incident.get("priority"),
            "risk_score": incident.get("risk_score"),
            "confidence": incident.get("confidence"),
            "campaign_id": incident.get("campaign_id"),
            "source_campaign_active_attack": incident.get("source_campaign_active_attack"),
            "source_campaign_attack_state": incident.get("source_campaign_attack_state"),
            "recommended_response": incident.get("recommended_response"),
            "orphan_evidence_count": incident.get("orphan_evidence_count", 0),
            "stories": len(incident.get("story_ids", [])),
            "hosts": incident.get("hosts", []),
            "users": incident.get("users", []),
            "mitre": [
                item.get("technique")
                for item in incident.get("mitre_techniques", [])
                if isinstance(item, dict)
            ],
            "ioc_counts": {
                key: len(values)
                for key, values in (incident.get("iocs", {}) or {}).items()
            },
            "event_count": len(incident.get("timeline", [])),
            "created_at": incident.get("created_at"),
            "updated_at": incident.get("updated_at"),
        }


# Alias so v3 can be imported under its own name too.
IncidentManagerV3 = IncidentManagerV2
IncidentManagerV4 = IncidentManagerV2


# ======================================================================
# PROJECT INTEGRATION  (v4: wires this module to
# attack_correlation_engine_v16_2.py's actual output)
# ======================================================================
#
# Two supported ways to feed the correlation engine's output into this
# manager, matching the two ways the rest of the project already
# produces/serves data:
#
#   1. ingest_analysis_result() - same process, straight from
#      analyze()'s return value (result["stories"], result["campaigns"]).
#      This is the simplest and most robust path: no serialization, no
#      schema adaptation, because it's the same Python objects the
#      engine itself just built. Use this when the engine and the
#      incident manager run in the same script/pipeline step.
#
#   2. ingest_from_analyst_view() - reads the exported analyst_view/
#      directory (campaigns_index.json + stories/<id>.json) that
#      export_analyst_view() writes. Use this when the incident manager
#      runs as a separate process/service from the engine, consuming
#      its output the same way analyst_api.py does. The story files
#      there are the CURATED, analyst-facing shape (build_story_detail /
#      build_event_view), not the engine's raw internal story shape, so
#      a small adapter re-normalizes the couple of fields that differ
#      (story_number -> chain_number, and the curated "correlation" key
#      back to the "_correlation" key story_to_incident_fragment reads)
#      before handing it to the exact same aggregation/correlation code
#      path as option 1. No incident-manager logic is duplicated between
#      the two paths.

def ingest_analysis_result(
    manager: "IncidentManagerV2",
    result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Primary integration path. `result` is exactly what
    attack_correlation_engine_v16_2.analyze(hits) returns (or anything
    with the same "stories" / "campaigns" keys) - pass it straight in,
    same process, right after analyze() runs and before or alongside
    export_campaigns_json()/export_analyst_view().
    """
    stories = result.get("stories", [])
    campaigns = result.get("campaigns", [])
    return manager.ingest_stories(stories, campaigns)


def _adapt_curated_story(curated: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes the couple of field-name differences between a curated
    stories/<story_id>.json document (build_story_detail() /
    build_event_view() in the engine's presentation layer) and the raw
    story shape story_to_incident_fragment() expects, so the exact same
    fragment-building code works for both. Everything else already
    matches field-for-field (risk_score, confidence, mitre_techniques,
    iocs, reasons, start_time, end_time, process_chain with
    host/user/pid/entity_id, and event host/user) - this only touches
    what's genuinely different.
    """
    story = dict(curated)
    story["chain_number"] = curated.get("story_number")

    adapted_events = []
    for event in curated.get("events", []):
        event = dict(event)
        # Curated events carry a cleaned "correlation" key (no leading
        # underscore, and dropped entirely when empty); the fragment
        # builder looks for "_correlation" specifically.
        if "correlation" in event:
            event["_correlation"] = event.pop("correlation")
        adapted_events.append(event)

    story["events"] = adapted_events
    return story


def ingest_from_analyst_view(
    manager: "IncidentManagerV2",
    analyst_view_dir: str,
) -> List[Dict[str, Any]]:
    """
    Decoupled integration path: reads campaigns_index.json and each
    referenced stories/<story_id>.json from an analyst_view/ directory
    already written by export_analyst_view(), and ingests them through
    the same manager.ingest_story() used by the in-process path.
    """
    campaigns_path = os.path.join(analyst_view_dir, "campaigns_index.json")

    with open(campaigns_path, "r", encoding="utf-8") as handle:
        campaigns = json.load(handle)

    incidents = []

    for campaign in campaigns:
        for story_id in campaign.get("story_ids", []):
            story_path = os.path.join(analyst_view_dir, "stories", f"{story_id}.json")

            if not os.path.exists(story_path):
                continue

            with open(story_path, "r", encoding="utf-8") as handle:
                curated_story = json.load(handle)

            adapted = _adapt_curated_story(curated_story)
            incidents.append(manager.ingest_story(adapted, campaign))

    return incidents


# ======================================================================
# CLI / DEMO
# ======================================================================

def check_elasticsearch() -> Dict[str, Any]:
    print("[*] Checking Elasticsearch...")
    client = get_client()

    if not client.ping():
        raise RuntimeError("Elasticsearch ping failed.")

    info = client.info()
    version = get_nested(info, "version", "number") or "unknown"
    print(f"[+] Elasticsearch connected (version {version})")
    return info


def demo_story(
    story_id: str,
    campaign_id: Optional[str],
    host: str,
    start_time: str,
    risk: int,
    confidence: int,
    technique: str,
    technique_name: str,
    sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Small synthetic story generator for testing the manager. Not a detector."""
    event = {
        "timestamp": start_time,
        "event_code": "1",
        "host": host,
        "user": "victim",
        "process": {
            "name": "powershell.exe",
            "pid": 4000,
            "entity_id": f"demo-{story_id}",
            "command_line": "powershell.exe -enc <demo>",
        },
        "_correlation": {"score": 95, "reasons": ["Same process identity"]},
    }

    return {
        "chain_number": 1,
        "story_id": story_id,
        "start_time": start_time,
        "end_time": start_time,
        "event_count": 1,
        "risk_score": risk,
        "confidence": confidence,
        "severity": calculate_severity(risk, confidence),
        "mitre_techniques": [{
            "technique": technique, "name": technique_name,
            "process": "powershell.exe", "source": "demo",
        }],
        "reasons": ["Synthetic demo story"],
        "events": [event],
        "process_chain": [{
            "name": "powershell.exe", "pid": 4000, "entity_id": f"demo-{story_id}",
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -enc <demo>",
            "timestamp": start_time, "user": "victim", "host": host,
        }],
        "iocs": {
            "ip": [], "domain": [],
            "sha256": [sha256] if sha256 else [],
            "file_path": [],
        },
        "campaign_id": campaign_id,
    }


def run_demo(manager: Optional["IncidentManagerV2"] = None) -> None:
    """Run the synthetic persistence/correlation demo."""
    if manager is None:
        manager = IncidentManagerV2()
        manager.ensure_ready(verbose=not DEMO_MODE)

    campaign_a = {"campaign_id": "CAMP-DEMO-001", "story_ids": ["STORY-DEMO-001", "STORY-DEMO-002"]}
    campaign_b = {"campaign_id": "CAMP-DEMO-002", "story_ids": ["STORY-DEMO-003"]}

    story_1 = demo_story("STORY-DEMO-001", "CAMP-DEMO-001", "demo-host-01", "2026-08-19T01:00:00+00:00", 70, 75, "T1059.001", "PowerShell", "a" * 64)
    story_2 = demo_story("STORY-DEMO-002", "CAMP-DEMO-001", "demo-host-01", "2026-08-19T01:05:00+00:00", 82, 85, "T1105", "Ingress Tool Transfer", "a" * 64)
    story_3 = demo_story("STORY-DEMO-003", "CAMP-DEMO-002", "demo-host-99", "2026-08-19T01:07:00+00:00", 80, 85, "T1059.003", "Windows Command Shell", "b" * 64)

    print()
    print("=" * 100)
    print("INCIDENT MANAGER v4 DEMO")
    print("=" * 100)

    for story, campaign in ((story_1, campaign_a), (story_2, campaign_a), (story_3, campaign_b)):
        incident = manager.ingest_story(story, campaign)
        print()
        print(f"[+] Story {story['story_id']} -> {incident['incident_id']}")
        print(json.dumps(manager.summarize(incident), indent=2, default=str))

    print()
    print("=" * 100)
    print("OPEN INCIDENTS")
    print("=" * 100)
    for incident in manager.search_open_incidents():
        print(json.dumps(manager.summarize(incident), indent=2, default=str))


def main() -> None:
    """CLI entry point. Existing integration functions remain unchanged."""
    import argparse

    parser = argparse.ArgumentParser(description="Incident Manager v4")
    parser.add_argument("--demo", action="store_true", help="Run offline in-memory demo")
    parser.add_argument("--check", action="store_true", help="Check Elasticsearch connectivity")
    args = parser.parse_args()

    print()
    print("=" * 100)
    print("INCIDENT MANAGER v4")
    print("=" * 100)
    print()

    # Handle --demo BEFORE creating the normal manager. This guarantees that
    # demo mode never initializes Elasticsearch.
    if args.demo:
        print("[*] --demo enabled - using in-memory store, no Elasticsearch required.")
        manager = IncidentManagerV2(store=InMemoryIncidentStore())
        manager.ensure_ready(verbose=False)
        print("[+] In-memory incident store ready.")
        print("[*] Running demo...")
        run_demo(manager)
        return

    if args.check:
        print("[*] Checking Elasticsearch connection...")
        check_elasticsearch()
        return

    manager = IncidentManagerV2()

    if DEMO_MODE:
        print("[*] DEMO_MODE enabled - using in-memory store, no Elasticsearch required.")
        manager.ensure_ready(verbose=False)
    else:
        print("[*] Ensuring Elasticsearch connection and incident index...")
        manager.ensure_ready(verbose=True)
        print(f"[+] Incident index ready: {INCIDENT_INDEX}")

    print()
    print("[+] Incident Manager v4 is ready.")
    print()
    print("Use this module from the correlation engine with:")
    print()
    print("    manager.ingest_story(story, campaign)")
    print("or:")
    print("    manager.ingest_stories(stories, campaigns)")
    print()
    print("For a synthetic persistence/correlation test:")
    print()
    print("    python incident_manager_v4.py --demo")
    print("    DEMO_MODE=true python incident_manager_v4.py --demo   (no ES needed)")
    print()

if __name__ == "__main__":
    main()
