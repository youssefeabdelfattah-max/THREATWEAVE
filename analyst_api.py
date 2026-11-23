"""
Analyst API - backend layer for the Attack Correlation & Rapid Response
Platform's analyst-facing presentation layer (spec sections 1-13).

Reads ONLY from the on-demand analyst_view/ directory produced by
attack_correlation_engine_v16_2.export_analyst_view() - never loads
campaign_results.json, and never loads more than one story's detail
file per request. The small index files (campaigns, stories listing,
IOC index, statistics) are loaded once at startup since they are
deliberately kept lean; individual story detail files are read from
disk on demand, with a small LRU cache so re-expanding the same story
in the UI doesn't re-hit the disk every time.

Run:
    ANALYST_VIEW_DIR=analyst_view uvicorn analyst_api:app --reload

Then, for example:
    GET /campaigns
    GET /campaigns/{campaign_id}
    GET /campaigns/{campaign_id}/active
    GET /campaigns/{campaign_id}/response
    GET /stories/{story_id}
    GET /stories/{story_id}/events
    GET /iocs
    GET /iocs/{ioc_type}
    GET /statistics
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

ANALYST_VIEW_DIR = os.getenv("ANALYST_VIEW_DIR", "analyst_view")

app = FastAPI(
    title="Attack Correlation Platform - Analyst API",
    description=(
        "Read-only, on-demand access to campaign/story/event/IOC data. "
        "Advisory only - no endpoint here executes any response action."
    ),
    version="16.2",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ============================================================
# INDEX LOADING  (small files, loaded once; never the per-story files)
# ============================================================

_state: Dict[str, Any] = {
    "campaigns": [],
    "campaigns_by_id": {},
    "stories_index": [],
    "stories_by_campaign": {},
    "iocs": {},
    "statistics": {},
}


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_indices() -> None:
    """Loads the small index files only. Called once at startup, and
    callable again (e.g. from tests) to pick up a freshly re-exported
    analyst_view/ directory."""
    campaigns_path = os.path.join(ANALYST_VIEW_DIR, "campaigns_index.json")
    stories_path = os.path.join(ANALYST_VIEW_DIR, "stories_index.json")
    iocs_path = os.path.join(ANALYST_VIEW_DIR, "iocs_index.json")
    stats_path = os.path.join(ANALYST_VIEW_DIR, "statistics.json")

    if not os.path.exists(campaigns_path):
        raise RuntimeError(
            f"{campaigns_path} not found. Run the engine with EXPORT_JSON=true "
            f"first (it calls export_analyst_view() automatically)."
        )

    campaigns = _read_json(campaigns_path)
    stories_index = _read_json(stories_path)

    stories_by_campaign: Dict[str, List[Dict[str, Any]]] = {}
    for story in stories_index:
        stories_by_campaign.setdefault(story.get("campaign_id"), []).append(story)

    _state["campaigns"] = campaigns
    _state["campaigns_by_id"] = {c["campaign_id"]: c for c in campaigns}
    _state["stories_index"] = stories_index
    _state["stories_by_campaign"] = stories_by_campaign
    _state["iocs"] = _read_json(iocs_path) if os.path.exists(iocs_path) else {}
    _state["statistics"] = _read_json(stats_path) if os.path.exists(stats_path) else {}

    read_story_detail.cache_clear()


@app.on_event("startup")
def _startup() -> None:
    load_indices()


@lru_cache(maxsize=256)
def read_story_detail(story_id: str) -> Optional[Dict[str, Any]]:
    """On-demand, cached read of exactly one story file. This is the
    only place a story's full event list is ever loaded into memory."""
    path = os.path.join(ANALYST_VIEW_DIR, "stories", f"{story_id}.json")

    if not os.path.exists(path):
        return None

    return _read_json(path)


# ============================================================
# CAMPAIGNS  (spec section 1, 2, 10, 11)
# ============================================================

@app.get("/campaigns")
def list_campaigns() -> List[Dict[str, Any]]:
    """Primary campaign view - what/how dangerous/active/why, for every
    campaign. No story or event bodies here (spec section 1)."""
    return _state["campaigns"]


@app.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str) -> Dict[str, Any]:
    """Campaign summary plus the lightweight story listing for its
    'More / Details' section (spec section 2). Story EVENT detail is
    still one level further - GET /stories/{story_id}."""
    campaign = _state["campaigns_by_id"].get(campaign_id)

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    return {
        **campaign,
        "stories": _state["stories_by_campaign"].get(campaign_id, []),
    }


@app.get("/campaigns/{campaign_id}/stories")
def get_campaign_stories(campaign_id: str) -> List[Dict[str, Any]]:
    """Just the story listing for one campaign (spec section 2)."""
    if campaign_id not in _state["campaigns_by_id"]:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    return _state["stories_by_campaign"].get(campaign_id, [])


@app.get("/campaigns/{campaign_id}/active")
def get_active_attack_view(campaign_id: str) -> Dict[str, Any]:
    """Active-attack view (spec section 10). 404s if the campaign isn't
    currently flagged active - this endpoint does not change or
    re-derive detect_active_attack()'s decision, only presents it."""
    campaign = _state["campaigns_by_id"].get(campaign_id)

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    if not campaign.get("active_attack"):
        raise HTTPException(
            status_code=404,
            detail=f"Campaign {campaign_id} is not currently flagged as an active attack",
        )

    stories = _state["stories_by_campaign"].get(campaign_id, [])
    latest_activity = max(
        (s.get("end_time") for s in stories if s.get("end_time")),
        default=None,
    )

    return {
        "campaign_id": campaign_id,
        "active_score": campaign.get("active_score"),
        "risk_score": campaign.get("risk_score"),
        "confidence": campaign.get("confidence"),
        "progression": campaign.get("progression"),
        "reasons": campaign.get("reasons"),
        "affected_hosts": campaign.get("affected_hosts", []),
        "affected_users": campaign.get("affected_users", []),
        "latest_activity": latest_activity,
    }


@app.get("/campaigns/{campaign_id}/response")
def get_response_view(campaign_id: str) -> Dict[str, Any]:
    """Response/decision-support view (spec section 11). Advisory only -
    simulation_only is always true; this endpoint never triggers any
    real action."""
    campaign = _state["campaigns_by_id"].get(campaign_id)

    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    response = campaign.get("response", {})

    return {
        "campaign_id": campaign_id,
        "response_urgency": response.get("response_urgency"),
        "action": response.get("action"),
        "approval_required": response.get("approval_required"),
        "simulation_only": response.get("simulation_only", True),
        "recommendations": response.get("recommendations", []),
        "affected_hosts": campaign.get("affected_hosts", []),
        "affected_users": campaign.get("affected_users", []),
    }


# ============================================================
# STORIES  (spec section 3, 4, 6, 7, 8, 9)
# ============================================================

@app.get("/stories/{story_id}")
def get_story(story_id: str) -> Dict[str, Any]:
    """Full story detail: events, process chain, IOCs, relationships,
    MITRE, progression (spec section 3). Reads exactly one file."""
    detail = read_story_detail(story_id)

    if not detail:
        raise HTTPException(status_code=404, detail=f"Story {story_id} not found")

    return detail


@app.get("/stories/{story_id}/events")
def get_story_events(story_id: str) -> List[Dict[str, Any]]:
    """Just the curated events for one story (spec section 4)."""
    detail = read_story_detail(story_id)

    if not detail:
        raise HTTPException(status_code=404, detail=f"Story {story_id} not found")

    return detail.get("events", [])


@app.get("/stories/{story_id}/process-chain")
def get_story_process_chain(story_id: str) -> List[Dict[str, Any]]:
    """Ordered process chain for the arrow-diagram view (spec section 6)."""
    detail = read_story_detail(story_id)

    if not detail:
        raise HTTPException(status_code=404, detail=f"Story {story_id} not found")

    return detail.get("process_chain", [])


# ============================================================
# IOCS  (spec section 5)
# ============================================================

@app.get("/iocs")
def list_iocs() -> Dict[str, List[Dict[str, Any]]]:
    """All IOCs, grouped by type, each with the stories/events it was
    observed in (spec section 5)."""
    return _state["iocs"]


@app.get("/iocs/{ioc_type}")
def list_iocs_by_type(ioc_type: str) -> List[Dict[str, Any]]:
    if ioc_type not in _state["iocs"]:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown IOC type '{ioc_type}'. Expected one of: {list(_state['iocs'].keys())}",
        )

    return _state["iocs"][ioc_type]


# ============================================================
# MISC
# ============================================================

@app.get("/statistics")
def get_statistics() -> Dict[str, Any]:
    return _state["statistics"]


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "analyst_view_dir": ANALYST_VIEW_DIR,
        "campaigns_loaded": len(_state["campaigns"]),
        "stories_indexed": len(_state["stories_index"]),
    }


@app.post("/admin/reload")
def reload_indices() -> Dict[str, Any]:
    """Re-reads the small index files (e.g. after a new engine run).
    Does not touch any story detail files until they're requested."""
    load_indices()
    return {"reloaded": True, "campaigns_loaded": len(_state["campaigns"])}
