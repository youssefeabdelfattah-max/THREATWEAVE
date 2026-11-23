"""
Incident API - FastAPI layer over incident_manager_v4.IncidentManagerV2.

Mirrors analyst_api.py's conventions (CORS, /health, DEMO_MODE-aware)
so the two backends feel like one project. This is the case-management
side: creating/merging/tracking incidents and their lifecycle. It never
executes a response action - see IncidentManagerV2's own docstring.

DEMO_MODE=true uses the in-memory incident store (no Elasticsearch
required), matching the same env var the correlation engine and
analyst_api.py already use.

Run:
    DEMO_MODE=true uvicorn incident_api:app --reload --port 8001

Then, for example:
    GET  /incidents
    GET  /incidents/{incident_id}
    POST /incidents/{incident_id}/status   {"status": "TRIAGED", "reason": "..."}
    POST /incidents/{incident_id}/notes    {"note": "...", "author": "..."}
    POST /ingest/analysis-result           {"stories": [...], "campaigns": [...]}
    POST /demo/seed                        (DEMO_MODE only) runs the engine's
                                            synthetic scenario and ingests it,
                                            for an end-to-end demo with zero setup.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import incident_manager_v4 as im

app = FastAPI(
    title="Attack Correlation Platform - Incident API",
    description=(
        "Case-management layer: correlates stories/campaigns into "
        "incidents, tracks lifecycle and analyst notes. Advisory only - "
        "no endpoint here executes a response action."
    ),
    version="4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

manager = im.IncidentManagerV2()


@app.on_event("startup")
def _startup() -> None:
    manager.ensure_ready(verbose=True)


# ============================================================
# Named exceptions -> HTTP status codes (this is exactly what
# IncidentValidationError / IncidentNotFoundError / IncidentTransitionError /
# IncidentConflictError were added in v3 for)
# ============================================================

@app.exception_handler(im.IncidentValidationError)
def _handle_validation_error(_request, exc: im.IncidentValidationError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(im.IncidentNotFoundError)
def _handle_not_found_error(_request, exc: im.IncidentNotFoundError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(im.IncidentTransitionError)
def _handle_transition_error(_request, exc: im.IncidentTransitionError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=409, content={"detail": str(exc)})


@app.exception_handler(im.IncidentConflictError)
def _handle_conflict_error(_request, exc: im.IncidentConflictError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=409, content={"detail": str(exc)})


# ============================================================
# Request bodies
# ============================================================

class StatusChangeRequest(BaseModel):
    status: str
    reason: str = ""
    author: str = "analyst"


class NoteRequest(BaseModel):
    note: str
    author: str = "analyst"


class AnalysisResultRequest(BaseModel):
    stories: List[Dict[str, Any]]
    campaigns: List[Dict[str, Any]] = []


# ============================================================
# INCIDENTS
# ============================================================

@app.get("/incidents")
def list_open_incidents() -> List[Dict[str, Any]]:
    return [manager.summarize(i) for i in manager.search_open_incidents()]


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> Dict[str, Any]:
    incident = manager.get_incident(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return incident


@app.get("/incidents/{incident_id}/summary")
def get_incident_summary(incident_id: str) -> Dict[str, Any]:
    incident = manager.get_incident(incident_id)

    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return manager.summarize(incident)


@app.post("/incidents/{incident_id}/status")
def change_status(incident_id: str, body: StatusChangeRequest) -> Dict[str, Any]:
    incident = manager.change_status(incident_id, body.status, body.reason, body.author)
    return manager.summarize(incident)


@app.post("/incidents/{incident_id}/notes")
def add_note(incident_id: str, body: NoteRequest) -> Dict[str, Any]:
    incident = manager.add_note(incident_id, body.note, body.author)
    return manager.summarize(incident)


# ============================================================
# INGEST  (from the correlation engine)
# ============================================================

@app.post("/ingest/story")
def ingest_single_story(
    story: Dict[str, Any],
    campaign: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    incident = manager.ingest_story(story, campaign)
    return manager.summarize(incident)


@app.post("/ingest/analysis-result")
def ingest_analysis_result_endpoint(body: AnalysisResultRequest) -> List[Dict[str, Any]]:
    """
    Accepts the correlation engine's raw analyze() output
    ({"stories": [...], "campaigns": [...]}) - the same shape
    ingest_analysis_result() takes in-process. Use this when the
    engine and this API run as separate processes/services and the
    engine POSTs its result here after each run.
    """
    result = {"stories": body.stories, "campaigns": body.campaigns}
    incidents = im.ingest_analysis_result(manager, result)
    return [manager.summarize(i) for i in incidents]


@app.post("/demo/seed")
def seed_demo_data() -> Dict[str, Any]:
    """
    DEMO_MODE convenience: runs the engine's synthetic MVP scenario and
    ingests it, so the whole pipeline (engine -> incidents) can be
    demoed end-to-end with zero setup. Disabled outside DEMO_MODE to
    avoid accidentally seeding fake data into a real deployment.
    """
    if not im.DEMO_MODE:
        raise HTTPException(
            status_code=403,
            detail="POST /demo/seed is only available with DEMO_MODE=true",
        )

    from collector import elastic_client as engine

    result = engine.analyze(engine.generate_demo_scenario())
    incidents = im.ingest_analysis_result(manager, result)

    return {
        "campaigns_analyzed": len(result["campaigns"]),
        "stories_analyzed": len(result["stories"]),
        "incidents": [manager.summarize(i) for i in incidents],
    }


# ============================================================
# MISC
# ============================================================

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "demo_mode": im.DEMO_MODE,
        "store_type": type(manager.store).__name__,
        "open_incidents": len(manager.search_open_incidents()),
    }
