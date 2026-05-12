"""JSON API endpoints consumed by the dashboard's JS layer."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core import report_store

from . import run_service

router = APIRouter()


class StartRunRequest(BaseModel):
    model: str = Field(..., description="LLM model name, e.g. gpt-4 or claude-3-opus")
    provider: str = Field("openai", description="openai or anthropic")
    suite: str = Field("prompt-injection", description="Test suite to run")
    use_validator: bool = Field(True, description="Enable LLM-as-judge validator")
    api_key: Optional[str] = Field(None, description="Override API key for this run")


@router.get("/runs")
def list_runs() -> dict:
    return {"runs": report_store.list_runs()}


@router.get("/runs/{run_id}")
def get_run(run_id: str) -> dict:
    try:
        return report_store.load_run(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/runs", status_code=202)
def start_run(payload: StartRunRequest) -> dict:
    run_id = run_service.start_run(
        model=payload.model,
        provider=payload.provider,
        suite=payload.suite,
        use_validator=payload.use_validator,
        api_key=payload.api_key,
    )
    return {"run_id": run_id, "status": "running"}


@router.get("/runs/{run_id}/status")
def run_status(run_id: str) -> dict:
    status = run_service.get_status(run_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Unknown run id")
    payload = {"run_id": run_id, "status": status}
    if status == "failed":
        failure = report_store.load_failure(run_id)
        if failure:
            payload["error"] = failure.get("error")
    return payload
