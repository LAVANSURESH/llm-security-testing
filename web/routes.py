"""HTML routes (Jinja-rendered) for the dashboard."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from core import report_store

from .app import TEMPLATES

router = APIRouter()


def _ctx(active: str, **extra) -> dict:
    base = {
        "active": active,
        "default_model": os.getenv("DEFAULT_MODEL", "gpt-4"),
        "app_version": "0.2.0",
    }
    base.update(extra)
    return base


def _render(request: Request, template: str, active: str, **extra) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(request, template, _ctx(active, **extra))


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    runs = report_store.list_runs()
    recent = runs[:10]

    seven_days_ago = datetime.now() - timedelta(days=7)
    critical = 0
    for r in runs:
        ts = r.get("timestamp") or ""
        try:
            when = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if when >= seven_days_ago:
            critical += r.get("vulnerable_count") or 0

    avg_score = (
        round(sum((r.get("overall_score") or 0) for r in runs) / len(runs), 2) if runs else 0.0
    )

    trend_points = list(reversed([
        {
            "run_id": r["run_id"],
            "timestamp": r.get("timestamp"),
            "score": r.get("overall_score") or 0,
        }
        for r in runs[:20]
    ]))

    return _render(
        request,
        "dashboard.html",
        active="dashboard",
        kpis={
            "total_runs": len(runs),
            "avg_score": avg_score,
            "critical_7d": critical,
            "last_status": (runs[0].get("status") if runs else "—"),
        },
        recent_runs=recent,
        trend=trend_points,
    )


@router.get("/runs", response_class=HTMLResponse)
def runs_index(request: Request) -> HTMLResponse:
    runs = report_store.list_runs()
    return _render(request, "runs.html", active="runs", runs=runs)


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str) -> HTMLResponse:
    try:
        run = report_store.load_run(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    summary = run.get("summary") or report_store.compute_summary(run)
    return _render(request, "run_detail.html", active="runs", run=run, summary=summary)


@router.get("/scan", response_class=HTMLResponse)
def scan_page(request: Request) -> HTMLResponse:
    return _render(request, "scan.html", active="scan")


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> HTMLResponse:
    env_state = {
        "OPENAI_API_KEY": bool(os.getenv("OPENAI_API_KEY")),
        "ANTHROPIC_API_KEY": bool(os.getenv("ANTHROPIC_API_KEY")),
        "TARGET_API_URL": os.getenv("TARGET_API_URL") or "",
        "DEFAULT_MODEL": os.getenv("DEFAULT_MODEL", "gpt-4"),
    }
    return _render(request, "settings.html", active="settings", env_state=env_state)


@router.get("/docs-redirect")
def docs_redirect() -> RedirectResponse:
    return RedirectResponse(url="https://github.com/lavansuresh/llm-security-testing#documentation", status_code=302)
