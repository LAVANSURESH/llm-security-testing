"""FastAPI application factory for the LLM Security Testing dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(WEB_DIR / "templates"))


def create_app() -> FastAPI:
    app = FastAPI(
        title="LLM Security Testing",
        description="Enterprise dashboard for OWASP LLM Top 10 security scans.",
        version="0.2.0",
    )

    app.mount(
        "/static",
        StaticFiles(directory=str(WEB_DIR / "static")),
        name="static",
    )

    from . import api, routes

    app.include_router(routes.router)
    app.include_router(api.router, prefix="/api")

    return app
