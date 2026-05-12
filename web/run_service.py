"""Background runner that bridges the web API to the existing CLI tester."""

from __future__ import annotations

import os
import threading
import traceback
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional

from core import report_store


_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="llmsec-run")
_STATUS: Dict[str, str] = {}
_STATUS_LOCK = threading.Lock()


def _set_status(run_id: str, status: str) -> None:
    with _STATUS_LOCK:
        _STATUS[run_id] = status


def get_status(run_id: str) -> Optional[str]:
    """Return current in-memory status, or None if unknown (e.g. after restart)."""
    with _STATUS_LOCK:
        if run_id in _STATUS:
            return _STATUS[run_id]
    # Fall back to disk: completed runs live in reports/runs, failed in reports/failed.
    try:
        report_store.load_run(run_id)
        return "completed"
    except FileNotFoundError:
        pass
    if report_store.load_failure(run_id) is not None:
        return "failed"
    return None


def _execute(run_id: str, args: Namespace) -> None:
    # Imported lazily so the web layer can boot even if API keys are missing.
    from run_security_tests import LLMSecurityTester

    try:
        tester = LLMSecurityTester(args)
        tester.run_id = run_id
        tester.results["metadata"]["run_id"] = run_id
        tester.run()
        _set_status(run_id, "completed")
    except Exception as exc:  # noqa: BLE001 — surface every failure to the UI
        report_store.save_failure(
            run_id,
            {
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "args": vars(args),
            },
        )
        _set_status(run_id, "failed")


def start_run(
    *,
    model: str,
    provider: str,
    suite: str,
    use_validator: bool = True,
    api_key: Optional[str] = None,
) -> str:
    """Submit a new scan; returns the assigned run_id immediately."""
    run_id = report_store.new_run_id()
    resolved_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    args = Namespace(
        model=model,
        api_key=resolved_key,
        test_suite=suite,
        report="json",
        output=None,
        provider=provider,
        use_validator=use_validator,
    )
    _set_status(run_id, "running")
    _EXECUTOR.submit(_execute, run_id, args)
    return run_id
