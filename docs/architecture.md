# Architecture

The framework is built around two ideas: a **validating-model** pattern for
high-accuracy verdicts, and a **single on-disk report store** that both the
CLI and the web dashboard share.

## Component overview

```mermaid
flowchart LR
  CLI[CLI<br/>run_security_tests.py] -- writes JSON --> Store[(reports/runs/*.json)]
  Web[FastAPI app · web/] -- reads --> Store
  Web -- POST /api/runs --> Service[run_service<br/>ThreadPoolExecutor]
  Service -- runs --> CLI
  Browser[Browser<br/>Jinja + Chart.js] <-- HTML/JSON --> Web
```

Everything the dashboard shows lives in `reports/runs/<run_id>.json`. There is
no database. CLI runs and dashboard-triggered runs are interchangeable.

## Validating-model pattern

Each test sends a malicious prompt to the **primary** model under test, then
asks an independent **validator** model whether the attack succeeded.

```
┌─────────────────────────────────────────────────────────────┐
│                    TEST ORCHESTRATOR                         │
└────────────┬────────────────────────────────────────────────┘
             ▼
        Attack phase                            Validation phase
   ┌────────────────────┐   response       ┌────────────────────┐
   │ Primary LLM        │ ───────────────▶ │ Validator LLM      │
   │ (under test)       │                  │ (judge)            │
   └────────────────────┘                  └─────────┬──────────┘
                                                     │
                                                     ▼
                                             {verdict, confidence,
                                              reasoning}
                                                     │
                                                     ▼
                                           Persisted in run JSON
```

### Why a second model instead of regex?

| Approach        | Pros                                   | Cons                                            |
|-----------------|----------------------------------------|-------------------------------------------------|
| Regex / keyword | Cheap, deterministic                   | Brittle; misses semantic variations; false positives on benign text |
| LLM-as-judge    | Semantic, context-aware, explainable   | Costs an extra API call; depends on judge quality |

The framework defaults to the LLM judge but keeps the heuristic fallback so
tests still produce a verdict when the validator is disabled.

## Run lifecycle

```mermaid
sequenceDiagram
  participant U as User
  participant W as Web (FastAPI)
  participant S as run_service
  participant T as LLMSecurityTester
  participant D as reports/runs

  U->>W: POST /api/runs {model, suite, ...}
  W->>S: start_run(...)
  S-->>W: run_id (status=running)
  W-->>U: 202 {run_id}
  S->>T: tester.run()
  T->>D: save_run(results)
  S-->>S: status=completed
  U->>W: GET /api/runs/{id}/status (poll)
  W-->>U: {status: completed}
  U->>W: GET /runs/{id}
  W-->>U: HTML detail page
```

If `tester.run()` raises, `run_service` writes `reports/failed/<run_id>.json`
and the status endpoint surfaces the exception.
