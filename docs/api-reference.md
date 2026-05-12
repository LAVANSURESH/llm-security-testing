# API Reference

The web app exposes a JSON API alongside its HTML pages. All endpoints are
unauthenticated and bind to localhost — see the [Dashboard security note](dashboard.md#start-the-server).

## Endpoints

| Method | Path                          | Purpose                                        |
|--------|-------------------------------|------------------------------------------------|
| GET    | `/api/runs`                   | List all persisted runs (summary view)         |
| GET    | `/api/runs/{run_id}`          | Full run JSON                                  |
| POST   | `/api/runs`                   | Start a new scan; returns `{run_id, status}`   |
| GET    | `/api/runs/{run_id}/status`   | `running` / `completed` / `failed`             |

### POST `/api/runs`

```json
{
  "model": "gpt-4",
  "provider": "openai",
  "suite": "prompt-injection",
  "use_validator": true,
  "api_key": null
}
```

`provider` is `openai` or `anthropic`. `suite` is one of `prompt-injection`,
`pii-leakage`, `owasp-top10`, or `full`. If `api_key` is omitted the runner
falls back to `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` from the environment.

Response (`202 Accepted`):

```json
{"run_id": "20260512-153012-a1b2c3", "status": "running"}
```

### GET `/api/runs/{run_id}/status`

```json
{"run_id": "20260512-153012-a1b2c3", "status": "completed"}
```

When `status` is `failed`, an `error` field is included with the exception
message; the full traceback is in `reports/failed/<run_id>.json`.

## Run JSON shape

```json
{
  "metadata": {
    "run_id": "20260512-153012-a1b2c3",
    "timestamp": "2026-05-12T15:30:12.000",
    "model": "gpt-4",
    "test_suite": "owasp-top10"
  },
  "tests": [
    {
      "test_type": "direct_injection",
      "total_payloads": 10,
      "successful_attacks": 2,
      "vulnerability_score": 2.0,
      "details": [
        {
          "attack_type": "direct_injection",
          "payload": "...",
          "response": "...",
          "vulnerable": false,
          "validation_method": "llm_judge",
          "validator_reasoning": "..."
        }
      ]
    }
  ],
  "summary": {
    "total_tests": 13,
    "vulnerable_count": 2,
    "overall_score": 1.0,
    "risk_level": "MEDIUM",
    "categories": [
      {"test_type": "direct_injection", "total": 10, "vulnerable": 2, "score": 2.0}
    ]
  }
}
```

The `summary` block is derived by `core.report_store.compute_summary()`. It is
recomputed and persisted on save, so dashboard reads stay O(1).
