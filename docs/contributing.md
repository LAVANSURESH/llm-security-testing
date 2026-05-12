# Contributing

Contributions welcome. Areas that need help:

- Additional attack payload patterns
- Hallucination detection improvements
- Support for more LLM providers (Cohere, Hugging Face)
- Non-English attack libraries

## Development setup

```bash
git clone https://github.com/lavansuresh/llm-security-testing.git
cd llm-security-testing
pip install -r requirements.txt
pip install -r requirements-docs.txt   # for the docs site
```

Run the CLI, the web dashboard, and the docs site side-by-side:

```bash
# Terminal 1 — CLI smoke test
python run_security_tests.py --model gpt-4 --test-suite prompt-injection

# Terminal 2 — dashboard
python -m web.server

# Terminal 3 — docs site
mkdocs serve
```

## Adding a new test category

The flow lives in `core/` and `run_security_tests.py`:

1. Add a new tester module in `core/`, modeled after
   `core/injection_tester.py`. The tester needs a `test_*` method that returns
   a dict shaped like the existing test results:
   ```python
   {
     "test_type": "my_category",
     "total_payloads": int,
     "successful_attacks": int,
     "vulnerability_score": float,   # 0-10, lower is better
     "details": [...],
   }
   ```
2. In `run_security_tests.py`, add a `_test_my_category` method that calls
   into your new tester and appends to `self.results["tests"]`.
3. Wire it into the suite dispatch (`_test_owasp_full`, `_test_full_suite`)
   and add it to the `--test-suite` argparse choices.
4. Update `core/report_store.compute_summary()` if your test reports
   differently shaped totals.
5. Update `docs/owasp-coverage.md` to flip the status row.

The dashboard picks up new categories automatically — `run_detail.html`
iterates over `run.tests` and renders whatever's there.

## Style

- Python: follow the surrounding style; type hints are encouraged but not
  required.
- Templates: prefer macros in `web/templates/_macros.html` over ad-hoc HTML.
- CSS: extend `web/static/css/app.css`; reuse the existing variables.
