# LLM Security Testing Framework

**OWASP LLM Top 10 automated security testing for AI applications.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

A security testing framework for LLM-powered applications, focused on prompt
injection, output validation, and the OWASP LLM Top 10. Ships with a CLI for
CI integration **and** an enterprise-style web dashboard for reviewing and
triggering scans.

> **Documentation lives in [`docs/`](./docs/index.md)** — overview, architecture,
> usage, dashboard tour, OWASP coverage, API reference, and contributing guide.
> Render it locally with `mkdocs serve`.

---

## Quick start

```bash
git clone https://github.com/lavansuresh/llm-security-testing.git
cd llm-security-testing
pip install -r requirements.txt

# 1. Configure
cp .env.example .env   # add OPENAI_API_KEY / ANTHROPIC_API_KEY

# 2. Run a scan from the CLI
python run_security_tests.py --model gpt-4 --test-suite prompt-injection

# 3. Open the dashboard (reads every CLI run automatically)
python -m web.server
# → http://127.0.0.1:8000

# 4. (Optional) Browse the full docs site
pip install -r requirements-docs.txt
mkdocs serve
# → http://127.0.0.1:8001
```

## What you get

- **OWASP LLM Top 10 coverage** with extensible test suites — see
  [`docs/owasp-coverage.md`](./docs/owasp-coverage.md)
- **Validating-model architecture** — a second LLM judges the first model's
  output, far more accurate than regex
- **Enterprise web dashboard** with KPI cards, trend charts, run drill-down,
  and one-click scan launch — see [`docs/dashboard.md`](./docs/dashboard.md)
- **Persistent run history** — every scan is saved to `reports/runs/` and
  surfaced on the dashboard (CLI and web runs share the store)
- **CI-friendly JSON output** — see [`docs/api-reference.md`](./docs/api-reference.md)

## Repository layout

```
llm-security-testing/
├── core/
│   ├── injection_tester.py    # LLM01 — prompt injection
│   ├── output_validator.py    # LLM-as-judge validator
│   ├── pii_scanner.py         # LLM06 — PII leakage
│   └── report_store.py        # Shared on-disk run store
│
├── web/                       # FastAPI + Jinja dashboard
│   ├── app.py · routes.py · api.py · run_service.py · server.py
│   ├── templates/             # base, dashboard, runs, run_detail, scan, settings
│   └── static/                # CSS, JS
│
├── docs/                      # mkdocs-material site
├── reports/runs/              # one JSON per completed scan
└── run_security_tests.py      # CLI entry point
```

## Security note

The dashboard ships **without authentication**. It binds to localhost by
default — do not expose it to the public internet. Details in
[`docs/dashboard.md`](./docs/dashboard.md).

---

## Contact

**Lavan Sureshbabu** — QA Engineer | SDET | AI Security Testing

- Email: lavan.sureshbabu26@gmail.com
- LinkedIn: [linkedin.com/in/lavan-s-0811](https://linkedin.com/in/lavan-s-0811)

## License

MIT — see [LICENSE](./LICENSE).

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always
obtain proper authorization before testing any system.
