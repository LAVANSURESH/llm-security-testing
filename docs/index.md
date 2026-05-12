# LLM Security Testing

**OWASP LLM Top 10 automated security testing for AI applications.**

A comprehensive security testing framework for LLM-powered applications,
focused on prompt injection, output validation, and the OWASP LLM Top 10. It
ships with a CLI for automation, an enterprise-style web dashboard for
reviewing and triggering scans, and a documented JSON report format suitable
for CI integration.

## Why this framework?

Traditional web-security tools don't cover LLM-specific risk:

- ❌ Burp Suite doesn't test prompt injections
- ❌ OWASP ZAP doesn't validate AI hallucinations
- ❌ Postman can't detect PII leakage in LLM outputs

This framework fills that gap.

## Highlights

- **OWASP LLM Top 10 coverage** with extensible test suites
- **Validating-model architecture** — a second LLM judges the first model's output, far more accurate than regex
- **Persistent run history** — every scan (CLI or web) is saved to `reports/runs/` and surfaced on the dashboard
- **Enterprise web dashboard** with KPI cards, trend charts, run detail drill-down, and one-click scan launch
- **No build step on the frontend** — Jinja templates + Chart.js via CDN, ships with the Python package

## Where to go next

- [Architecture](architecture.md) — the dual-LLM judge pattern and the new CLI ↔ store ↔ dashboard data flow
- [Usage (CLI)](usage.md) — run scans from the terminal
- [Dashboard](dashboard.md) — start the UI and tour each page
- [OWASP Coverage](owasp-coverage.md) — current implementation status per category
- [API Reference](api-reference.md) — HTTP endpoints and report JSON shape
