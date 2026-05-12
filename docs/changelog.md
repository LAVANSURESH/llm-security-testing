# Changelog

## 0.2.0 — Enterprise dashboard and docs site

- **New web dashboard** (`web/`) with sidebar navigation: Dashboard, Runs,
  New Scan, Documentation, Settings
- **Per-run drill-down** with payload/response/verdict/reasoning for every
  attempt
- **In-browser scan launcher** — `POST /api/runs` runs scans on a background
  thread pool with status polling
- **Shared report store** (`core/report_store.py`) — CLI and dashboard both
  write to `reports/runs/<run_id>.json`
- **mkdocs-material docs site** — Overview, Architecture, Usage, Dashboard,
  OWASP Coverage, API Reference, Contributing
- README slimmed to point at the docs site

## 0.1.0 — Initial release

- CLI (`run_security_tests.py`) with `prompt-injection`, `pii-leakage`,
  `owasp-top10`, and `full` suites
- Core modules: `injection_tester`, `output_validator`, `pii_scanner`
- LLM-as-judge validation pattern
