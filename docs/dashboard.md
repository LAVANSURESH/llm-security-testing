# Dashboard

The dashboard is a FastAPI + Jinja application served from the `web/` package.
No Node, no build step — Chart.js is loaded from a CDN.

## Start the server

```bash
pip install -r requirements.txt
python -m web.server
# → http://127.0.0.1:8000
```

Optional flags:

```bash
python -m web.server --host 127.0.0.1 --port 8000 --reload
```

!!! warning "Security note"
    The dashboard ships **without authentication**. It is intended for
    localhost-only use during development and security engagements. Never
    expose the port to the public internet. If you need shared access, put
    it behind your own reverse proxy with auth.

## Pages

### Dashboard (`/`)

- **KPI cards** — total runs, average vulnerability score, vulnerable
  findings in the last 7 days, last-run status
- **Score trend** — line chart of vulnerability score across the last 20 runs
- **Recent runs** — clickable table linking to per-run detail

### Runs (`/runs`)

Full filterable table of every persisted run. The search box does a client-side
substring match against model, suite, and run id.

### Run detail (`/runs/{run_id}`)

- Header with model, suite, timestamp, and overall score badge
- Summary block (total tests, vulnerable count, risk level, categories)
- One collapsible card per OWASP category, with payload / response / verdict /
  validator reasoning for each attempt
- Raw JSON at the bottom for debugging

### New Scan (`/scan`)

A form that POSTs to `/api/runs`. The page polls `/api/runs/{id}/status` every
3 seconds and redirects to the run detail page on completion.

### Settings (`/settings`)

Read-only view of which environment variables are populated. Secret values are
never displayed — only their presence.

## Where data lives

```
reports/
├── runs/      # one JSON per completed run (source of truth)
└── failed/    # one JSON per crashed run, surfaced via /api/runs/{id}/status
```

CLI runs and dashboard-triggered runs share this directory. Delete a file to
remove it from the dashboard.
