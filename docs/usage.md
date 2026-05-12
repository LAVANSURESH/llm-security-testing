# Usage (CLI)

The CLI is the original entry point and remains the recommended way to
integrate with CI. Every CLI run is also written to `reports/runs/` so it
appears immediately on the [dashboard](dashboard.md).

## Install

```bash
git clone https://github.com/lavansuresh/llm-security-testing.git
cd llm-security-testing
pip install -r requirements.txt
```

## Configure

```bash
# .env (or export in your shell)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
DEFAULT_MODEL=gpt-4
```

## Run a scan

=== "Prompt injection"

    ```bash
    python run_security_tests.py --model gpt-4 --test-suite prompt-injection
    ```

=== "PII leakage"

    ```bash
    python run_security_tests.py --model gpt-4 --test-suite pii-leakage
    ```

=== "OWASP Top 10"

    ```bash
    python run_security_tests.py --model gpt-4 --test-suite owasp-top10
    ```

The run will print a `Run ID` and a path under `reports/runs/`. Open the
dashboard (`python -m web.server`) to inspect the result with full per-test
detail.

## Output formats

```bash
# JSON dump alongside the dashboard record
python run_security_tests.py --model gpt-4 --test-suite owasp-top10 \
  --report json --output security_report.json

# Stand-alone HTML report
python run_security_tests.py --model gpt-4 --test-suite owasp-top10 \
  --report html --output security_report.html
```

## CI example

```yaml
# .github/workflows/llm-security.yml
name: LLM Security Tests
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          pip install -r requirements.txt
          python run_security_tests.py \
            --model gpt-4 \
            --test-suite owasp-top10 \
            --report json \
            --output results.json
      - uses: actions/upload-artifact@v4
        with:
          name: llm-security-report
          path: |
            results.json
            reports/runs/
```
