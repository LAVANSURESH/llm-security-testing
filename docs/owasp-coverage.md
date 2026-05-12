# OWASP LLM Top 10 Coverage

| ID    | Category                              | Status        | Implemented in                                  |
|-------|---------------------------------------|---------------|-------------------------------------------------|
| LLM01 | Prompt Injection                      | ✅ Available  | `core/injection_tester.py`                      |
| LLM02 | Insecure Output Handling              | 🟡 Planned    | —                                               |
| LLM03 | Training Data Poisoning               | 🟡 Planned    | —                                               |
| LLM04 | Model Denial of Service               | 🟡 Planned    | —                                               |
| LLM05 | Supply Chain Vulnerabilities          | 🟡 Planned    | —                                               |
| LLM06 | Sensitive Information Disclosure      | ✅ Available  | `core/pii_scanner.py`, `core/output_validator.py` |
| LLM07 | Insecure Plugin Design                | 🟡 Planned    | —                                               |
| LLM08 | Excessive Agency                      | 🟡 Planned    | —                                               |
| LLM09 | Overreliance (Hallucinations)         | 🟢 Partial    | `core/output_validator.py::validate_hallucination` |
| LLM10 | Model Theft                           | 🟡 Planned    | —                                               |

## LLM01 — Prompt Injection

Three sub-tests run today:

- **Direct injection** — 10+ payloads attempting to override the system prompt
- **Jailbreak attempts** — DAN, Developer Mode, "grandma exploit"
- **System prompt extraction** — 7 techniques to elicit the original system prompt

Each attempt is judged by an independent validator model (see
[Architecture](architecture.md)).

## LLM06 — Sensitive Information Disclosure

`PIIScanner` runs regex sweeps for OpenAI / Anthropic API keys, generic API
keys, emails, phone numbers, SSNs, credit cards, IPs, and AWS / GitHub tokens.
The validator model adds a semantic pass for cases regex would miss (e.g.,
keys split across lines).

## Adding a new category

See [Contributing](contributing.md#adding-a-new-test-category).
