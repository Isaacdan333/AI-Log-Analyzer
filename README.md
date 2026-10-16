# Cybersecurity Log Analyzer

A deterministic, explainable Python-based log analysis project designed to ingest multiple log sources, normalize them into a common event model, detect suspicious activity, and generate clear incident reports.

The goal is to help analysts review security-relevant behavior without relying on opaque ML or LLM decisions for the core detection pipeline. The first release focuses on rule-based detection, evidence-backed alerts, and clear reporting.

## Project goal

This project is intended to:

- ingest logs from multiple security sources
- normalize them into a shared event format
- detect suspicious patterns such as brute-force activity, privilege escalation, suspicious logins, and port scanning
- produce readable human reports with evidence and recommended actions
- provide a future-ready foundation for JSON output, API integrations, and advanced analytics

## Supported log sources

The initial implementation supports:

- Windows Security Event Log CSV exports
- Firewall logs
- SSH authentication logs
- Web server logs in Apache/Nginx combined format

## Key principles

- Normalize diverse log formats into a common event model
- Keep parsing, detection, and reporting separate
- Make every alert explainable with evidence
- Prefer deterministic rules over black-box model decisions
- Treat ML and LLM features as optional enhancement layers, not as the source of truth

## Example output

```text
Severity: HIGH

Potential brute-force attack detected.

47 failed SSH login attempts
Source: 185.xxx.xxx.xxx
Time: 02:14-02:19

Recommended actions:
1. Block source IP
2. Disable password authentication
3. Review successful logins
```

## Repository structure

```text
CyberSecurity Log Analyzer/
├── loganalyzer/
│   ├── __init__.py
│   ├── cli.py
│   ├── engine.py
│   ├── models.py
│   ├── report.py
│   ├── detectors/
│   ├── parsers/
│   └── synthetic/
├── samples/
├── tests/
├── .gitignore
├── plan.md
├── pyproject.toml
├── README.md
└── report.txt (generated output; should be ignored in Git)
```

## Requirements

### Python

- Python 3.11 or newer
- Recommended: use a project-local virtual environment

### Runtime dependencies

These are defined in [pyproject.toml](pyproject.toml):

- pandas
- python-dateutil
- scikit-learn is optional for rule-based runs; install the `ml` extra to use the standalone anomaly model.
- OpenAI is optional; install the `llm` extra only when using hosted LLM summaries.

### Development dependencies

- pytest
- scikit-learn (included so the ML tests run)

## Local setup

From the project root, create and activate a virtual environment:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For a rule-based runtime that also uses the isolated IsolationForest component,
install the optional ML extra:

```powershell
python -m pip install -e ".[ml]"
```

If PowerShell blocks activation scripts, run Python directly from the environment or adjust your execution policy for the current user only.

## Verify the environment

```powershell
python --version
python -c "import sys; print(sys.executable)"
```

The output should point to the project's local `.venv` directory.

## Run the tests

```powershell
python -m pytest
```

## Run the analyzer

Analyze the sample logs:

```powershell
python -m loganalyzer.cli analyze --logs .\samples
```

Write output to a report file:

```powershell
python -m loganalyzer.cli analyze --logs .\samples --out report.txt
```

Export JSON output:

```powershell
python -m loganalyzer.cli analyze --logs .\samples --format json
```

## Optional ML anomaly analysis (CLI)

Install the optional dependency (the `dev` extra already includes it):

```powershell
python -m pip install -e ".[ml]"
```

Choose a directory or file of representative baseline logs for training and
keep it separate from the logs being analyzed (overlapping files are rejected):

```powershell
python -m loganalyzer.cli analyze --logs .\samples --enable-ml --ml-training-logs .\training_samples --format json
```

`--enable-ml` requires `--ml-training-logs`. Model settings come from
`[ml.isolation_forest]` in the `--config` TOML file. Output gains a separate
`ML Anomaly Findings` text section, or `ml_analysis` and `ml_findings` JSON
fields. Without `--enable-ml`, output is unchanged.

ML findings differ from deterministic alerts: they have no severity, do not
affect alerts or the exit code, and mean only that an activity pattern deviates
from the training baseline. They are not confirmed attacks. IsolationForest
gives no per-feature causal attribution; the listed training ranges and
percentiles are context only. The model is refit on each run (no persistence),
and results depend heavily on a representative, mostly normal baseline; an
unrepresentative baseline produces misleading output.

## Optional LLM alert summaries (Phase 3)

LLM summaries are report-only prose for deterministic alerts. They do not
create or change alerts, severity, evidence, detector results, ML
classifications, or exit codes. The original structured alerts and evidence
remain in both text and JSON reports. ML findings are never sent to the
summarizer.

Install the optional OpenAI client:

```powershell
python -m pip install -e ".[llm]"
```

Set `OPENAI_API_KEY` in the process environment using your organization's
approved secret manager or credential-handling method. For example, when
PowerShell SecretManagement is already configured with a vault:

```powershell
$env:OPENAI_API_KEY = Get-Secret -Name OpenAIApiKey -AsPlainText
```

This makes the value available only to that PowerShell process and its child
processes. Never put the key in `config.toml`, source control, command-line
arguments, or reports. Provider and model settings use the existing TOML
configuration mechanism:

```toml
[llm]
enabled = false
provider = "openai"
model = "gpt-4o-mini"
timeout_seconds = 20
```

Enable summaries for one run with `--summarize`, or set `enabled = true` in the
TOML file passed with `--config`. `--no-summarize` overrides the TOML setting.
For example:

```powershell
python -m loganalyzer.cli analyze --logs .\samples --summarize --format json
python -m loganalyzer.cli analyze --logs .\samples --config .\config.example.toml --no-summarize
```

Network access is opt-in: ordinary rule-based analysis and ML runs do not
initialize the provider. A request is attempted only when summaries are enabled
and `OPENAI_API_KEY` is non-empty. If the key is absent, the SDK is unavailable,
the provider fails or times out, or output validation fails, a deterministic
template is used and report generation continues. Provider error details are
not included in reports.

The provider receives one alert at a time: its structured severity, title,
existing summary and evidence, detector, allowed response actions, source IPs,
and time bounds. It does not receive raw files, raw event collections,
unrelated alerts, ML findings, environment variables, or credentials.
Nevertheless, evidence may contain usernames, IP addresses, or other sensitive
values; enabling summaries sends those supplied alert fields to OpenAI. Use
synthetic or appropriately sanitized data unless that data sharing is
authorized.

Generated output is schema-checked and conservatively checked for supported
IP addresses, timestamps, numeric facts, username-like identifiers, the
authoritative severity, and response actions. Recommendations must be exact
members of the detector's allowed-action list. Invalid or uncertain output is
discarded in favor of the deterministic template. These checks reduce common
unsupported claims but cannot prove every natural-language statement is
factually correct or detect every possible paraphrase-based hallucination;
summaries remain advisory and require analyst review.

The test suite uses mocked providers and does not require `OPENAI_API_KEY`,
network access, or paid API calls:

```powershell
python -m pytest
```

## Standalone IsolationForest scoring

The ML model is opt-in and independent of deterministic alerts. It consumes
the existing `FeatureObservation` records and returns `MLAnomalyFinding`
values labelled `normal` or `anomaly`. An anomaly is a model classification,
not a confirmed attack. Per-feature ranges and percentiles provide
training-data context only; they are not causal feature explanations.

### Feature vector contract

Every observation has the following 12 features in this exact vector order
(the names are the `FEATURE_NAMES` contract):

1. `events_per_minute`
2. `failed_login_ratio`
3. `distinct_ports`
4. `distinct_destination_hosts`
5. `distinct_users`
6. `bytes_sent_total`
7. `status_1xx_ratio`
8. `status_2xx_ratio`
9. `status_3xx_ratio`
10. `status_4xx_ratio`
11. `status_5xx_ratio`
12. `status_other_ratio`

Events with a source IP are grouped by source IP and UTC-aligned time bucket;
the default bucket is 60 seconds. Naive event timestamps are interpreted as
UTC. Events without a source IP are grouped separately by log type and bucket,
so unrelated source-less event types are not combined.

Missing metrics are represented by zero to keep every feature vector numeric
and fixed-width. For example, a bucket without login events has a
`failed_login_ratio` of zero, and a bucket without web status values has zero
for each status ratio. Zero means no metric was observed; missingness itself is
not represented as a separate feature, so zero remains a value the model may
compare with its training data.

### IsolationForest settings and score interpretation

Settings are read from `[ml.isolation_forest]` and match
`config.example.toml`: `n_estimators = 100`, `max_samples = 256`,
`contamination = 0.05`, and `random_state = 42`.

- `n_estimators` is the number of trees in the forest.
- `max_samples` selects the number (or, in scikit-learn, fraction) of training
  observations sampled for each tree. This project's wrapper currently accepts
  a positive integer or `"auto"`; the example value is 256 and is limited to
  the available training observation count. Fractional values are not
  currently accepted by this wrapper.
- `contamination` is the assumed proportion of outliers used to establish the
  raw-score threshold. It is not a measured malicious-activity rate or an
  accuracy guarantee.
- `random_state` is the seed used for reproducibility; the default is 42.

Reports label the raw `score_samples` value and its `offset_` threshold
separately. Lower raw scores are more abnormal; the model classifies an
observation as an outlier when `score_samples < offset_`. The reported
`decision_function` is `score_samples - offset_`: negative values classify as
outliers, and zero is its decision boundary. Neither score identifies why an
observation is unusual.

This example trains with the generated normal web baseline and scores a
separate generated web spike. The two sets are parsed and feature-engineered
independently:

```python
from pathlib import Path

from loganalyzer.config import load_config
from loganalyzer.engine import analyze_paths
from loganalyzer.features import engineer_features
from loganalyzer.ml import IsolationForestAnomalyDetector
from loganalyzer.synthetic.generate_logs import generate_logs

training_file = generate_logs(
    Path("synthetic-training"), scenario="web_baseline", seed=2026
)["web_baseline"]
training_result = analyze_paths(
    [training_file], formats={training_file: "web"}, detectors=[]
)
training_observations = engineer_features(training_result.events)

scoring_file = generate_logs(
    Path("synthetic-scoring"), scenario="web_spike", seed=2026
)["web_spike"]
scoring_result = analyze_paths(
    [scoring_file], formats={scoring_file: "web"}, detectors=[]
)
scoring_observations = engineer_features(scoring_result.events)

settings = load_config(Path("config.example.toml")).ml_options["isolation_forest"]
model = IsolationForestAnomalyDetector(**settings).fit(training_observations)
for finding in model.score(scoring_observations):
    print(finding.classification, finding.source_group, finding.time_bucket)
```

The checked-in generator's baseline is intentionally small; this example
demonstrates the API, not detection accuracy. In practice, fit against a
representative normal history and evaluate on separate data before relying on
model classifications.

`IsolationForestAnomalyDetector` defaults to a fixed random seed and exposes
its effective training and decision settings through `model.metadata`.
Settings can be supplied in `[ml.isolation_forest]` in a TOML config and are
used by both the standalone component (pass them directly) and the CLI ML
workflow.

## Current project direction

The project has a rule-based MVP and an independently usable Phase 2 feature
engineering and anomaly-scoring layer, plus opt-in Phase 3 summaries:

1. parse log sources into a normalized event model
2. run rule-based detectors for suspicious activity
3. correlate evidence and produce structured alerts
4. format clear text or JSON reports
5. validate against synthetic and sample data
6. optionally add validated, advisory prose to deterministic alert reports

LLM summaries remain optional and intentionally secondary to explainability
and correctness.

## Security and operational notes

- Treat logs as untrusted input
- Keep findings grounded in observed evidence
- Avoid storing secrets or credentials in reports or source control
- Do not commit virtual environments, generated reports, or local environment files
- Prefer synthetic or sanitized data for development and testing

## License

This project is intended for educational and security-research use. Add an appropriate open-source license if you plan to publish it publicly on GitHub.

## Notes

This repository is designed around a clean, testable engineering workflow and a future path toward richer analysis, structured alerting, and operational reporting.
