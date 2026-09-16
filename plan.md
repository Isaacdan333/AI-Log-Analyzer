# AI Cybersecurity Log Analyzer

## 1. Project Goal

Build a Python-based cybersecurity log analyzer that accepts multiple log sources, converts them into a common event format, detects suspicious activity, and produces clear incident reports.

Initial supported sources:

- Windows Event Logs
- Firewall logs
- SSH authentication logs
- Apache or Nginx web server logs

The first version should be deterministic, explainable, and testable. Machine learning and large language model features should be added only after the core detection pipeline works reliably.

## 2. Example Output

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

Every alert should preserve the evidence that caused it. The reporting layer should not invent facts that are absent from the parsed logs.

## 3. Recommended Technology

### Initial stack

- Python 3.11+
- A project-local `.venv` virtual environment
- `pandas` for event analysis and time-window operations
- `python-dateutil` for timestamp parsing
- `pytest` for automated tests
- `argparse` or `click` for the command-line interface

### Dependency files

Use `pyproject.toml` as the project configuration and dependency definition. Keep generated or environment-specific files out of source control.

The initial runtime dependencies are:

```text
pandas
python-dateutil
```

The initial development dependencies are:

```text
pytest
```

Later phases can add `scikit-learn`, `FastAPI`, and other packages only when their features are implemented.

## 4. Local Development Environment

Develop and run the project inside a project-local virtual environment. This prevents the analyzer's packages from conflicting with other Python projects and makes setup reproducible.

### Prerequisites

- Python 3.11 or newer installed and available through the Windows Python launcher (`py`)
- VS Code with the Python extension
- PowerShell or another terminal that can run the environment activation script

### Initial setup on Windows

Run these commands from the project root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The `-e` option installs the project in editable mode, so package changes are available immediately while developing.

If PowerShell blocks activation scripts, use the current user's execution-policy setting or run the environment's Python executable directly. Do not disable security controls system-wide just for this project.

### VS Code interpreter

Select `.venv\Scripts\python.exe` through **Python: Select Interpreter**. New terminals should show `(.venv)` when the environment is active.

Confirm the selected environment with:

```powershell
python --version
python -c "import sys; print(sys.executable)"
```

The executable path should point inside this project's `.venv` directory.

### Daily workflow

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest
python -m loganalyzer.cli analyze --logs .\samples
```

Deactivate the environment when finished or when switching projects:

```powershell
deactivate
```

### Recreating the environment

The virtual environment is disposable. If it becomes inconsistent, remove `.venv` and recreate it from the project configuration:

```powershell
Remove-Item -Recurse -Force .venv
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Do not commit `.venv` or rely on `pip freeze` as the primary dependency definition. Use `pyproject.toml` to describe intentional dependencies and let the environment contain installed packages.

### Later additions

- `scikit-learn` for anomaly detection
- `FastAPI` for an API and web backend
- A frontend using the project's chosen web framework
- An optional LLM provider or local model for report wording
- GeoIP data such as MaxMind GeoLite2 for impossible-travel analysis

## 5. Design Principles

1. Normalize different log formats into one event model.
2. Keep detection logic separate from parsing and reporting.
3. Make every detection explainable through evidence and thresholds.
4. Keep rule-based detection as the source of truth for severity.
5. Treat ML as an additional signal, not a replacement for deterministic rules.
6. Treat an LLM as a writing and summarization layer, not an authority that decides whether an attack occurred.
7. Make the first release useful without external services or API keys.
8. Expect false positives and expose the reason for each alert so thresholds can be tuned.
9. Avoid storing secrets, passwords, or unnecessary personal data in reports.
10. Use synthetic data for initial development and testing.

## 6. Proposed Project Structure

```text
CyberSecurity Log Analyzer/
|-- .venv/                       # local virtual environment; never commit
|-- loganalyzer/
|   |-- __init__.py
|   |-- models.py                # shared NormalizedEvent and Alert dataclasses
|   |-- parsers/
|   |   |-- __init__.py
|   |   |-- base.py
|   |   |-- ssh.py
|   |   |-- firewall.py
|   |   |-- webserver.py
|   |   `-- windows_evt.py
|   |-- detectors/
|   |   |-- __init__.py
|   |   |-- base.py
|   |   |-- bruteforce.py
|   |   |-- suspicious_login.py
|   |   |-- port_scan.py
|   |   |-- impossible_travel.py
|   |   |-- privilege_escalation.py
|   |   `-- unusual_traffic.py
|   |-- synthetic/
|   |   |-- __init__.py
|   |   `-- generate_logs.py
|   |-- cli.py
|   |-- engine.py
|   |-- report.py
|   `-- settings.py
|-- tests/
|   |-- test_parsers.py
|   |-- test_detectors.py
|   |-- test_report.py
|   `-- test_engine.py
|-- samples/
|   `-- generated logs go here
|-- pyproject.toml
|-- .gitignore
`-- plan.md
```
The `.venv` directory is shown to make the local environment explicit, but its contents are generated by Python and must not be edited or committed. All application code belongs under `loganalyzer/`; tests run against the active environment.

## 7. Shared Data Models

Define the two cross-layer data structures in `loganalyzer/models.py`. This file should contain data definitions only; parsing, detection, and reporting behavior belongs in the relevant modules.

### `NormalizedEvent`


All parsers should produce a shared `NormalizedEvent` object. A dataclass is a good starting point.

Suggested fields:

```text
timestamp       Parsed UTC or timezone-aware timestamp
source          Name of the input source or file
log_type        windows, firewall, ssh, or web
event_type      login_failure, login_success, connection, http_request, privilege_change, etc.
src_ip          Source IP address, when available
dst_ip          Destination IP address, when available
dst_port        Destination port, when available
protocol        TCP, UDP, ICMP, or other protocol
user            Username, when available
status          success, failure, denied, accepted, or unknown
bytes_sent      Request or network byte count, when available
path            Requested web path, when available
geo             Optional location data added later
metadata        Source-specific fields such as Windows Event ID
raw_line        Original log line or a safe source reference
```

The parser should retain the original event context but should not copy passwords, tokens, cookies, or other secrets into `raw_line` or reports.

### `Alert`

All detectors should return a shared `Alert` object from `loganalyzer/models.py` so the engine, formatters, CLI, and future API use the same structure.

Suggested fields:

```text
severity             LOW, MEDIUM, HIGH, or CRITICAL
title                Short alert title
summary              Human-readable explanation
evidence             Structured facts supporting the alert
recommended_actions  Ordered response suggestions
source_ips           Related source addresses
time_start           Beginning of observed activity
time_end             End of observed activity
detector             Detector name
confidence           Optional numeric or categorical confidence
```

## 8. Parser Requirements

### 8.1 SSH parser

Start with Linux `auth.log` or `secure`-style lines.

Recognize:

- `Failed password`
- `Accepted password`
- `Accepted publickey`
- `Invalid user`
- `sudo`
- `su`

Extract:

- Timestamp
- Username
- Source IP
- Authentication result
- Authentication method
- Process or service where available

### 8.2 Firewall parser

Start with common iptables/syslog-style records.

Recognize:

- Accepted connections
- Dropped or rejected connections
- Source and destination IP addresses
- Destination ports
- Protocols
- Packet and byte counts when available

The parser should tolerate optional fields and report malformed lines without stopping the entire analysis.

### 8.3 Web server parser

Support Apache/Nginx combined log format first.

Extract:

- Client IP
- Timestamp
- HTTP method
- Requested path
- Status code
- Response bytes
- Referrer
- User agent

Recognize useful signals such as repeated 401/403 responses, unusual request rates, suspicious paths, and large response or request volumes.

### 8.4 Windows Event Log parser

Start with exported Windows Security Event Log CSV files instead of raw `.evtx` files.

Important initial Event IDs:

- `4624`: successful logon
- `4625`: failed logon
- `4672`: special privileges assigned to a new logon
- `4720`: user account created
- `4728` and `4732`: account added to privileged groups
- `4688`: process creation, when command-line auditing is enabled

Later, add direct `.evtx` parsing using a dedicated library after the CSV pipeline is working.

## 9. Detection Rules

Each detector should receive normalized events and return zero or more `Alert` objects defined in `loganalyzer/models.py`.

### 9.1 Brute-force attempts

Initial rule:

- Group failed authentication events by source IP and username where possible.
- Use a rolling time window, such as 5 minutes.
- Trigger when the failure count crosses a configurable threshold.

Example configuration:

```text
MEDIUM: 10 failed attempts in 5 minutes
HIGH:   25 failed attempts in 5 minutes
CRITICAL: failure burst followed by a successful privileged login
```

These values are starting points, not universal security advice. They should be configurable.

### 9.2 Suspicious login patterns

Possible signals:

- Successful login after repeated failures from the same source
- Login outside the configured normal hours
- New source IP for a user
- Rapid switching between many accounts
- Login using a weaker or unexpected authentication method
- Successful login to a sensitive account from an unfamiliar source

The detector should report which signal caused the alert rather than simply labeling a login suspicious.

### 9.3 Port scanning

Initial rule:

- Group network connection events by source IP and short time window.
- Count distinct destination ports and destination hosts.
- Trigger when one source touches many ports or hosts in a short period.

Example starting thresholds:

```text
MEDIUM: 10 distinct ports in 60 seconds
HIGH:   25 distinct ports in 60 seconds
CRITICAL: many ports across multiple hosts with mostly denied results
```

### 9.4 Impossible travel

Initial rule:

- Group successful logins by user.
- Resolve source IPs to approximate coordinates.
- Compare the distance between consecutive login locations with the elapsed time.
- Trigger when the implied travel speed is impossible.

Development can use a small static IP-to-location map for synthetic addresses. Production use requires a maintained offline GeoIP database and clear handling for VPNs, proxies, mobile networks, and corporate egress points.

This detector should initially produce a lower-confidence alert because IP geolocation is inherently approximate.

### 9.5 Privilege escalation

Possible signals:

- Windows Event ID `4672`
- A new account followed by privileged-group membership
- Windows Event IDs `4720`, `4728`, or `4732`
- `sudo` or `su` activity shortly after an unusual login
- Privileged process creation following a suspicious authentication event

Correlate events by user, host, and nearby timestamps. Preserve the exact event IDs as evidence.

### 9.6 Unusual traffic

Initial version:

- Calculate request or connection counts per source and time bucket.
- Establish a baseline from the same source or service.
- Flag large deviations using a configurable z-score or IQR rule.
- Include the baseline and observed values in the evidence.

The initial baseline should require enough historical data. If there is not enough data, return no statistical alert rather than pretending the result is reliable.

## 10. Detection Engine

`engine.py` should perform this sequence:

1. Discover input files in the requested directory.
2. Select a parser using an explicit file type or user-provided format.
3. Parse each file into normalized events.
4. Record parser errors without discarding valid events from other files.
5. Combine events and sort them by timestamp.
6. Run each detector.
7. Deduplicate overlapping alerts where appropriate.
8. Sort alerts by severity and time.
9. Send structured alerts to the reporting layer.

The engine should expose a Python API so the future CLI and web API use the same behavior.

## 11. Report Formatting

The first report should be a deterministic text formatter.

Required sections:

```text
Severity: HIGH

[Short title or summary]

[Evidence facts]
Source: [IP or source]
Time: [start-end]

Recommended actions:
1. [Action]
2. [Action]
3. [Action]
```

Recommendations should be tied to the detector. For example:

- Brute force: block or rate-limit the source, review successful logins, prefer key-based authentication.
- Port scan: inspect the source, review denied connections, verify exposed services.
- Privilege escalation: review account and process activity, disable unauthorized accounts, preserve forensic evidence.
- Unusual traffic: compare against application changes, inspect high-volume endpoints, apply rate limits where appropriate.

The report must clearly distinguish observations from recommendations. It should not claim that an attack is confirmed when the detector only found suspicious behavior.

## 12. Command-Line Interface

Initial commands:

```text
python -m loganalyzer.cli analyze --logs ./samples
python -m loganalyzer.cli analyze --logs ./samples --out report.txt
python -m loganalyzer.cli analyze --logs ./samples --format json
```

Useful options:

- Input directory or individual file
- Explicit log type override
- Output format: text or JSON
- Configuration file for thresholds
- Minimum severity to display
- Optional timezone setting
- Optional `--use-llm` flag in a later phase

JSON output is important because the future dashboard should consume structured alerts rather than scrape formatted text.

## 13. Synthetic Test Data

Create a generator that produces realistic but clearly synthetic logs for:

- Normal successful and failed SSH logins
- A brute-force burst from one source
- A successful login after a failure burst
- A firewall port scan
- A normal web traffic baseline and an injected traffic spike
- Windows privileged events
- Two geographically distant synthetic login locations within an impossible time interval

The generator should use fixed random seeds when requested so tests are repeatable.

## 14. Testing Strategy

### Parser tests

For each parser:

- Parse representative valid lines.
- Verify extracted timestamp, IP, user, event type, and status.
- Verify malformed lines do not crash the full parser.
- Verify sensitive values are not copied into reports.

### Detector tests

For each detector:

- Test a clear positive case.
- Test a clear negative case.
- Test events exactly at configured thresholds.
- Test events just below thresholds.
- Verify evidence and severity are correct.

### Integration tests

- Generate a synthetic log directory.
- Run the engine across all files.
- Confirm expected alert types are present.
- Confirm unrelated normal activity does not create excessive alerts.
- Confirm the CLI can produce both text and JSON output.

## 15. Implementation Phases

### Phase 1: Rule-Based MVP

Goal: produce useful, explainable reports from batch log files.

Tasks:

1. Create `.venv`, `pyproject.toml`, `.gitignore`, and the package structure.
2. Install the project and development dependencies into `.venv`.
3. Implement the normalized event model.
4. Implement SSH, firewall, web, and Windows CSV parsers.
5. Create synthetic logs.
6. Implement the six rule-based detectors.
7. Implement the detection engine.
8. Implement text and JSON reporting.
9. Implement the CLI.
10. Add unit and end-to-end tests.

Completion criteria:

- Synthetic logs run from start to finish.
- A brute-force example produces a HIGH alert.
- All alerts include evidence and recommendations.
- Test suite passes.

### Phase 2: Statistical and ML Detection

Goal: find unusual behavior that fixed rules may miss.

Add `scikit-learn` and engineer features such as:

- Events per minute
- Failed-login ratio
- Distinct ports
- Distinct destination hosts
- Distinct users
- Request bytes
- Status-code distribution

Start with `IsolationForest` for per-source or per-time-bucket anomaly scoring. Keep the model output separate from deterministic findings and label it as an anomaly rather than a confirmed attack.

Completion criteria:

- Model is tested on synthetic normal and anomalous data.
- Features and model settings are recorded.
- Alerts show why the model considered an observation unusual.
- A model result cannot silently override a deterministic severity.

### Phase 3: LLM-Powered Summarization

Goal: make reports easier for analysts to read without delegating detection decisions to an LLM.

The LLM should receive:

- Structured alert data
- Evidence values
- Detector name
- Severity selected by the engine
- Allowed response actions

The LLM should produce:

- A concise incident summary
- A plain-language explanation
- Prioritized recommendations
- Questions for an analyst to investigate

The LLM should not:

- Decide severity
- Create an IP address, count, timestamp, or username
- Replace raw evidence
- Execute remediation actions
- Receive secrets or unnecessary raw logs

Use a templated report automatically when no API key is configured or the LLM request fails. Validate that generated text contains the important structured facts.

### Phase 4: Web Dashboard

Goal: provide an analyst-friendly interface.

Possible FastAPI endpoints:

```text
POST /analyze
GET  /alerts
GET  /alerts/{alert_id}
GET  /health
```

Dashboard features:

- Upload or select a log set
- Alert list sorted by severity and time
- Filters for source, detector, severity, and date
- Expandable evidence
- Recommended actions
- JSON export
- Clear distinction between observed evidence and generated explanation

Real-time log tailing can be added after batch analysis is stable. It should use a queue and worker model rather than blocking HTTP requests.

## 16. Configuration

Thresholds should be configurable rather than hardcoded.

Example configuration areas:

```text
brute_force.failure_window_minutes
brute_force.medium_threshold
brute_force.high_threshold
port_scan.window_seconds
port_scan.distinct_port_threshold
suspicious_login.normal_hours
unusual_traffic.minimum_baseline_events
report.minimum_severity
```

Use a checked-in example configuration file with safe defaults. Do not put API keys or GeoIP license credentials in source control.

## 17. Security and Operational Considerations

- Treat log files as untrusted input.
- Escape control characters before displaying raw log content.
- Validate IP addresses and timestamps.
- Limit maximum file sizes and line lengths.
- Avoid command execution based on log content.
- Keep LLM prompts free of credentials and unnecessary personal information.
- Redact usernames or IPs in exported reports when required by organizational policy.
- Use UTC internally where possible and show the timezone in reports.
- Log parser failures separately from security findings.
- Preserve original files when forensic retention is required.
- Do not automatically block IPs in the first version. Produce recommendations for human review.
- Never commit `.venv`, API keys, local log files, generated reports, or GeoIP database files.

Suggested `.gitignore` entries:

```gitignore
.venv/
__pycache__/
*.py[cod]
.pytest_cache/
*.egg-info/
samples/*.log
reports/
.env
```

## 18. Verification Checklist

1. `pytest` passes parser, detector, report, and engine tests.
2. Synthetic log generation creates all intended scenarios.
3. CLI analysis completes with no external service dependencies.
4. Text output contains severity, summary, evidence, and recommendations.
5. JSON output contains structured alert fields.
6. A known brute-force scenario creates the expected HIGH alert.
7. Normal traffic does not create a large number of false alerts.
8. All six detector types can be demonstrated with synthetic data.
9. Malformed input produces parser diagnostics instead of terminating analysis.
10. Later LLM output preserves the facts from the structured alert.

## 19. Recommended Starting Order

Start with the smallest useful vertical slice:

1. Create the project-local `.venv`.
2. Add `pyproject.toml` and `.gitignore`.
3. Install the package in editable mode with development dependencies.
4. Define `NormalizedEvent` and `Alert`.
5. Implement the SSH parser.
6. Implement the brute-force detector.
7. Implement text reporting.
8. Add a small synthetic SSH log.
9. Run the CLI and tests end to end inside `.venv`.
10. Add the remaining parsers and detectors one at a time.

This gives a working security analysis path early and makes each later addition easier to verify.

## 20. Important Scope Decisions

- Begin with batch files, not real-time streaming.
- Begin with Windows CSV exports, not raw `.evtx` files.
- Begin with deterministic rules, not an LLM.
- Use synthetic data before introducing real sensitive logs.
- Keep automated remediation out of the first release.
- Add ML only after the rule-based evidence pipeline is reliable.
