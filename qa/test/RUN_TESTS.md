# Running QA Tests with Statistics

This project provides a standalone runner and regular pytest commands.

## Quick Start

Run all configured suites:

```bash
C:/LegacyApp/Python/Python312/python.exe qa/test/main_test.py
```

Current suites in `main_test.py`:
1. Positive Test Cases (`pos_case.py`)
2. Negative Test Cases (`neg_case.py`)
3. Corner Cases (`corner_case.py`)
4. Security Tests (`security_case.py`)
5. OAuth2 Functional Tests (`oauth_case.py`)

## QA Folder Layout

```
qa/
├── qa_utils.py               # shared helpers: derive_password_x, register_user, start_commit, pkce_challenge
├── attack_simulation/
│   ├── automated.py          # automated attack scenarios
│   └── manual.py             # manual attack scripts
├── measurement/
│   ├── benchmark.py          # pytest-based latency & memory benchmarks
│   ├── brute_force_dlp.py    # DLP brute-force demo (standalone)
│   ├── locustfile.py         # Locust load-test scenarios
│   ├── main_probes.py        # dissertation data-collection probes
│   ├── comparision.py        # protocol comparison measurements
│   ├── generates.py          # data generators for measurements
│   └── run_all_measurements.py
└── test/
    ├── main_test.py          # suite runner with statistics
    ├── pos_case.py           # positive (happy-path) tests
    ├── neg_case.py           # negative / attack tests
    ├── corner_case.py        # boundary & edge cases
    ├── security_case.py      # cryptographic attack vectors & protocol security
    ├── oauth_case.py         # OAuth2 PKCE & Simple authorization code flow
    ├── conftest.py
    └── perf/                 # (empty — benchmarks moved to qa/measurement/)
```

## Install Dependencies

```bash
C:/LegacyApp/Python/Python312/python.exe -m pip install -r requirements.txt
```

## Useful Commands

Run one suite:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/pos_case.py -v
```

Run selected suites:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/pos_case.py qa/test/neg_case.py qa/test/corner_case.py qa/test/security_case.py qa/test/oauth_case.py -v
```

Run all tests in `qa/test`:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/ -v
```

## Output Format

The custom reporter prints plain text summary blocks:

```text
USE CASE: <suite name>
Total Tests: <n>
Passed: <n>
Failed: <n>
OVERALL STATUS: PASSED|FAILED
```

No symbol markers are used in the summary lines.

## Continuous Integration

To run tests in CI/CD pipelines, use:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/ -v --tb=short
```

The `--tb=short` flag provides concise traceback output suitable for CI logs.

## Additional Pytest Options

| Option | Description |
|--------|-------------|
| `-v` | Verbose output (recommended) |
| `-vv` | Very verbose output with all details |
| `-q` | Quiet mode (minimal output) |
| `--tb=short` | Shorter traceback format |
| `-s` | Show print statements |
| `-k test_name` | Run only tests matching the name |
| `--collect-only` | List all tests without running them |

Example:
```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/security_case.py -v -s
```
