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
4. Performance & Load Tests (`perf_load.py`)

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
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/pos_case.py qa/test/neg_case.py qa/test/corner_case.py -v
```

Run all tests in `qa/test`:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/ -v
```

Run benchmark test from perf_load.py (prints latency table):

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/perf_load.py -k benchmark_prints_latency_table -v -s
```

Run Locust script requested by prompts:

```bash
locust -f qa/test/locustfile.py --host=http://localhost:5000
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

# From anywhere with full path
C:/LegacyApp/Python/Python312/python.exe -m pytest c:\local_store\files\my_workspace\acas\qa\test\pos_case.py -v
```

## Continuous Integration

To run tests in CI/CD pipelines, use:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/pos_case.py -v --tb=short
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
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/pos_case.py -v -s
```
