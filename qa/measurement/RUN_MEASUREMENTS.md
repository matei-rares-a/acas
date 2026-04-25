# Running Measurements

This folder contains performance benchmarks and load-test scenarios for the dissertation.
These scripts are run **manually** (not via `main_test.py`).

## Folder Layout

```
qa/measurement/
├── benchmark.py          # pytest-based latency & memory benchmarks
├── brute_force_dlp.py    # DLP brute-force demo (standalone)
├── locustfile.py         # Locust load-test scenarios (ZKP + OAuth2)
├── main_probes.py        # dissertation data-collection probes (latency table, audit, charts)
├── comparision.py        # protocol comparison measurements
├── generates.py          # data generators for measurements
├── run_all_measurements.py
└── run_bench.py
```

## Benchmarks (`benchmark.py`)

Run all three benchmark tests (requires no live server — uses Flask test client):

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/measurement/benchmark.py -v -s
```

Run only the micro-latency table (prints Markdown table to console):

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/measurement/benchmark.py -k benchmark_prints_latency_table -v -s
```

Run only the end-to-end protocol comparison:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/measurement/benchmark.py -k benchmark_e2e_protocol_comparison -v -s
```

Run only the memory footprint test:

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/measurement/benchmark.py -k memory_footprint -v -s
```

## DLP Brute-Force Demo (`brute_force_dlp.py`)

Standalone script demonstrating brute-force infeasibility at scale (no server needed):

```bash
C:/LegacyApp/Python/Python312/python.exe qa/measurement/brute_force_dlp.py
```

## Locust Load Tests (`locustfile.py`)

Requires a **live server** running on port 5000:

```bash
# Terminal 1 – start the server
python server_app/server.py

# Terminal 2 – run Locust
locust -f qa/measurement/locustfile.py --host=http://localhost:5000 --users 100 --spawn-rate 10 --headless --run-time 60s --html locust_report.html
```

Adjust `--users` and `--run-time` as needed. The HTML report is written to `locust_report.html` at the workspace root.

## Dissertation Probes (`main_probes.py`)

Standalone data-collection scripts that generate Markdown tables and PNG charts for the dissertation:

```bash
# Latency table (Markdown, stdout)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --latency

# Traffic content audit (writes audit_report.md)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --audit

# Security snippet extractor (writes security_snippets.md)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --snippets

# Chart generator — box plot + histogram (writes charts/)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --charts

# Run all probes
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --all
```

> `--charts` requires `matplotlib`: `pip install matplotlib`
