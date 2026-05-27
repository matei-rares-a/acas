# QA

This folder contains all quality-assurance work for the project: functional tests, performance
benchmarks, load tests, measurement probes, and manual security audits.

---

## Folder Layout

```
qa/
+-- qa_utils.py               # shared helpers: derive_password_x, register_user, start_commit, pkce_challenge
|                             # also: BaseTestSuite, OAuthTestSuite base classes
+-- measurement_utils.py      # shared utilities for measurement scripts
+-- attack_simulation/
|   +-- automated.py          # automated attack scenarios
|   \\-- manual.py             # manual attack scripts
+-- measurement/
|   +-- benchmark.py          # pytest-based latency & memory benchmarks
|   +-- brute_force_dlp.py    # DLP brute-force demo (standalone)
|   +-- locustfile.py         # Locust load-test scenarios (ZKP + OAuth2)
|   +-- main_probes.py        # dissertation data-collection probes
|   +-- comparision.py        # protocol comparison measurements
|   +-- generates.py          # data generators for measurements
|   +-- run_all_measurements.py
|   \\-- run_bench.py
\\-- test/
    +-- main_test.py          # suite runner with statistics
    +-- pos_case.py           # positive (happy-path) tests
    +-- neg_case.py           # negative / attack tests
    +-- corner_case.py        # boundary & edge cases
    +-- security_case.py      # cryptographic attack vectors & protocol security
    +-- oauth_case.py         # OAuth2 PKCE & Simple authorization code flow
    \\-- conftest.py
```

---

## Functional Tests

### Quick Start

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

### Install Dependencies

```bash
C:/LegacyApp/Python/Python312/python.exe -m pip install -r requirements.txt
```

### Useful Commands

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

### Output Format

The custom reporter prints plain text summary blocks:

```text
USE CASE: <suite name>
Total Tests: <n>
Passed: <n>
Failed: <n>
OVERALL STATUS: PASSED|FAILED
```

No symbol markers are used in the summary lines.

### Continuous Integration

```bash
C:/LegacyApp/Python/Python312/python.exe -m pytest qa/test/ -v --tb=short
```

The `--tb=short` flag provides concise traceback output suitable for CI logs.

### Additional Pytest Options

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

---

## Measurements & Benchmarks

These scripts are run **manually** (not via `main_test.py`).

### Benchmarks (`benchmark.py`)

Run all three benchmark tests (requires no live server -- uses Flask test client):

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

### DLP Brute-Force Demo (`brute_force_dlp.py`)

Standalone script demonstrating brute-force infeasibility at scale (no server needed):

```bash
C:/LegacyApp/Python/Python312/python.exe qa/measurement/brute_force_dlp.py
```

### Locust Load Tests (`locustfile.py`)

Requires a **live server** running on port 5000:

```bash
# Terminal 1 - start the server
python server_app/server.py

# Terminal 2 - run Locust
locust -f qa/measurement/locustfile.py --host=http://localhost:5000 --users 100 --spawn-rate 10 --headless --run-time 60s --html locust_report.html
```

Adjust `--users` and `--run-time` as needed. The HTML report is written to `locust_report.html` at the workspace root.

### Dissertation Probes (`main_probes.py`)

Standalone data-collection scripts that generate Markdown tables and PNG charts for the dissertation:

```bash
# Latency table (Markdown, stdout)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --latency

# Traffic content audit (writes audit_report.md)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --audit

# Security snippet extractor (writes security_snippets.md)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --snippets

# Chart generator -- box plot + histogram (writes charts/)
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --charts

# Run all probes
C:/LegacyApp/Python/Python312/python.exe qa/measurement/main_probes.py --all
```

> `--charts` requires `matplotlib`: `pip install matplotlib`

---

## Security Audit (Manual)

Manual scenarios that verify the ZKP protocol's privacy and parameter-integrity guarantees.

### Prompt 1: Traffic Sniffing (Store-Now Decrypt-Later)

**Objective**: Verify that the plaintext password and private key `x` do not traverse the network
in the ZKP flow.

**Setup**
1. Start the Flask server on HTTP (no TLS): `python server_app/server.py`
2. Start Wireshark/tshark on the loopback interface.
3. Recommended filter: `http.request.method == "POST"`

**Steps**
1. Open `http://localhost:5000`.
2. Perform a valid login via the UI.
3. Capture the payloads for:
   - `POST /login/commit`
   - `POST /login/verify`

**Expected findings**
- In commit: `client_id`, `commitment_t`
- In verify: `solution_s`

**Must NOT appear**
- `password` in plaintext
- private key `x`

**Conclusion**: Captured values `{t, c, s}` do not reveal `x`; the zero-knowledge property holds.

---

### Prompt 2: MitM on /parameters

**Objective**: Simulate injection of weak parameters (`P=23`, `G=4`) and document the impact.

**Setup**
1. Start the Flask server.
2. Configure the browser through Burp Suite / OWASP ZAP.
3. Intercept `GET /parameters`.

**Steps**
1. Intercept the response carrying the global group parameters.
2. Replace the values with `P=23`, `G=4`.
3. Forward the modified response to the client.
4. Continue the login and observe that the DLP becomes trivial on the small group.

**Consequences**: The attacker can recover `x` in the weak group and forge a valid `s`.

**Mitigations**
1. HTTPS/TLS mandatory for `/parameters` in production.
2. Optional: certificate pinning in the client.
3. Optional: hardcode trusted parameters in the frontend.

**Evidence to attach in dissertation**
1. Wireshark/tshark capture with commit/verify payloads.
2. Burp/ZAP capture showing the modified `/parameters` response.
3. Notes on why password extraction is impossible in the normal flow.
