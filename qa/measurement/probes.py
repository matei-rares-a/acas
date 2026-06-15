"""
  data collection scripts.
"""

from pathlib import Path
import csv
import hashlib
import secrets as secrets_module
import subprocess
import sys
import time
import matplotlib.pyplot as plt


_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))
from qa_utils import (
    server,
    derive_password_x, pkce_challenge,
    OAUTH_PKCE_CLIENT_ID, OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI,
    AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI,
)
from measurement_utils import setup_isolated_test_user
from benchmark import (
    _benchmark_latency as run_micro_benchmark,
)

_GENERATED = Path(__file__).resolve().parent / "generated"
_GENERATED.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Probe 2 - Traffic content auditor
# ---------------------------------------------------------------------------

def audit_traffic_content(output_md: str = str(_GENERATED / "audit_traffic_content.md")):
    """
    Simulate an application-level MitM observer and produce .md.
    Shows what each protocol transmits over the wire without keyword scanning.
    """

    client_id = "audit_traffic_user"
    password = "audit-secret"
    x, client = setup_isolated_test_user(client_id, password)
    server.sessions.clear()

    rand_r = secrets_module.randbelow(server.P - 2) + 1
    t = pow(server.G, rand_r, server.P)

    commit_body = {"client_id": client_id, "commitment_t": str(t)}
    commit_resp = client.post("/login/commit", json=commit_body)
    payload = commit_resp.get_json()
    c = int(payload["challenge_c"])
    s = (rand_r + c * x) % server.Q
    verify_body = {"solution_s": str(s)}

    classic_example_body = {"client_id": client_id, "password": password}

    # OAuth2 PKCE bodies (what travels over the wire in the GET+POST browser flow)
    code_verifier = secrets_module.token_urlsafe(48)
    code_challenge = pkce_challenge(code_verifier)
    pkce_authorize_get_qs = {
        "response_type": "code",
        "client_id": OAUTH_PKCE_CLIENT_ID,
        "redirect_uri": "<redirect_uri>",
        "scope": "openid profile",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    pkce_authorize_post_body = {
        "auth_request_id": "<opaque-one-time-token>",
        "username": client_id,
        "password": "<hidden-by-browser-form>",
    }
    pkce_token_body = {
        "grant_type": "authorization_code",
        "client_id": OAUTH_PKCE_CLIENT_ID,
        "code": "<opaque-auth-code>",
        "code_verifier": code_verifier,
    }

    # OAuth2 Simple bodies
    simple_authorize_get_qs = {
        "response_type": "code",
        "client_id": OAUTH_SIMPLE_CLIENT_ID,
        "redirect_uri": "<redirect_uri>",
        "scope": "openid profile",
    }
    simple_authorize_post_body = {
        "auth_request_id": "<opaque-one-time-token>",
        "username": client_id,
        "password": "<hidden-by-browser-form>",
    }
    simple_token_body = {
        "grant_type": "authorization_code",
        "client_id": OAUTH_SIMPLE_CLIENT_ID,
        "code": "<opaque-auth-code>",
    }

    # Authlib PKCE bodies (form-encoded, same fields as PKCE)
    authlib_authorize_body = {
        "response_type": "code",
        "client_id": AUTHLIB_CLIENT_ID,
        "username": client_id,
        "password": password,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    authlib_token_body = {
        "grant_type": "authorization_code",
        "client_id": AUTHLIB_CLIENT_ID,
        "code": "<opaque-auth-code>",
        "code_verifier": code_verifier,
    }

    def _truncate(body):
        return str({k: (str(v)[:60] + "...") if len(str(v)) > 63 else str(v) for k, v in body.items()})

    report_lines = [
        "# Audit Trafic: ZKP vs OAuth2 PKCE vs OAuth2 Simple vs Authlib PKCE",
        "",
        "## POST /login/commit (ZKP Step 1)",
        "```json",
        _truncate(commit_body),
        "```",
        "",
        "## POST /login/verify (ZKP Step 2)",
        "```json",
        _truncate(verify_body),
        "```",
        "",
        "## POST /classic/login (Autentificare Clasica)",
        "```json",
        str(classic_example_body),
        "```",
        "Nota: parola este trimisa in clar catre server.",
        "",
        "## GET /oauth/pkce/authorize (OAuth2 PKCE Step 1a - browser initiates)",
        "```",
        str(pkce_authorize_get_qs),
        "```",
        "Nota: browser-ul (client app) trimite parametrii OAuth in query string; parola nu apare.",
        "",
        "## POST /oauth/pkce/authorize (OAuth2 PKCE Step 1b - user submits credentials)",
        "```",
        str(pkce_authorize_post_body),
        "```",
        "Nota: parola este trimisa direct catre Authorization Server (nu trece prin client app).",
        "",
        "## POST /oauth/pkce/token (OAuth2 PKCE Step 2 - code exchange)",
        "```json",
        _truncate(pkce_token_body),
        "```",
        "Nota: code_verifier este un secret de scurta durata, parola nu mai apare in aceasta cerere.",
        "",
        "## GET /oauth/simple/authorize (OAuth2 Simple Step 1a - browser initiates)",
        "```",
        str(simple_authorize_get_qs),
        "```",
        "Nota: browser-ul trimite parametrii OAuth in query string, fara PKCE.",
        "",
        "## POST /oauth/simple/authorize (OAuth2 Simple Step 1b - user submits credentials)",
        "```",
        str(simple_authorize_post_body),
        "```",
        "Nota: parola este trimisa direct catre Authorization Server.",
        "",
        "## POST /oauth/simple/token (OAuth2 Simple Step 2)",
        "```json",
        _truncate(simple_token_body),
        "```",
        "",
        "## POST /authlib/oauth/authorize (Authlib PKCE Step 1 - form-encoded)",
        "```",
        _truncate(authlib_authorize_body),
        "```",
        "Nota: echivalent cu OAuth2 PKCE dar folosind biblioteca Authlib, parametri form-encoded.",
        "",
        "## POST /authlib/oauth/token (Authlib PKCE Step 2 - form-encoded)",
        "```",
        _truncate(authlib_token_body),
        "```",
        "",
    ]

    out = Path(output_md)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(report_lines), encoding="utf-8")
    print(f"Audit report written to: {out.resolve()}")



# ---------------------------------------------------------------------------
# Shared chart helper
# ---------------------------------------------------------------------------

def _save_fig(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=300)
    print(f"Saved: {path}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Probe 4 - Chart generator
# ---------------------------------------------------------------------------

def generate_charts(latency_data: dict | None = None, output_dir: str = str(_GENERATED / "charts")):
    """Generate box plot and histogram """
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    # Collect raw latency data if not provided
    if latency_data is None:
        client_id = "chart_probe_user"
        password = "chart-probe-pw"
        x, client = setup_isolated_test_user(client_id, password)
        client.post("/oauth/pkce/register",   json={"client_id": client_id, "password": password})
        client.post("/oauth/simple/register", json={"client_id": client_id, "password": password})
        client.post("/authlib/register",      json={"client_id": client_id, "password": password})

        verify_ms:  list[float] = []
        pkce_ms:    list[float] = []
        simple_ms:  list[float] = []
        authlib_ms: list[float] = []
        classic_ms: list[float] = []

        import re as _re2
        from urllib.parse import urlparse as _urlparse2, parse_qs as _parse_qs2
        for _ in range(100):
            # ZKP full login: commit + verify
            server.sessions.clear()
            rand_r = secrets_module.randbelow(server.P - 2) + 1
            t = pow(server.G, rand_r, server.P)
            t0 = time.perf_counter_ns()
            resp = client.post("/login/commit",
                               json={"client_id": client_id, "commitment_t": t})
            p = resp.get_json()
            c = int(p["challenge_c"])
            sid = p["session_id"]
            s = (rand_r + c * x) % server.Q
            client.post("/login/verify",
                        headers={"X-Auth-Session": sid},
                        json={"solution_s": s})
            t1 = time.perf_counter_ns()
            verify_ms.append((t1 - t0) / 1e6)

            # OAuth2 PKCE: GET authorize + POST authorize + token exchange
            code_verifier = secrets_module.token_urlsafe(48)
            challenge = pkce_challenge(code_verifier)
            t0 = time.perf_counter_ns()
            get_r = client.get("/oauth/pkce/authorize", query_string={
                "response_type": "code", "client_id": OAUTH_PKCE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI, "scope": "openid profile",
                "code_challenge": challenge, "code_challenge_method": "S256",
            })
            ar_match = _re2.search(r'name="auth_request_id"\s+value="([^"]+)"',
                                   get_r.data.decode("utf-8") if get_r.status_code == 200 else "")
            ar_id = ar_match.group(1) if ar_match else ""
            post_r = client.post("/oauth/pkce/authorize",
                        data={"auth_request_id": ar_id, "username": client_id, "password": password},
                        follow_redirects=False)
            _loc = post_r.headers.get("Location", "")
            _codes = _parse_qs2(_urlparse2(_loc).query).get("code", [])
            if _codes:
                client.post("/oauth/pkce/token",
                            json={"grant_type": "authorization_code",
                                  "code": _codes[0],
                                  "client_id": OAUTH_PKCE_CLIENT_ID,
                                  "redirect_uri": OAUTH_REDIRECT_URI,
                                  "code_verifier": code_verifier})
            t1 = time.perf_counter_ns()
            pkce_ms.append((t1 - t0) / 1e6)

            # OAuth2 Simple: GET authorize + POST authorize + token exchange
            t0 = time.perf_counter_ns()
            get_r = client.get("/oauth/simple/authorize", query_string={
                "response_type": "code", "client_id": OAUTH_SIMPLE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI, "scope": "openid profile",
            })
            ar_match = _re2.search(r'name="auth_request_id"\s+value="([^"]+)"',
                                   get_r.data.decode("utf-8") if get_r.status_code == 200 else "")
            ar_id = ar_match.group(1) if ar_match else ""
            post_r = client.post("/oauth/simple/authorize",
                        data={"auth_request_id": ar_id, "username": client_id, "password": password},
                        follow_redirects=False)
            _loc = post_r.headers.get("Location", "")
            _codes = _parse_qs2(_urlparse2(_loc).query).get("code", [])
            if _codes:
                client.post("/oauth/simple/token",
                            json={"grant_type": "authorization_code",
                                  "code": _codes[0],
                                  "client_id": OAUTH_SIMPLE_CLIENT_ID,
                                  "redirect_uri": OAUTH_REDIRECT_URI})
            t1 = time.perf_counter_ns()
            simple_ms.append((t1 - t0) / 1e6)

            # Authlib PKCE: authorize + token (form-encoded)
            code_verifier = secrets_module.token_urlsafe(48)
            challenge = pkce_challenge(code_verifier)
            t0 = time.perf_counter_ns()
            ar = client.post("/authlib/oauth/authorize", data={
                "response_type": "code", "client_id": AUTHLIB_CLIENT_ID,
                "redirect_uri": AUTHLIB_REDIRECT_URI, "username": client_id,
                "password": password, "scope": "openid profile",
                "code_challenge": challenge, "code_challenge_method": "S256",
            })
            if ar.status_code == 200:
                client.post("/authlib/oauth/token", data={
                    "grant_type": "authorization_code",
                    "client_id": AUTHLIB_CLIENT_ID,
                    "redirect_uri": AUTHLIB_REDIRECT_URI,
                    "code": ar.get_json()["code"],
                    "code_verifier": code_verifier,
                })
            t1 = time.perf_counter_ns()
            authlib_ms.append((t1 - t0) / 1e6)

            # Classic baseline: SHA-256
            t2 = time.perf_counter_ns()
            hashlib.sha256(password.encode()).hexdigest()
            t3 = time.perf_counter_ns()
            classic_ms.append((t3 - t2) / 1e6)

        latency_data = {
            "verify_ms":  verify_ms,
            "pkce_ms":    pkce_ms,
            "simple_ms":  simple_ms,
            "authlib_ms": authlib_ms,
            "classic_ms": classic_ms,
        }

    verify_ms  = latency_data["verify_ms"]
    pkce_ms    = latency_data.get("pkce_ms", [])
    simple_ms  = latency_data.get("simple_ms", [])
    authlib_ms = latency_data.get("authlib_ms", [])
    classic_ms = latency_data.get("classic_ms", [])

    protocols = [
        (verify_ms,  "ZKP\n(commit+verify)",  "#1565C0"),
        (pkce_ms,    "OAuth2\nPKCE",          "#2E7D32"),
        (simple_ms,  "OAuth2\nSimple",        "#E65100"),
        (authlib_ms, "Authlib\nPKCE",         "#6A1B9A"),
    ]

    # Box plot: per-protocol latency distribution with individual data points
    data_for_box   = [d for d, _, _ in protocols if d]
    labels_for_box = [lbl for d, lbl, _ in protocols if d]
    colors_for_box = [col for d, _, col in protocols if d]
    if data_for_box:
        import statistics as _stats
        import random as _rng

        fig, ax = plt.subplots(figsize=(12, 6))
        ax.set_facecolor("#F9F9F9")
        fig.patch.set_facecolor("#FFFFFF")

        bp = ax.boxplot(
            data_for_box,
            vert=True,
            patch_artist=True,
            widths=0.45,
            medianprops=dict(color="#E53935", linewidth=2.5),
            whiskerprops=dict(linewidth=1.4, linestyle="--"),
            capprops=dict(linewidth=1.8),
            flierprops=dict(marker="x", markersize=5, alpha=0.4),
            showmeans=True,
            meanprops=dict(marker="D", markerfacecolor="white",
                           markeredgecolor="#333333", markersize=7),
        )
        for patch, color in zip(bp["boxes"], colors_for_box):
            patch.set_facecolor(color)
            patch.set_alpha(0.55)

        # Jitter strip -- individual measurements
        for i, (data, color) in enumerate(zip(data_for_box, colors_for_box), start=1):
            jitter = [i + _rng.uniform(-0.18, 0.18) for _ in data]
            ax.scatter(jitter, data, color=color, alpha=0.25, s=10, zorder=3)

        # Annotate median above each box
        for i, data in enumerate(data_for_box, start=1):
            med = _stats.median(data)
            ax.text(i, med, f" {med:.2f}", va="center", ha="left",
                    fontsize=8, color="#E53935", fontweight="bold")

        ax.set_xticks(range(1, len(labels_for_box) + 1))
        ax.set_xticklabels(labels_for_box, fontsize=10)
        ax.set_ylabel("Latenta (ms)", fontsize=11)
        ax.set_title(
            "Distributia latentei per protocol de autentificare\n"
            "(100 masuratori * * = medie * linie rosie = mediana * puncte = valori individuale)",
            fontsize=11,
        )
        ax.grid(axis="y", linestyle="--", alpha=0.5, color="#CCCCCC")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        _save_fig(fig, out / "boxplot_verify_latency.png")

    # Histogram: ZKP verify vs SHA-256 baseline only -- shows zero-knowledge overhead
    # (all-protocol distribution is already covered by the box plot above)
    if verify_ms and classic_ms:
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.set_facecolor("#F9F9F9")
        fig.patch.set_facecolor("#FFFFFF")
        bins = 25
        ax.hist(verify_ms,  bins=bins, alpha=0.70, color="#1565C0",
                label="ZKP (commit+verify)",  edgecolor="white", linewidth=0.4)
        ax.hist(classic_ms, bins=bins, alpha=0.70, color="#E53935",
                label="SHA-256 (clasic)",   edgecolor="white", linewidth=0.4)
        ax.set_xlabel("Latenta (ms)", fontsize=11)
        ax.set_ylabel("Frecventa", fontsize=11)
        ax.set_title(
            "Overhead ZKP vs autentificare clasica (SHA-256)\n"
            "Distributia latentei pe 100 masuratori",
            fontsize=11,
        )
        ax.legend(fontsize=10)
        ax.grid(linestyle="--", alpha=0.4, color="#CCCCCC")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        _save_fig(fig, out / "histogram_zkp_vs_classic.png")


# ---------------------------------------------------------------------------
# Probe 5 - Resource monitor (psutil, runs alongside a live server process)
# ---------------------------------------------------------------------------


# def run_resource_monitor(flask_pid: int, duration_seconds: int = 30,
#                          output_csv: str = str(_GENERATED / "monitor_resources.csv")):
#     """Monitor CPU, RAM, and sessions for a running Flask process."""
#     try:
#         import psutil
#     except ImportError:
#         print("psutil not installed. Run: pip install psutil")
#         return

#     process = psutil.Process(flask_pid)
#     output_path = Path(output_csv)
#     output_path.parent.mkdir(parents=True, exist_ok=True)

#     print(f"Monitoring PID {flask_pid} for {duration_seconds}s -> {output_path}")
#     with output_path.open("w", newline="") as f:
#         writer = csv.writer(f)
#         writer.writerow(["timestamp", "cpu_percent", "ram_mb", "active_sessions"])
#         for _ in range(duration_seconds):
#             ts = time.strftime("%H:%M:%S")
#             cpu = process.cpu_percent(interval=1)
#             ram = process.memory_info().rss / 1024 / 1024
#             sessions = len(server.sessions)
#             writer.writerow([ts, f"{cpu:.2f}", f"{ram:.2f}", sessions])
#             # Note: server.sessions tracks only ZKP in-flight commit sessions.
#             # OAuth2 PKCE / Simple / Authlib sessions are persisted in the DB
#             # (OAuthAuthorizationCode / Token models) and are not held in this
#             # dict, so active_sessions here reflects ZKP state only.
#             expired = [sid for sid, s in server.sessions.items()
#                        if s["created_at"] < time.time() - 5]
#             if expired:
#                 print(f"[{ts}] {len(expired)} session(s) expired and will be cleaned on next verify.")


# ---------------------------------------------------------------------------
# Probe 6 - Comparison charts (requires matplotlib + pandas + CSV data)
# ---------------------------------------------------------------------------

def generate_comparison_charts(
    benchmark_csv: str = str(_GENERATED / "benchmark_results.csv"),
    monitor_csv: str = str(_GENERATED / "monitor_resources.csv"),
    throughput_csv: str = str(_GENERATED / "throughput_results.csv"),
    output_dir: str = str(_GENERATED / "charts"),
):
    try:
        import pandas as pd
    except ImportError:
        print("pandas not installed. Run: pip install pandas")
        return

    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    # Bar chart: mean latency from CSV if available, fallback to fresh benchmark.
    if Path(benchmark_csv).exists():
        df_bench = pd.read_csv(benchmark_csv)
        labels = df_bench["operation"].tolist()
        means = df_bench["mean_ms"].tolist()
    else:
        results = run_micro_benchmark(iterations=100)
        labels = list(results.keys())
        means = [results[k]["mean"] for k in labels]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_facecolor("#F9F9F9")
    fig.patch.set_facecolor("#FFFFFF")
    colors = ["#1565C0", "#2E7D32", "#E65100", "#F44336"]
    bars = ax.bar(range(len(labels)), means,
                  color=colors[:len(labels)], edgecolor="white", linewidth=0.6)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=15, ha="right", fontsize=9)
    ax.set_ylabel("Latenta medie (ms) -- scala logaritmica", fontsize=10)
    ax.set_title("Comparatie latenta componente: ZKP Schnorr vs OAuth2\n"
                 "(scala log -- evidentiaza diferentele de ordine de marime)", fontsize=11)
    ax.set_yscale("log")
    ax.grid(axis="y", linestyle="--", alpha=0.5, color="#CCCCCC", which="both")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for bar, val in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, val * 1.15,
                f"{val:.4f}", ha="center", va="bottom", fontsize=8)
    _save_fig(fig, out / "latency_comparison.png")

    # Line chart: RAM vs active sessions (from monitor CSV)
    if Path(monitor_csv).exists():
        df = pd.read_csv(monitor_csv)
        fig, ax1 = plt.subplots(figsize=(10, 5))
        ax1.plot(df["timestamp"], df["ram_mb"], label="RAM (MB)", color="#2196F3")
        ax1.set_ylabel("RAM (MB)", color="#2196F3")
        ax2 = ax1.twinx()
        ax2.plot(df["timestamp"], df["active_sessions"],
                 label="Sesiuni active", color="#FF9800", linestyle="--")
        ax2.set_ylabel("Sesiuni active", color="#FF9800")
        ax1.set_title("Consum RAM vs Sesiuni active (sessions dict)")
        ax1.tick_params(axis="x", rotation=45, labelsize=7)
        ax1.grid(linestyle="--", alpha=0.4)
        _save_fig(fig, out / "ram_vs_sessions.png")
    else:
        print(f"Monitor CSV not found at {monitor_csv}; skipping RAM chart.")

    # Throughput comparison: all protocols at multiple load levels
    if Path(throughput_csv).exists():
        df_t = pd.read_csv(throughput_csv)
        expected = {"users", "method", "rps"}
        if expected.issubset(set(df_t.columns)):
            pivot = df_t.pivot(index="users", columns="method", values="rps")
            fig, ax = plt.subplots(figsize=(9, 5))
            pivot.plot(kind="bar", ax=ax)
            ax.set_title("Throughput Comparison: RPS ZKP vs OAuth2")
            ax.set_xlabel("Utilizatori concurenti")
            ax.set_ylabel("Requests per second (RPS)")
            ax.grid(axis="y", linestyle="--", alpha=0.4)
            ax.legend(title="Metoda")
            _save_fig(fig, out / "throughput_comparison.png")
        else:
            print(
                f"{throughput_csv} missing required columns {sorted(expected)}; "
                "skipping throughput chart."
            )
    else:
        print(f"Throughput CSV not found at {throughput_csv}; skipping throughput chart.")


# ---------------------------------------------------------------------------
# Probe 8 - Server internals: unmeasured crypto functions + protected endpoints
# ---------------------------------------------------------------------------

def run_server_internals_benchmark(
    iterations: int = 100,
    output_csv: str = str(_GENERATED / "server_internals_results.csv"),
) -> None:
    """
    Measures server.py functions and endpoints not covered by benchmark.py:
      - is_subgroup_member()        pow(value, Q, P) subgroup check
      - _compute_session_binding()  SHA-256 channel binding derivation
      - _compute_challenge()        int.from_bytes + modulo reduction
      - _issue_jwt()                HS256 JWT signing
      - GET  /parameters            public parameters endpoint
      - POST /register              user registration endpoint
      - GET  /data                  protected resource access (requires JWT)
      - POST /data                  protected resource write  (requires JWT)
    Saves server_internals_results.csv.
    """
    import timeit
    import statistics as _stats

    P, Q, G = server.P, server.Q, server.G

    # -- representative inputs -----------------------------------------------
    sample_y = pow(G, 42, P)                 # valid subgroup element
    sample_session_id = "sample-session-abc"
    sample_client_id  = "internals_bench_user"
    sample_binding    = server._compute_session_binding(
        "127.0.0.1", "test-agent", sample_session_id, sample_client_id, sample_y
    )

    def _time(fn, n=iterations):
        times = [timeit.timeit(fn, number=1) * 1000 for _ in range(n)]
        return {
            "mean":  _stats.mean(times),
            "min":   min(times),
            "max":   max(times),
            "p95":   sorted(times)[int(n * 0.95)],
            "stdev": _stats.stdev(times),
        }

    results = {}

    results["is_subgroup_member (ms)"] = _time(
        lambda: server.is_subgroup_member(sample_y)
    )
    results["_compute_session_binding (ms)"] = _time(
        lambda: server._compute_session_binding(
            "127.0.0.1", "test-agent", sample_session_id, sample_client_id, sample_y
        )
    )
    results["_compute_challenge (ms)"] = _time(
        lambda: server._compute_challenge(sample_binding)
    )
    results["_issue_jwt (ms)"] = _time(
        lambda: server._issue_jwt(sample_client_id)
    )

    # -- endpoint latency (Flask test client) --------------------------------
    with server.app.test_client() as c:
        with server.app.app_context():
            x = derive_password_x("internals-bench-pw")
            y = pow(G, x, P)
            existing = server.User.query.filter_by(client_id=sample_client_id).first()
            if not existing:
                server.db.session.add(server.User(client_id=sample_client_id, secret_y=y.to_bytes(256, 'big')))
                server.db.session.commit()

        # GET /parameters
        params_times = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            c.get("/parameters")
            params_times.append((time.perf_counter_ns() - t0) / 1e6)
        results["GET /parameters (ms)"] = {
            "mean":  _stats.mean(params_times),  "min": min(params_times),
            "max":   max(params_times),
            "p95":   sorted(params_times)[int(iterations * 0.95)],
            "stdev": _stats.stdev(params_times),
        }

        # POST /register — fresh client_id each iteration so every call goes
        # through the full path: DB lookup → is_subgroup_member → INSERT.
        reg_times = []
        for i in range(iterations):
            reg_client_id = f"internals_reg_bench_{i}"
            t0 = time.perf_counter_ns()
            c.post("/register", json={"client_id": reg_client_id, "secret_y": str(y)})
            reg_times.append((time.perf_counter_ns() - t0) / 1e6)
        results["POST /register (ms)"] = {
            "mean":  _stats.mean(reg_times),  "min": min(reg_times),
            "max":   max(reg_times),
            "p95":   sorted(reg_times)[int(iterations * 0.95)],
            "stdev": _stats.stdev(reg_times),
        }

        # Obtain a JWT via a single ZKP login for /data measurements
        rand_r = secrets_module.randbelow(P - 2) + 1
        commitment_t = pow(G, rand_r, P)
        server.sessions.clear()
        cr = c.post("/login/commit", json={"client_id": sample_client_id, "commitment_t": commitment_t})
        payload = cr.get_json()
        s = (rand_r + int(payload["challenge_c"]) * x) % Q
        vr = c.post("/login/verify",
                    headers={"X-Auth-Session": payload["session_id"]},
                    json={"solution_s": s})
        jwt_token = vr.get_json().get("token", "")
        auth_header = {"Authorization": f"Bearer {jwt_token}"}

        # Seed one data record so GET /data returns 200
        c.post("/data", headers=auth_header, json={"data": "bench-seed"})

        # GET /data
        data_get_times = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            c.get("/data", headers=auth_header)
            data_get_times.append((time.perf_counter_ns() - t0) / 1e6)
        results["GET /data (ms)"] = {
            "mean":  _stats.mean(data_get_times),  "min": min(data_get_times),
            "max":   max(data_get_times),
            "p95":   sorted(data_get_times)[int(iterations * 0.95)],
            "stdev": _stats.stdev(data_get_times),
        }

        # POST /data
        data_post_times = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            c.post("/data", headers=auth_header, json={"data": "bench-value"})
            data_post_times.append((time.perf_counter_ns() - t0) / 1e6)
        results["POST /data (ms)"] = {
            "mean":  _stats.mean(data_post_times),  "min": min(data_post_times),
            "max":   max(data_post_times),
            "p95":   sorted(data_post_times)[int(iterations * 0.95)],
            "stdev": _stats.stdev(data_post_times),
        }

    out = Path(output_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["operation", "mean_ms", "min_ms", "max_ms", "p95_ms", "stdev_ms"],
        )
        writer.writeheader()
        for op, v in results.items():
            writer.writerow({
                "operation": op,
                "mean_ms":  round(v["mean"],  6),
                "min_ms":   round(v["min"],   6),
                "max_ms":   round(v["max"],   6),
                "p95_ms":   round(v["p95"],   6),
                "stdev_ms": round(v["stdev"], 6),
            })
            print(f"  {op:<40} mean={v['mean']:>8.4f} ms  p95={v['p95']:>8.4f} ms")
    print(f"Saved: {out}")


def _print_locust_stats_table(
    stats_csv: str = str(_GENERATED / "locust_stats.csv"),
) -> None:
    """Parse locust_stats.csv and print the final summary table to stdout."""
    stats_path = Path(stats_csv)
    if not stats_path.exists():
        print(f"[locust table] {stats_csv} not found; skipping.")
        return

    rows = []
    with stats_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    if not rows:
        print("[locust table] stats CSV is empty.")
        return

    # Columns to display and their header labels
    cols = [
        ("Method",          "Type"),
        ("Name",            "Name"),
        ("Request Count",   "# reqs"),
        ("Failure Count",   "# fails"),
        ("Average Response Time", "Avg"),
        ("Min Response Time",     "Min"),
        ("Max Response Time",     "Max"),
        ("Median Response Time",  "Med"),
        ("Requests/s",      "req/s"),
        ("Failures/s",      "failures/s"),
    ]

    csv_keys  = [c[0] for c in cols]
    disp_keys = [c[1] for c in cols]

    widths = [len(h) for h in disp_keys]
    for row in rows:
        for i, key in enumerate(csv_keys):
            val = row.get(key, "")
            widths[i] = max(widths[i], len(val))

    sep = "-+-".join("-" * w for w in widths)
    hdr = " | ".join(h.ljust(widths[i]) for i, h in enumerate(disp_keys))

    print("\n=== Locust final stats ===")
    print(hdr)
    print(sep)
    for row in rows:
        line = " | ".join(
            row.get(key, "").ljust(widths[i])
            for i, key in enumerate(csv_keys)
        )
        print(line)
    print(sep)


def _save_locust_stats_chart(
    stats_csv: str = str(_GENERATED / "locust_stats.csv"),
    output_png: str = str(_GENERATED / "charts" / "locust_protocol_comparison.png"),
) -> None:
    """Generate a bar chart comparing avg/p95 latency per protocol from locust_stats.csv."""
    stats_path = Path(stats_csv)
    if not stats_path.exists():
        print(f"[locust chart] {stats_csv} not found; skipping.")
        return

    rows = []
    with stats_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    # Focus on the 4 login/login-equivalent event rows (custom + HTTP endpoint rows)
    _PROTOCOL_NAMES = {
        "full_zkp_login":        ("ZKP\n(commit+verify)", "#1565C0"),
        "oauth_pkce_login":      ("OAuth2\nPKCE",         "#2E7D32"),
        "oauth_simple_login":    ("OAuth2\nSimple",       "#E65100"),
        "full_authlib_pkce_login": ("Authlib\nPKCE",      "#6A1B9A"),
    }

    selected = []
    for row in rows:
        name = row.get("Name", "").strip()
        if name in _PROTOCOL_NAMES:
            label, color = _PROTOCOL_NAMES[name]
            try:
                avg  = float(row.get("Average Response Time", 0))
                p95  = float(row.get("95%", 0))
                mn   = float(row.get("Min Response Time", 0))
                mx   = float(row.get("Max Response Time", 0))
                rps  = float(row.get("Requests/s", 0))
            except ValueError:
                continue
            selected.append((label, color, avg, p95, mn, mx, rps))

    if not selected:
        print("[locust chart] no protocol login rows found in CSV; skipping chart.")
        return

    labels = [r[0] for r in selected]
    colors = [r[1] for r in selected]
    avgs   = [r[2] for r in selected]
    p95s   = [r[3] for r in selected]
    mins_  = [r[4] for r in selected]
    maxs   = [r[5] for r in selected]

    x = list(range(len(labels)))
    bar_w = 0.35

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor("#FFFFFF")

    # --- left: latency bars (avg + p95) ---
    ax1.set_facecolor("#F9F9F9")
    bars_avg = ax1.bar([i - bar_w / 2 for i in x], avgs, width=bar_w,
                       color=colors, alpha=0.85, label="Avg", edgecolor="white")
    bars_p95 = ax1.bar([i + bar_w / 2 for i in x], p95s, width=bar_w,
                       color=colors, alpha=0.45, label="p95", edgecolor="white", hatch="///")

    # error whiskers: min–max range over the avg bar
    for i, (mn, mx, avg) in enumerate(zip(mins_, maxs, avgs)):
        ax1.errorbar(i - bar_w / 2, avg, yerr=[[avg - mn], [mx - avg]],
                     fmt="none", color="#333333", capsize=4, linewidth=1.2)

    for bar, val in zip(bars_avg, avgs):
        ax1.text(bar.get_x() + bar.get_width() / 2, val + 0.5,
                 f"{val:.1f}", ha="center", va="bottom", fontsize=8, fontweight="bold")
    for bar, val in zip(bars_p95, p95s):
        ax1.text(bar.get_x() + bar.get_width() / 2, val + 0.5,
                 f"{val:.1f}", ha="center", va="bottom", fontsize=8, color="#555555")

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=10)
    ax1.set_ylabel("Latency (ms)", fontsize=11)
    ax1.set_title("Login latency under load\n(solid=avg, hatched=p95, whiskers=min/max)", fontsize=11)
    ax1.legend(fontsize=9)
    ax1.grid(axis="y", linestyle="--", alpha=0.5, color="#CCCCCC")
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    # --- right: requests/s ---
    ax2.set_facecolor("#F9F9F9")
    rps_vals = [r[6] for r in selected]
    bars_rps = ax2.bar(x, rps_vals, color=colors, alpha=0.85, edgecolor="white")
    for bar, val in zip(bars_rps, rps_vals):
        ax2.text(bar.get_x() + bar.get_width() / 2, val + 0.1,
                 f"{val:.2f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=10)
    ax2.set_ylabel("Requests / second", fontsize=11)
    ax2.set_title("Throughput under load\n(req/s per protocol)", fontsize=11)
    ax2.grid(axis="y", linestyle="--", alpha=0.5, color="#CCCCCC")
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    Path(output_png).parent.mkdir(parents=True, exist_ok=True)
    _save_fig(fig, output_png)


# ---------------------------------------------------------------------------
# Pipeline helpers - server lifecycle
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PYTHON       = sys.executable


def _run(label: str, args: list, check: bool = True) -> int:
    print(f"\n[STEP] {label}")
    print(f"[CMD ] {' '.join(str(a) for a in args)}")
    r = subprocess.run(args, cwd=_PROJECT_ROOT)
    if check and r.returncode != 0:
        raise RuntimeError(f"Step failed: {label} (exit {r.returncode})")
    return r.returncode


# All servers use file-based SQLite for a fair comparison (same I/O conditions).
def _start_server(port: int) -> subprocess.Popen:
    db_dir = _PROJECT_ROOT / "server_app" / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_uri = f"sqlite:///{db_dir / f'auth_{port}.db'}"
    env = {**__import__('os').environ, "ACAS_DB_URI": db_uri}
    bootstrap = (
        "import sys; sys.path.insert(0, 'server_app'); "
        "import server; "
        f"server.app.run(host='127.0.0.1', port={port}, debug=False, use_reloader=False)"
    )
    return subprocess.Popen([_PYTHON, "-c", bootstrap], cwd=_PROJECT_ROOT, env=env)


_LOCUST_PORTS = {
    "ZKP":    5000,
    "PKCE":   5001,
    "Simple": 5002,
    "Authlib": 5003,
}


def _start_all_servers() -> list:
    """Start one Flask process per protocol on its dedicated port. Returns list of Popen."""
    procs = []
    for label, port in _LOCUST_PORTS.items():
        print(f"  [start] {label} server on port {port}")
        procs.append(_start_server(port))
    return procs


def _stop_all_servers(procs: list) -> None:
    for proc in procs:
        _stop_server(proc)


def _stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wait_for_health(url: str = "http://127.0.0.1:5000/health", timeout: int = 25) -> bool:
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def _wait_for_all_servers(timeout: int = 40) -> bool:
    """Wait until all 4 server health endpoints respond."""
    import urllib.request
    all_up = {port: False for port in _LOCUST_PORTS.values()}
    deadline = time.time() + timeout
    while time.time() < deadline:
        for port in list(all_up):
            if all_up[port]:
                continue
            try:
                url = f"http://127.0.0.1:{port}/health"
                with urllib.request.urlopen(url, timeout=1) as r:
                    if r.status == 200:
                        all_up[port] = True
                        print(f"  [up] port {port}")
            except Exception:
                pass
        if all(all_up.values()):
            return True
        time.sleep(0.5)
    missing = [p for p, up in all_up.items() if not up]
    print(f"  [timeout] servers not ready on ports: {missing}")
    return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
'''
python.exe qa/measurement/probes.py --run-all 400 60s
'''

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "--help"

    if cmd == "--audit":
        audit_traffic_content()

    elif cmd == "--charts":
        generate_charts()

    # elif cmd == "--monitor":
    #     if len(sys.argv) < 3:
    #         print("Usage: python probes.py --monitor <flask-pid> [duration_seconds]")
    #     else:
    #         run_resource_monitor(int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 30)

    elif cmd == "--comparison-charts":
        generate_comparison_charts()

    elif cmd == "--server-internals":
        run_server_internals_benchmark()

    elif cmd == "--offline":
        
        print("\n=== offline measurements ===")
        _run("benchmark.py (latency + throughput CSVs)",[_PYTHON, "qa/measurement/benchmark.py"])
        audit_traffic_content()
        generate_charts()
        run_server_internals_benchmark()
        generate_comparison_charts()
    
    elif cmd == "--locust":
        # Optional args: --run-all [locust_users] [locust_runtime]
        # e.g.  python probes.py --run-all 100 60s
        locust_users   = int(sys.argv[2]) if len(sys.argv) > 2 else 100
        locust_runtime = sys.argv[3]      if len(sys.argv) > 3 else "60s"

        # -- Phase 2: live server required -----------------------------------
        print("\n=== Phase 2: live-server measurements (4 dedicated servers) ===")
        # Remove stale Locust CSV files so Locust can create them fresh
        for _stale in _GENERATED.glob("locust*.csv"):
            try:
                _stale.unlink()
            except OSError as _e:
                print(f"  [warn] could not delete {_stale}: {_e}")
        server_procs = []
        try:
            server_procs = _start_all_servers()
            print("[*] Waiting for all 4 servers to become healthy ...")
            if not _wait_for_all_servers(timeout=40):
                raise RuntimeError("One or more servers did not respond in time")

            # Run Locust -- no --host; each HttpUser class has its own host
            # --csv writes locust_stats.csv / locust_failures.csv etc.
            _run(
                f"Locust load test ({locust_users} users, {locust_runtime})",
                [
                    "locust",
                    "-f", "qa/measurement/locustfile.py",
                    f"--users={locust_users}",
                    "--spawn-rate=10",
                    "--headless",
                    f"--run-time={locust_runtime}",
                    "--html", "qa/measurement/generated/locust_report.html",
                    "--csv",  "qa/measurement/generated/locust",
                ],
                check=False,
            )
        finally:
            _stop_all_servers(server_procs)

        # -- Phase 3: post-processing (CSVs now available) --------------------
        print("\n=== Phase 3: comparison charts ===")
        generate_comparison_charts()
        _print_locust_stats_table()
        _save_locust_stats_chart()
        print("\nDone. All measurements complete.")

    else:
        print("Usage: python probes.py [--audit|--snippets|--charts|--comparison-charts")
        print("                        |--monitor <pid> [secs]|--all")
        print("                        |--run-all [users=50] [runtime=60s]]")
        print("       ZKP latency table: python qa/measurement/benchmark.py --latency")

