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
import matplotlib.style as mstyle


_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))
from qa_utils import (
    server, SERVER_MODULE_PATH,
    derive_password_x, pkce_challenge,
    OAUTH_PKCE_CLIENT_ID, OAUTH_SIMPLE_CLIENT_ID, OAUTH_REDIRECT_URI,
    AUTHLIB_CLIENT_ID, AUTHLIB_REDIRECT_URI,
)
from measurement_utils import setup_isolated_test_user
from benchmark import (
    _benchmark_latency as run_micro_benchmark,
    run_throughput_sweep,
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
    session_id = payload["session_id"]
    s = (rand_r + c * x) % server.Q
    verify_body = {"solution_s": str(s)}

    classic_example_body = {"client_id": client_id, "password": password}

    # OAuth2 PKCE bodies (static representation of what travels over the wire)
    code_verifier = secrets_module.token_urlsafe(48)
    code_challenge = pkce_challenge(code_verifier)
    pkce_authorize_body = {
        "response_type": "code",
        "client_id": OAUTH_PKCE_CLIENT_ID,
        "username": client_id,
        "password": password,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    pkce_token_body = {
        "grant_type": "authorization_code",
        "client_id": OAUTH_PKCE_CLIENT_ID,
        "code": "<opaque-auth-code>",
        "code_verifier": code_verifier,
    }

    # OAuth2 Simple bodies
    simple_authorize_body = {
        "response_type": "code",
        "client_id": OAUTH_SIMPLE_CLIENT_ID,
        "username": client_id,
        "password": password,
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
        "## POST /oauth/pkce/authorize (OAuth2 PKCE Step 1)",
        "```json",
        _truncate(pkce_authorize_body),
        "```",
        "Nota: parola este trimisa catre authorization server (acelasi domeniu), nu catre client.",
        "",
        "## POST /oauth/pkce/token (OAuth2 PKCE Step 2 - code exchange)",
        "```json",
        _truncate(pkce_token_body),
        "```",
        "Nota: code_verifier este un secret de scurta durata, parola nu mai apare in aceasta cerere.",
        "",
        "## POST /oauth/simple/authorize (OAuth2 Simple Step 1)",
        "```json",
        _truncate(simple_authorize_body),
        "```",
        "Nota: parola este trimisa catre authorization server, fara PKCE.",
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
# Probe 3 -  Extract parts of server.py that ensure a protection for some attacks
# # Ex: is_subgroup_member / del sessions[...] (Replay) / secrets.randbelow (entropy)
# TODO: Manual
# ---------------------------------------------------------------------------

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

        for _ in range(100):
            # ZKP /login/verify
            server.sessions.clear()
            rand_r = secrets_module.randbelow(server.P - 2) + 1
            t = pow(server.G, rand_r, server.P)
            resp = client.post("/login/commit",
                               json={"client_id": client_id, "commitment_t": t})
            p = resp.get_json()
            c = int(p["challenge_c"])
            sid = p["session_id"]
            s = (rand_r + c * x) % server.Q
            t0 = time.perf_counter_ns()
            client.post("/login/verify",
                        headers={"X-Auth-Session": sid},
                        json={"solution_s": s})
            t1 = time.perf_counter_ns()
            verify_ms.append((t1 - t0) / 1e6)

            # OAuth2 PKCE: authorize + token
            code_verifier = secrets_module.token_urlsafe(48)
            challenge = pkce_challenge(code_verifier)
            t0 = time.perf_counter_ns()
            ar = client.post("/oauth/pkce/authorize", json={
                "response_type": "code", "client_id": OAUTH_PKCE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI, "username": client_id,
                "password": password, "scope": "openid profile",
                "code_challenge": challenge, "code_challenge_method": "S256",
                "response_mode": "json",
            })
            if ar.status_code == 200:
                client.post("/oauth/pkce/token", json={
                    "grant_type": "authorization_code",
                    "client_id": OAUTH_PKCE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "code": ar.get_json()["code"],
                    "code_verifier": code_verifier,
                })
            t1 = time.perf_counter_ns()
            pkce_ms.append((t1 - t0) / 1e6)

            # OAuth2 Simple: authorize + token
            t0 = time.perf_counter_ns()
            ar = client.post("/oauth/simple/authorize", json={
                "response_type": "code", "client_id": OAUTH_SIMPLE_CLIENT_ID,
                "redirect_uri": OAUTH_REDIRECT_URI, "username": client_id,
                "password": password, "scope": "openid profile",
                "response_mode": "json",
            })
            if ar.status_code == 200:
                client.post("/oauth/simple/token", json={
                    "grant_type": "authorization_code",
                    "client_id": OAUTH_SIMPLE_CLIENT_ID,
                    "redirect_uri": OAUTH_REDIRECT_URI,
                    "code": ar.get_json()["code"],
                })
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
        (verify_ms,  "ZKP\n/login/verify",  "#1565C0"),
        (pkce_ms,    "OAuth2\nPKCE",        "#2E7D32"),
        (simple_ms,  "OAuth2\nSimple",      "#E65100"),
        (authlib_ms, "Authlib\nPKCE",       "#6A1B9A"),
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
                label="ZKP /login/verify",  edgecolor="white", linewidth=0.4)
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
# TODO: This monitor requires a live Flask server process.
#       Run it as: python qa/measurement/main_probes.py --monitor <flask-pid>
#       It will record CPU/RAM/sessions to monitor_resources.csv every second.

def run_resource_monitor(flask_pid: int, duration_seconds: int = 30,
                         output_csv: str = str(_GENERATED / "monitor_resources.csv")):
    """Monitor CPU, RAM, and sessions for a running Flask process."""
    try:
        import psutil
    except ImportError:
        print("psutil not installed. Run: pip install psutil")
        return

    process = psutil.Process(flask_pid)
    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Monitoring PID {flask_pid} for {duration_seconds}s -> {output_path}")
    with output_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "cpu_percent", "ram_mb", "active_sessions"])
        for _ in range(duration_seconds):
            ts = time.strftime("%H:%M:%S")
            cpu = process.cpu_percent(interval=1)
            ram = process.memory_info().rss / 1024 / 1024
            sessions = len(server.sessions)
            writer.writerow([ts, f"{cpu:.2f}", f"{ram:.2f}", sessions])
            # Note: server.sessions tracks only ZKP in-flight commit sessions.
            # OAuth2 PKCE / Simple / Authlib sessions are persisted in the DB
            # (OAuthAuthorizationCode / Token models) and are not held in this
            # dict, so active_sessions here reflects ZKP state only.
            expired = [sid for sid, s in server.sessions.items()
                       if s["created_at"] < time.time() - 5]
            if expired:
                print(f"[{ts}] {len(expired)} session(s) expired and will be cleaned on next verify.")


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
# Probe 7 - Session memory footprint under commit flood
# ---------------------------------------------------------------------------

def run_memory_footprint_benchmark(
    batches: tuple = (100, 500, 1000),
    output_csv: str = str(_GENERATED / "memory_footprint_results.csv"),
) -> None:
    """
    Send commits in increasing batch sizes and measure the server sessions dict
    memory footprint (shallow, deep, tracemalloc) after each batch.
    Saves memory_footprint_results.csv.
    """
    import sys as _sys
    import tracemalloc

    def _deep_sizeof(obj, seen=None):
        if seen is None:
            seen = set()
        oid = id(obj)
        if oid in seen:
            return 0
        seen.add(oid)
        size = _sys.getsizeof(obj)
        if isinstance(obj, dict):
            size += sum(_deep_sizeof(k, seen) + _deep_sizeof(v, seen) for k, v in obj.items())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            size += sum(_deep_sizeof(i, seen) for i in obj)
        return size

    password = "flood-probe-pass"
    client_id = "flood_probe_user"
    rows = []

    with server.app.test_client() as c:
        with server.app.app_context():
            x, _ = derive_password_x(password)
            y = pow(server.G, x, server.P)
            server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
            server.db.session.commit()

        for batch in batches:
            server.sessions.clear()
            tracemalloc.start()

            for _ in range(batch):
                rand_r = secrets_module.randbelow(server.P - 2) + 1
                t = pow(server.G, rand_r, server.P)
                c.post("/login/commit", json={"client_id": client_id, "commitment_t": t})

            current_mem, peak_mem = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            deep_size = _deep_sizeof(server.sessions)
            row = {
                "batch": batch,
                "shallow_bytes": _sys.getsizeof(server.sessions),
                "deep_bytes": deep_size,
                "tracemalloc_current_kb": current_mem // 1024,
                "tracemalloc_peak_kb": peak_mem // 1024,
                "active_entries": len(server.sessions),
            }
            rows.append(row)
            print(
                f"After {batch:>5} commits: "
                f"shallow={row['shallow_bytes']} B, "
                f"deep={row['deep_bytes']} B, "
                f"tracemalloc current={row['tracemalloc_current_kb']} KB "
                f"peak={row['tracemalloc_peak_kb']} KB, "
                f"active entries={row['active_entries']}"
            )

    out = Path(output_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["batch", "shallow_bytes", "deep_bytes",
                        "tracemalloc_current_kb", "tracemalloc_peak_kb", "active_entries"],
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Saved: {out}")


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
            x, _ = derive_password_x("internals-bench-pw")
            y = pow(G, x, P)
            existing = server.User.query.filter_by(client_id=sample_client_id).first()
            if not existing:
                server.db.session.add(server.User(client_id=sample_client_id, secret_y=str(y)))
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

        # POST /register (first call creates, rest return 409 -- measures full path)
        reg_client_id = "internals_reg_bench_user"
        reg_times = []
        for _ in range(iterations):
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


def _start_server() -> subprocess.Popen:
    bootstrap = (
        "import sys; sys.path.insert(0, 'server_app'); "
        "import server; "
        "server.app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)"
    )
    return subprocess.Popen([_PYTHON, "-c", bootstrap], cwd=_PROJECT_ROOT)


def _stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wait_for_health(url: str = "http://127.0.0.1:5000/health", timeout: int = 25) -> bool:
    import urllib.request
    import urllib.error
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
'''
python.exe qa/measurement/probes.py --run-all 100 60s
'''

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "--help"

    if cmd == "--audit":
        audit_traffic_content()

    elif cmd == "--charts":
        generate_charts()

    elif cmd == "--monitor":
        if len(sys.argv) < 3:
            print("Usage: python probes.py --monitor <flask-pid> [duration_seconds]")
        else:
            run_resource_monitor(int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 30)

    elif cmd == "--comparison-charts":
        generate_comparison_charts()

    elif cmd == "--server-internals":
        run_server_internals_benchmark()

    elif cmd == "--all-offline":
        audit_traffic_content()
        generate_charts()
        generate_comparison_charts()
        run_memory_footprint_benchmark()
        run_server_internals_benchmark()

    elif cmd == "--run-all":
        # Optional args: --run-all [locust_users] [locust_runtime]
        # e.g.  python probes.py --run-all 100 60s
        locust_users   = int(sys.argv[2]) if len(sys.argv) > 2 else 100
        locust_runtime = sys.argv[3]      if len(sys.argv) > 3 else "60s"
        monitor_secs   = int(locust_runtime.rstrip("s")) if locust_runtime.endswith("s") else int(locust_runtime)

        # -- Phase 1: no live server required --------------------------------
        print("\n=== Phase 1: offline measurements ===")
        _run("benchmark.py (latency + throughput CSVs)",[_PYTHON, "qa/measurement/benchmark.py"])
        audit_traffic_content()
        generate_charts()
        run_memory_footprint_benchmark()
        run_server_internals_benchmark()

        # -- Phase 2: live server required -----------------------------------
        print("\n=== Phase 2: live-server measurements ===")
        server_proc = _start_server()
        try:
            print("[*] Waiting 5 s for server to start ...")
            time.sleep(5)
            if not _wait_for_health(timeout=20):
                raise RuntimeError("Server did not respond on http://127.0.0.1:5000/health")

            # Start resource monitor in background (separate process)
            monitor_proc = subprocess.Popen(
                [_PYTHON, str(Path(__file__).resolve()),
                 "--monitor", str(server_proc.pid), str(monitor_secs)],
                cwd=_PROJECT_ROOT,
            )

            # Run Locust load test (blocks until done)
            _run(
                f"Locust load test ({locust_users} users, {locust_runtime})",
                [
                    "locust",
                    "-f", "qa/measurement/locustfile.py",
                    "--host=http://localhost:5000",
                    f"--users={locust_users}",
                    "--spawn-rate=10",
                    "--headless",
                    f"--run-time={locust_runtime}",
                    "--html", "qa/measurement/generated/locust_report.html",
                ],
                check=False,
            )

            monitor_proc.wait()  # ensure monitor finishes writing CSV
        finally:
            _stop_server(server_proc)

        # -- Phase 3: post-processing (CSVs now available) --------------------
        print("\n=== Phase 3: comparison charts ===")
        generate_comparison_charts()
        print("\nDone. All measurements complete.")

    else:
        print("Usage: python probes.py [--audit|--snippets|--charts|--comparison-charts")
        print("                        |--monitor <pid> [secs]|--all")
        print("                        |--run-all [users=50] [runtime=60s]]")
        print("       ZKP latency table: python qa/measurement/benchmark.py --latency")

