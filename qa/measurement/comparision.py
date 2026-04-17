"""
Measurement & comparison scripts for the Schnorr ZKP vs Classic authentication.

Prompt 1  – /login/classic baseline (SHA-256 password check + JWT)
Prompt 2  – Client-side micro-benchmark (JS snippet + Python equivalent)
Prompt 3  – CPU/RAM resource monitor using psutil (requires live server)
Prompt 4  – Locust throughput comparison (requires locust + live server)
Prompt 5  – Statistical analysis & chart generation (requires matplotlib/pandas)
"""

from pathlib import Path
import csv
import hashlib
import importlib.util
import secrets as secrets_module
import statistics
import sys
import time
import timeit

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_APP_PATH = PROJECT_ROOT / "server_app"
SERVER_MODULE_PATH = SERVER_APP_PATH / "server.py"
if str(SERVER_APP_PATH) not in sys.path:
    sys.path.insert(0, str(SERVER_APP_PATH))
spec = importlib.util.spec_from_file_location("server", SERVER_MODULE_PATH)
server = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(server)


CLASSIC_PASSWORD_HASHES = {}


# ---------------------------------------------------------------------------
# Prompt 1 – /login/classic baseline endpoint
# ---------------------------------------------------------------------------

def ensure_classic_endpoint():
    """Register /login/classic on the running app if not already present."""
    import jwt as _jwt

    existing = [r.rule for r in server.app.url_map.iter_rules()]
    if "/login/classic" in existing:
        return

    @server.app.route("/login/classic", methods=["POST"])
    def classic_login():
        from flask import request, jsonify
        data = request.get_json() or {}
        client_id = data.get("client_id")
        password = data.get("password")
        if not client_id or not password:
            return jsonify({"reason": "missing parameters"}), 400
        user = server.User.query.filter_by(client_id=client_id).first()
        if not user:
            return jsonify({"reason": "user not found"}), 404
        stored_hash = CLASSIC_PASSWORD_HASHES.get(client_id)
        if stored_hash is None:
            return jsonify({"reason": "classic auth not set up"}), 404
        if hashlib.sha256(password.encode()).hexdigest() != stored_hash:
            return jsonify({"reason": "invalid credentials"}), 401
        token = _jwt.encode({"client_id": client_id}, server.SECRET, algorithm="HS256")
        return jsonify({"token": token}), 200


ensure_classic_endpoint()


# ---------------------------------------------------------------------------
# Prompt 2 – Micro-benchmark: ZKP components vs Classic hash
# ---------------------------------------------------------------------------

def run_micro_benchmark(iterations: int = 100) -> dict:
    P, Q, G = server.P, server.Q, server.G

    def derive():
        salt = secrets_module.token_bytes(16)
        h = hashlib.scrypt(b"bench-password", salt=salt, n=2**11, r=8, p=1)
        return int.from_bytes(h, "big") % Q

    x = derive()
    y = pow(G, x, P)
    r = secrets_module.randbelow(P - 2) + 1
    t = pow(G, r, P)
    c = secrets_module.randbelow(Q - 1) + 1
    s = (r + c * x) % Q

    def commit_math():
        _r = secrets_module.randbelow(P - 2) + 1
        return pow(G, _r, P)

    def verify_math():
        left = pow(G, s, P)
        right = (t * pow(y, c, P)) % P
        return left == right

    def classic_hash():
        return hashlib.sha256(b"bench-password").hexdigest()

    ops = {
        "derive_password_x (scrypt)": derive,
        "commitment_t = g^r mod p": commit_math,
        "ZKP verify: g^s == t*y^c mod p": verify_math,
        "Classic SHA-256 hash": classic_hash,
    }

    results = {}
    for name, fn in ops.items():
        samples = [timeit.timeit(fn, number=1) * 1000 for _ in range(iterations)]
        results[name] = {
            "mean": statistics.mean(samples),
            "min": min(samples),
            "max": max(samples),
            "p95": sorted(samples)[int(iterations * 0.95)],
            "stdev": statistics.stdev(samples),
        }
    return results


def print_benchmark_table(results: dict):
    header = (
        f"| {'Operation':<42} | {'Mean':>8} | {'Min':>8}"
        f" | {'Max':>8} | {'P95':>8} | {'StdDev':>8} | Unit |"
    )
    sep = "|" + "-" * 44 + "|" + ("-" * 10 + "|") * 5 + "------|"
    print(header)
    print(sep)
    for op, v in results.items():
        print(
            f"| {op:<42} | {v['mean']:>8.4f} | {v['min']:>8.4f}"
            f" | {v['max']:>8.4f} | {v['p95']:>8.4f} | {v['stdev']:>8.4f} | ms   |"
        )


# ---------------------------------------------------------------------------
# Prompt 3 – Resource monitor (psutil, runs alongside a live server process)
# ---------------------------------------------------------------------------
# TODO: This monitor requires a live Flask server process.
#       Run it as: python qa/measurement/comparision.py --monitor <flask-pid>
#       It will record CPU/RAM/sessions to monitor_resources.csv every second.

def run_resource_monitor(flask_pid: int, duration_seconds: int = 30,
                         output_csv: str = "monitor_resources.csv"):
    """Monitor CPU, RAM, and sessions for a running Flask process."""
    try:
        import psutil
    except ImportError:
        print("psutil not installed. Run: pip install psutil")
        return

    process = psutil.Process(flask_pid)
    output_path = Path(output_csv)

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
            expired = [sid for sid, s in server.sessions.items()
                       if s["created_at"] < time.time() - 5]
            if expired:
                print(f"[{ts}] {len(expired)} session(s) expired and will be cleaned on next verify.")


# ---------------------------------------------------------------------------
# Prompt 4 – Locust throughput comparison
# ---------------------------------------------------------------------------
# TODO: Locust requires a live server process and cannot be driven from here.
#       Steps:
#         1. pip install locust
#         2. python server_app/server.py
#         3. locust -f qa/measurement/comparision.py --host=http://localhost:5000
#                   --users 100 --spawn-rate 10 --headless --run-time 60s
#                   --html locust_throughput_report.html

try:
    from locust import HttpUser, task, between

    class ThroughputComparisonUser(HttpUser):
        wait_time = between(0.3, 1.0)

        def on_start(self):
            self._client_id = f"locust_{secrets_module.token_hex(8)}"
            self._password = secrets_module.token_hex(16)
            salt = secrets_module.token_bytes(16)
            hashed = hashlib.scrypt(
                self._password.encode(), salt=salt, n=2**11, r=8, p=1
            )
            self._x = int.from_bytes(hashed, "big") % server.Q
            self._y = pow(server.G, self._x, server.P)
            self.client.post(
                "/register",
                json={"client_id": self._client_id, "secret_y": self._y},
            )
            CLASSIC_PASSWORD_HASHES[self._client_id] = hashlib.sha256(
                self._password.encode()
            ).hexdigest()

        @task(2)
        def test_schnorr_login(self):
            rand_r = secrets_module.randbelow(server.P - 2) + 1
            t = pow(server.G, rand_r, server.P)
            commit = self.client.post(
                "/login/commit",
                json={"client_id": self._client_id, "commitment_t": t},
                name="/login/commit",
            )
            if commit.status_code != 200:
                return
            payload = commit.json()
            c = int(payload["challenge_c"])
            session_id = payload["session_id"]
            s = (rand_r + c * self._x) % server.Q
            self.client.post(
                "/login/verify",
                headers={"X-Auth-Session": session_id},
                json={"solution_s": s},
                name="/login/verify",
            )

        @task(1)
        def test_classic_login(self):
            self.client.post(
                "/login/classic",
                json={"client_id": self._client_id, "password": self._password},
                name="/login/classic",
            )

except ImportError:
    pass


# ---------------------------------------------------------------------------
# Prompt 5 – Statistical charts (requires matplotlib + pandas + CSV data)
# ---------------------------------------------------------------------------
# TODO: Run this after collecting data with run_micro_benchmark() and
#       run_resource_monitor() to generate charts for the dissertation.
#       Requires: pip install matplotlib pandas

def generate_charts(
    benchmark_csv: str = "benchmark_results.csv",
    monitor_csv: str = "monitor_resources.csv",
    throughput_csv: str = "throughput_results.csv",
    output_dir: str = "charts",
):
    try:
        import pandas as pd
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib/pandas not installed. Run: pip install matplotlib pandas")
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
    bars = ax.bar(range(len(labels)), means, color=["#2196F3", "#4CAF50", "#FF9800", "#F44336"])
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=15, ha="right", fontsize=9)
    ax.set_ylabel("Latenta medie (ms)")
    ax.set_title("Comparatie latenta: ZKP Schnorr vs Clasic")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    for bar, val in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.002,
                f"{val:.4f}", ha="center", va="bottom", fontsize=8)
    plt.tight_layout()
    fig.savefig(out / "latency_comparison.png", dpi=300)
    print(f"Saved: {out / 'latency_comparison.png'}")
    plt.close(fig)

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
        fig.tight_layout()
        fig.savefig(out / "ram_vs_sessions.png", dpi=300)
        print(f"Saved: {out / 'ram_vs_sessions.png'}")
        plt.close(fig)
    else:
        print(f"Monitor CSV not found at {monitor_csv}; skipping RAM chart.")

    # Throughput comparison: ZKP vs Classic at multiple load levels
    if Path(throughput_csv).exists():
        df_t = pd.read_csv(throughput_csv)
        expected = {"users", "method", "rps"}
        if expected.issubset(set(df_t.columns)):
            pivot = df_t.pivot(index="users", columns="method", values="rps")
            fig, ax = plt.subplots(figsize=(9, 5))
            pivot.plot(kind="bar", ax=ax)
            ax.set_title("Throughput Comparison: RPS ZKP vs Clasic")
            ax.set_xlabel("Utilizatori concurenti")
            ax.set_ylabel("Requests per second (RPS)")
            ax.grid(axis="y", linestyle="--", alpha=0.4)
            ax.legend(title="Metoda")
            fig.tight_layout()
            fig.savefig(out / "throughput_comparison.png", dpi=300)
            print(f"Saved: {out / 'throughput_comparison.png'}")
            plt.close(fig)
        else:
            print(
                f"{throughput_csv} missing required columns {sorted(expected)}; "
                "skipping throughput chart."
            )
    else:
        print(f"Throughput CSV not found at {throughput_csv}; skipping throughput chart.")


# ---------------------------------------------------------------------------
# Entry point: run benchmark + print table when executed directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys as _sys
    if len(_sys.argv) > 1 and _sys.argv[1] == "--monitor":
        if len(_sys.argv) < 3:
            print("Usage: python comparision.py --monitor <flask-pid> [duration_seconds]")
        else:
            pid = int(_sys.argv[2])
            dur = int(_sys.argv[3]) if len(_sys.argv) > 3 else 30
            run_resource_monitor(pid, dur)
    elif len(_sys.argv) > 1 and _sys.argv[1] == "--charts":
        generate_charts()
    else:
        print("Running micro-benchmark (100 iterations)...")
        data = run_micro_benchmark(iterations=100)
        print_benchmark_table(data)


'''
1. Prompt pentru Implementarea OAuth Local (Baseline)
Acesta este primul pas necesar pentru a avea un termen de comparație valid.
"Acționează ca un Backend Developer. Adaugă în server.py un endpoint nou /login/classic pentru a simula un flux de autentificare tradițional.
Endpoint-ul trebuie să primească client_id și password în clar.
Folosește librăria bcrypt pentru a verifica parola (simulează extragerea hash-ului din baza de date și verificarea lui).
Dacă verificarea reușește, returnează un JWT identic cu cel din fluxul Schnorr.
Include header-ul X-Response-Time pentru a măsura latența acestui proces.
Asigură-te că endpoint-ul este izolat și nu afectează logica ZKP existentă."

2. Prompt pentru Micro-Benchmarking Client-Side (JS)
Măsurarea costului computațional pe dispozitivul utilizatorului este critică pentru ZKP, deoarece mută efortul de la server la client.
"Scrie un script de test în JavaScript (care poate fi rulat în consola browserului sau integrat în auth.js) pentru a măsura performanța operațiunilor criptografice pe client:
Măsoară timpul necesar pentru 100 de iterații ale funcției modPow folosind numere de 2048 biți.
Măsoară timpul pentru derivarea parolei folosind derivePasswordX (SHA-256).
Calculează media, minimul și maximul în milisecunde.
Rezultatele trebuie să fie afișate într-un tabel formatat în consolă, gata pentru a fi incluse în documentația de performanță."

3. Prompt pentru Profilarea Consumului de Resurse (CPU/RAM)
O critică comună a sistemelor stateful (care mențin sesiuni în memorie) este consumul de RAM sub asediu.
"Scrie un script Python de monitorizare (monitor_resources.py) care să ruleze în paralel cu serverul Flask în timpul testelor de sarcină:
Folosește librăria psutil pentru a înregistra consumul de CPU (%) și RAM (MB) al procesului Flask.
Măsoară dimensiunea obiectului sessions (numărul de intrări active) la fiecare secundă.
Salvează datele într-un fișier CSV cu timestamp-uri.
Scriptul trebuie să poată detecta momentul în care sesiunile expiră (după cele 5 secunde setate) și să evidențieze eliberarea memoriei."

4. Prompt pentru Teste de Sarcină (Locust - Throughput)Acesta generează scriptul pentru a măsura câte cereri pe secundă (RPS) poate duce serverul tău."Creează un fișier locustfile.py pentru a compara Throughput-ul celor două metode:Definește două task-uri: test_schnorr_login (care face fluxul /login/commit urmat de /login/verify) și test_classic_login (care apelează /login/classic).Pentru test_schnorr_login, simulează corect logica de client: primește challenge-ul și calculează soluția $s$ înainte de a trimite verificarea.Configurează Locust să ruleze teste incrementale (10, 50, 100 de utilizatori concurenți).Raportul final trebuie să compare Requests Per Second (RPS) și Failure Rate pentru ambele metode."

5. Prompt pentru Analiza Statistică și Vizualizare (Grafice)
După ce ai datele, ai nevoie de o modalitate de a le prezenta academic.
"Scrie un script Python folosind pandas și matplotlib care să preia rezultatele din testele anterioare (CSV-uri) și să genereze următoarele grafice pentru disertație:
Bar Chart: Compararea latenței medii (ms) între Schnorr Verify și Bcrypt Verify.
Line Chart: Evoluția consumului de RAM în funcție de numărul de sesiuni active în dicționarul sessions.
Throughput Comparison: Un grafic care să arate RPS pentru ZKP vs Clasic la diferite niveluri de sarcină.
Salvează imaginile la rezoluție înaltă (300 DPI) potrivite pentru print."


'''