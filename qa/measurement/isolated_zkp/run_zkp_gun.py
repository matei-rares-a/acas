"""
Runner izolat — ZKP pe port 5200, fara competitie cu alte servere.

Strategie multi-proces (GIL separat per worker):
  Linux / WSL : Gunicorn  --  fork-based, _WORKERS procese pe portul _PORT
  Windows     : _WORKERS procese Flask/waitress pe porturile interne
                (_PORT+1 .. _PORT+_WORKERS) + proxy TCP round-robin pe _PORT

Utilizare:
    python qa/measurement/isolated_zkp/run_zkp.py [users] [runtime]

Exemple:
    python qa/measurement/isolated_zkp/run_zkp.py 100 60s
    python qa/measurement/isolated_zkp/run_zkp.py 400 120s
"""
import itertools
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ISOLATED_DIR = Path(__file__).resolve().parent
_GENERATED    = _ISOLATED_DIR / "generated"
_GENERATED.mkdir(parents=True, exist_ok=True)

_PYTHON      = sys.executable
_PORT        = 5200
_WORKERS     = 4  # procese independente — GIL separat per worker
_IS_WINDOWS  = platform.system() == "Windows"
# Porturi interne folosite de workerii Windows (5201, 5202, 5203, 5204)
_WORKER_PORTS = [_PORT + 1 + i for i in range(_WORKERS)]


# ---------------------------------------------------------------------------
# Linux / WSL  —  Gunicorn (fork-based, GIL separat per worker)
# ---------------------------------------------------------------------------

def _start_gunicorn() -> subprocess.Popen:
    db_dir = _PROJECT_ROOT / "server_app" / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_uri = f"sqlite:///{db_dir / f'auth_{_PORT}.db'}"
    env = {**os.environ, "ACAS_DB_URI": db_uri}
    print(f"[start] Flask/Gunicorn pe port {_PORT} ({_WORKERS} workers, SQLite)")
    return subprocess.Popen(
        [
            _PYTHON, "-m", "gunicorn",
            f"--workers={_WORKERS}",
            "--worker-class=sync",
            f"--bind=127.0.0.1:{_PORT}",
            "--chdir", str(_PROJECT_ROOT / "server_app"),
            "server:app",
        ],
        cwd=_PROJECT_ROOT,
        env=env,
    )


# ---------------------------------------------------------------------------
# Windows  —  N procese Flask/waitress pe porturi interne
# ---------------------------------------------------------------------------

def _start_windows_workers() -> list:
    """
    Porneste _WORKERS procese Python independente, fiecare cu propriul GIL.
    Fiecare proces ruleaza waitress pe un port intern diferit.
    Parametrii sunt transmisi prin variabile de mediu (evita probleme de escapare).
    """
    db_dir = _PROJECT_ROOT / "server_app" / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_uri  = f"sqlite:///{db_dir / f'auth_{_PORT}.db'}"
    srv_dir = str(_PROJECT_ROOT / "server_app")

    # Script inline: importa app din server_app, porneste waitress pe portul dat
    inline = (
        "import os, sys; "
        "sys.path.insert(0, os.environ['_ACAS_SRV']); "
        "from server import app; "
        "from waitress import serve; "
        "serve(app, host='127.0.0.1', port=int(os.environ['_ACAS_PORT']), "
        "      threads=1, channel_timeout=30, connection_limit=300)"
    )

    print(f"[start] {_WORKERS} procese Flask/waitress pe porturile {_WORKER_PORTS} (Windows)")
    procs = []
    for port in _WORKER_PORTS:
        worker_env = {
            **os.environ,
            "ACAS_DB_URI": db_uri,
            "_ACAS_SRV":   srv_dir,
            "_ACAS_PORT":  str(port),
        }
        procs.append(
            subprocess.Popen([_PYTHON, "-c", inline], cwd=_PROJECT_ROOT, env=worker_env)
        )
    return procs


# ---------------------------------------------------------------------------
# Proxy TCP round-robin  (folosit doar pe Windows)
# ---------------------------------------------------------------------------

def _pump(src: socket.socket, dst: socket.socket) -> None:
    """Copiaza date src -> dst pana la inchiderea conexiunii."""
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _start_proxy(listen_port: int, backends: list) -> socket.socket:
    """
    Proxy TCP round-robin: conexiunile HTTP keep-alive merg integral la
    acelasi backend (corect pentru HTTP/1.1).
    Returneaza socket-ul server pentru a-l inchide la cleanup.
    """
    pool = itertools.cycle(backends)
    lock = threading.Lock()

    def _next_port() -> int:
        with lock:
            return next(pool)

    def _handle(client: socket.socket) -> None:
        try:
            backend = socket.create_connection(("127.0.0.1", _next_port()), timeout=10)
        except OSError:
            client.close()
            return
        threading.Thread(target=_pump, args=(client, backend), daemon=True).start()
        threading.Thread(target=_pump, args=(backend, client), daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(512)

    def _accept_loop() -> None:
        while True:
            try:
                client, _ = srv.accept()
                threading.Thread(target=_handle, args=(client,), daemon=True).start()
            except OSError:
                break

    threading.Thread(target=_accept_loop, daemon=True).start()
    print(f"[proxy] Round-robin TCP 127.0.0.1:{listen_port} -> {backends}")
    return srv


# ---------------------------------------------------------------------------
# Helpers comuni
# ---------------------------------------------------------------------------

def _wait_for_port(port: int, timeout: int = 30) -> bool:
    url      = f"http://127.0.0.1:{port}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def _stop_procs(procs: list) -> None:
    for p in procs:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    users   = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    runtime = sys.argv[2]      if len(sys.argv) > 2 else "60s"

    csv_prefix = str(_GENERATED / "locust_zkp")
    html_out   = str(_GENERATED / "locust_zkp_report.html")

    procs      = []
    proxy_sock = None

    if _IS_WINDOWS:
        procs      = _start_windows_workers()
        proxy_sock = _start_proxy(_PORT, _WORKER_PORTS)
        print(f"[*] Astept cei {_WORKERS} workeri ...")
        for wp in _WORKER_PORTS:
            if not _wait_for_port(wp):
                raise RuntimeError(f"Worker pe portul {wp} nu a pornit in 30s")
        print(f"[up] Toti workerii sunt gata.")
    else:
        procs = [_start_gunicorn()]
        print(f"[*] Astept server pe port {_PORT} ...")
        if not _wait_for_port(_PORT):
            raise RuntimeError(f"Serverul nu a pornit pe port {_PORT}")

    try:
        print(f"[up] Server gata. Pornesc Locust: {users} useri, {runtime}")
        subprocess.run(
            [
                "locust",
                "-f",            str(_ISOLATED_DIR / "locust_zkp.py"),
                f"--users={users}",
                "--spawn-rate=20",
                "--headless",
                f"--run-time={runtime}",
                "--html",        html_out,
                "--csv",         csv_prefix,
            ],
            cwd=_PROJECT_ROOT,
            check=False,
        )
    finally:
        print("[stop] Opresc serverul ...")
        _stop_procs(procs)
        if proxy_sock:
            proxy_sock.close()

    print(f"\n[done] Rezultate in: {_GENERATED}")
    print(f"  HTML report : {html_out}")
    print(f"  CSV stats   : {csv_prefix}_stats.csv")


if __name__ == "__main__":
    main()
