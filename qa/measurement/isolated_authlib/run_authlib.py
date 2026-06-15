"""
Runner izolat — Authlib PKCE pe port 5300, fara competitie cu alte servere.

Utilizare:
    python qa/measurement/isolated_authlib/run_authlib.py [users] [runtime]

Exemple:
    python qa/measurement/isolated_authlib/run_authlib.py 100 60s
    python qa/measurement/isolated_authlib/run_authlib.py 400 120s
"""
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_ISOLATED_DIR = Path(__file__).resolve().parent
_GENERATED    = _ISOLATED_DIR / "generated"
_GENERATED.mkdir(parents=True, exist_ok=True)

_PYTHON  = sys.executable
_PORT    = 5300
_THREADS = 8


def _start_server() -> subprocess.Popen:
    db_dir = _PROJECT_ROOT / "server_app" / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_uri = f"sqlite:///{db_dir / f'auth_{_PORT}.db'}"
    env = {**__import__('os').environ, "ACAS_DB_URI": db_uri}
    bootstrap = (
        "import sys; sys.path.insert(0, 'server_app'); "
        "import server; "
        "from waitress import serve; "
        f"serve(server.app, host='127.0.0.1', port={_PORT}, "
        f"threads={_THREADS}, channel_timeout=60)"
    )
    print(f"[start] Flask/Waitress pe port {_PORT} ({_THREADS} threads, SQLite)")
    return subprocess.Popen(
        [_PYTHON, "-c", bootstrap],
        cwd=_PROJECT_ROOT,
        env=env,
    )


def _wait_for_server(timeout: int = 30) -> bool:
    url = f"http://127.0.0.1:{_PORT}/health"
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


def _stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    users   = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    runtime = sys.argv[2]      if len(sys.argv) > 2 else "60s"

    csv_prefix = str(_GENERATED / "locust_authlib")
    html_out   = str(_GENERATED / "locust_authlib_report.html")

    proc = _start_server()
    try:
        print(f"[*] Astept server pe port {_PORT} ...")
        if not _wait_for_server():
            raise RuntimeError(f"Serverul nu a pornit pe port {_PORT}")
        print(f"[up] Server gata. Pornesc Locust: {users} useri, {runtime}")

        subprocess.run(
            [
                "locust",
                "-f",            str(_ISOLATED_DIR / "locust_authlib.py"),
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
        _stop_server(proc)

    print(f"\n[done] Rezultate in: {_GENERATED}")
    print(f"  HTML report : {html_out}")
    print(f"  CSV stats   : {csv_prefix}_stats.csv")


if __name__ == "__main__":
    main()
