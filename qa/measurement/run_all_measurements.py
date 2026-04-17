"""
One-command runner for measurement scripts.

What it can do:
1) Optional dependency install
2) Run comparision.py micro-benchmark
3) Run generates.py steps (latency, audit, snippets, charts)
4) Run comparision.py chart generation
5) Optional live server startup + resource monitor step

Run from project root or anywhere:
python qa/measurement/run_all_measurements.py --help
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PYTHON_BIN = sys.executable


def run_cmd(label: str, args: list[str], check: bool = True) -> int:
    print(f"\n[STEP] {label}")
    print(f"[CMD ] {' '.join(args)}")
    result = subprocess.run(args, cwd=PROJECT_ROOT)
    if check and result.returncode != 0:
        raise RuntimeError(f"Step failed: {label} (exit code {result.returncode})")
    return result.returncode


def wait_for_health(url: str, timeout_seconds: int = 20) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.5)
    return False


def start_server_process() -> subprocess.Popen:
    # Start server without debug reloader to keep a single PID we can monitor.
    bootstrap = (
        "import sys;"
        "sys.path.insert(0, 'server_app');"
        "import server;"
        "server.app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)"
    )
    proc = subprocess.Popen([PYTHON_BIN, "-c", bootstrap], cwd=PROJECT_ROOT)
    return proc


def stop_server_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()


def install_dependencies(include_optional: bool) -> None:
    run_cmd(
        "Install base requirements",
        [PYTHON_BIN, "-m", "pip", "install", "-r", "requirements.txt"],
    )
    if include_optional:
        run_cmd(
            "Install optional measurement packages",
            [PYTHON_BIN, "-m", "pip", "install", "psutil", "matplotlib", "pandas"],
        )


def run_measurement_flow(args: argparse.Namespace) -> None:
    if args.install:
        install_dependencies(include_optional=args.install_optional)

    run_cmd(
        "comparision.py benchmark",
        [PYTHON_BIN, "qa/measurement/comparision.py"],
    )

    run_cmd(
        "generates.py latency table",
        [PYTHON_BIN, "qa/measurement/generates.py", "--latency"],
    )
    run_cmd(
        "generates.py traffic audit",
        [PYTHON_BIN, "qa/measurement/generates.py", "--audit"],
    )
    run_cmd(
        "generates.py security snippets",
        [PYTHON_BIN, "qa/measurement/generates.py", "--snippets"],
    )
    run_cmd(
        "generates.py charts",
        [PYTHON_BIN, "qa/measurement/generates.py", "--charts"],
    )

    run_cmd(
        "comparision.py charts",
        [PYTHON_BIN, "qa/measurement/comparision.py", "--charts"],
    )

    if args.monitor:
        proc = start_server_process()
        try:
            healthy = wait_for_health("http://127.0.0.1:5000/health", timeout_seconds=25)
            if not healthy:
                raise RuntimeError("Server did not become healthy on http://127.0.0.1:5000/health")
            run_cmd(
                "comparision.py resource monitor",
                [
                    PYTHON_BIN,
                    "qa/measurement/comparision.py",
                    "--monitor",
                    str(proc.pid),
                    str(args.monitor_seconds),
                ],
            )
        finally:
            stop_server_process(proc)



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run full measurement setup and scripts in one go."
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install dependencies from requirements.txt before running.",
    )
    parser.add_argument(
        "--install-optional",
        action="store_true",
        help="Also install psutil, matplotlib, and pandas.",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Start live server and run resource monitor step.",
    )
    parser.add_argument(
        "--monitor-seconds",
        type=int,
        default=30,
        help="Duration for monitor step in seconds (default: 30).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        run_measurement_flow(parse_args())
        print("\nDone. Measurement pipeline completed.")
    except Exception as exc:
        print(f"\nPipeline failed: {exc}")
        sys.exit(1)
