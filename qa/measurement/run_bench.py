"""Quick script to print the E2E protocol comparison table."""
import sys, importlib.util, statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]   # workspace root (acas/)
_QA_PATH = Path(__file__).resolve().parents[1]  # qa/
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))

from qa_utils import server

import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("benchmark", Path(__file__).resolve().parent / "benchmark.py")
pl = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(pl)

server.app.config["TESTING"] = True
with server.app.app_context():
    server.db.drop_all()
    server.db.create_all()
server.sessions.clear()
server.clear_oauth_state()
server.clear_authlib_state()

data = pl._benchmark_e2e_flows(iterations=30)

col = 54
print()
print("END-TO-END PROTOCOL COMPARISON  (30 iterations, full auth latency including client-side crypto)")
print(f"| {'Protocol Flow':<{col}} | {'Mean':>10} | {'Min':>10} | {'Max':>10} | {'P95':>10} |")
print("|" + "-" * (col + 2) + "|" + ("-" * 12 + "|") * 4)
for k, v in data.items():
    print(f"| {k:<{col}} | {v['mean']:>10.3f} | {v['min']:>10.3f} | {v['max']:>10.3f} | {v['p95']:>10.3f} |")
print()
