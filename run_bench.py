"""Quick script to print the E2E protocol comparison table."""
import sys, importlib.util, statistics
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "server_app"))
sys.path.insert(0, str(ROOT / "qa" / "test"))

spec = importlib.util.spec_from_file_location("server", ROOT / "server_app" / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

import perf_load as pl

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
print("END-TO-END PROTOCOL COMPARISON  (30 iterations, client-side crypto excluded)")
print(f"| {'Protocol Flow':<{col}} | {'Mean':>10} | {'Min':>10} | {'Max':>10} | {'P95':>10} |")
print("|" + "-" * (col + 2) + "|" + ("-" * 12 + "|") * 4)
for k, v in data.items():
    print(f"| {k:<{col}} | {v['mean']:>10.3f} | {v['min']:>10.3f} | {v['max']:>10.3f} | {v['p95']:>10.3f} |")
print()
