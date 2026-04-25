"""
Measurement generators for dissertation artifacts.

Includes:
1. Global parameter generation benchmark (custom vs library)
2. Latency table generator for ZKP flow
3. Traffic content auditor with forbidden-field scan
4. Security snippet extractor from server.py
5. Chart generator (box plot + histogram)
"""

from pathlib import Path
import secrets
import statistics
import sys
import time

from cryptography.hazmat.primitives.asymmetric import dh

_QA_PATH = Path(__file__).resolve().parents[1]
if str(_QA_PATH) not in sys.path:
    sys.path.insert(0, str(_QA_PATH))
from qa_utils import server, derive_password_x


P, Q, G = None, None, None


def generate_global_parameters(generate_new=False, use_library=False, generator=2, key_size=2048):
    global P, Q, G
    mode = "library" if use_library else "custom"
    print(f"Generating global parameters with {mode} for: {generator}, {key_size}")
    start_time = time.time_ns()
    if not generate_new:
        P = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
        Q = (P - 1) // 2
        G = 4
    else:
        parameters = dh.generate_parameters(generator=generator, key_size=key_size)
        P = parameters.parameter_numbers().p
        if use_library:
            G = parameters.parameter_numbers().g
        else:
            Q = (P - 1) // 2
            temp_h = secrets.randbelow(P - 3) + 2
            G = pow(temp_h, 2, P)
            while G == 1 or pow(G, Q, P) != 1:
                temp_h = secrets.randbelow(P - 3) + 2
                G = pow(temp_h, 2, P)
        Q = (P - 1) // 2

    elapsed_ms = (time.time_ns() - start_time) / 1000000
    print(f"Global parameters generated in {elapsed_ms:.6f} ms")
    print(f"P = {P}")
    print(f"G = {G}")
    print(f"Q = {Q}")
    print(f"P este prim sigur (p = 2q + 1)? -> {P == 2 * Q + 1}")
    return {"P": P, "Q": Q, "G": G, "elapsed_ms": elapsed_ms}


def generate_latency_table(iterations: int = 100) -> str:
    server.app.config["TESTING"] = True
    client_id = "generate_latency_user"
    x = derive_password_x("latency-password")
    y = pow(server.G, x, server.P)

    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()

    client = server.app.test_client()
    commit_ms = []
    verify_ms = []
    rtt_ms = []

    for _ in range(iterations):
        server.sessions.clear()
        r = secrets.randbelow(server.P - 2) + 1
        t = pow(server.G, r, server.P)
        rtt0 = time.perf_counter_ns()

        c0 = time.perf_counter_ns()
        commit_resp = client.post("/login/commit", json={"client_id": client_id, "commitment_t": t})
        c1 = time.perf_counter_ns()
        commit_ms.append((c1 - c0) / 1e6)
        payload = commit_resp.get_json()

        c = int(payload["challenge_c"])
        s = (r + c * x) % server.Q
        sid = payload["session_id"]

        v0 = time.perf_counter_ns()
        client.post("/login/verify", headers={"X-Auth-Session": sid}, json={"solution_s": s})
        v1 = time.perf_counter_ns()
        verify_ms.append((v1 - v0) / 1e6)
        rtt_ms.append((v1 - rtt0) / 1e6)

    def row(label, values):
        return (
            f"| {label:<30} | {statistics.mean(values):>9.4f} | {min(values):>9.4f}"
            f" | {max(values):>9.4f} | {statistics.stdev(values):>9.4f} |"
        )

    lines = [
        "## Tabel de Latenta (100 iteratii)",
        "| Etapa                          |  Mean ms  |   Min ms  |   Max ms  |   StdDev  |",
        "|--------------------------------|-----------|-----------|-----------|-----------|",
        row("/login/commit", commit_ms),
        row("/login/verify", verify_ms),
        row("Round-trip total", rtt_ms),
    ]
    return "\n".join(lines)


def audit_traffic_content(output_md: str = "audit_report.md"):
    client_id = "audit_user"
    x = derive_password_x("audit-password")
    y = pow(server.G, x, server.P)
    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()

    client = server.app.test_client()
    r = secrets.randbelow(server.P - 2) + 1
    t = pow(server.G, r, server.P)
    commit_body = {"client_id": client_id, "commitment_t": str(t)}
    commit_resp = client.post("/login/commit", json=commit_body)
    p = commit_resp.get_json()
    sid = p["session_id"]
    c = int(p["challenge_c"])
    verify_body = {"solution_s": str((r + c * x) % server.Q)}
    client.post("/login/verify", headers={"X-Auth-Session": sid}, json=verify_body)

    import base64 as _base64

    forbidden = {"password", "parola", "x"}

    def find_hits(body):
        hits = []
        for k, v in body.items():
            if k.lower() in forbidden:
                hits.append(k)
            if isinstance(v, str) and v.lower() in forbidden:
                hits.append(v)
        return hits

    commit_hits = find_hits(commit_body)
    verify_hits = find_hits(verify_body)

    # OAuth PKCE authorize body – credentials travel to the authorization server
    # (not forwarded to any third-party client), and the code_challenge replaces
    # the verifier in transit for the token exchange step.
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = _base64.urlsafe_b64encode(
        __import__("hashlib").sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    oauth_pkce_body = {
        "response_type": "code",
        "client_id": "acas-pkce-client",
        "redirect_uri": "https://client.example/callback",
        "username": client_id,
        "password": "audit-password",   # resource-owner cred, sent to auth server only
        "scope": "openid profile",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    oauth_token_body = {
        "grant_type": "authorization_code",
        "client_id": "acas-pkce-client",
        "redirect_uri": "https://client.example/callback",
        "code": "<opaque-auth-code>",
        "code_verifier": code_verifier,  # sent only to token endpoint, never to client
    }
    oauth_pkce_hits = find_hits(oauth_pkce_body)
    oauth_token_hits = find_hits(oauth_token_body)

    report = [
        "# Audit trafic - ZKP vs OAuth2",
        "",
        "## /login/commit payload (ZKP)",
        f"`{commit_body}`",
        f"Hits interzise: {commit_hits if commit_hits else 'niciunul (PASS)'}",
        "",
        "## /login/verify payload (ZKP)",
        f"`{verify_body}`",
        f"Hits interzise: {verify_hits if verify_hits else 'niciunul (PASS)'}",
        "",
        "## /oauth/pkce/authorize payload (OAuth2 PKCE - comparatie)",
        f"`{oauth_pkce_body}`",
        f"Hits interzise: {oauth_pkce_hits}",
        "Nota: parola este trimisa catre authorization server (acelasi domeniu), nu catre client.",
        "Securitatea depinde de confidentialitatea canalului HTTPS, nu de zero-knowledge.",
        "",
        "## /oauth/pkce/token payload (OAuth2 PKCE - code exchange)",
        f"`{oauth_token_body}`",
        f"Hits interzise: {oauth_token_hits if oauth_token_hits else 'niciunul (PASS)'}",
        "Nota: code_verifier este un secret de scurta durata, parola nu mai apare in aceasta cerere.",
    ]
    Path(output_md).write_text("\n".join(report), encoding="utf-8")
    print(f"Wrote {output_md}")


def extract_security_snippets(output_md: str = "security_snippets.md"):
    src = SERVER_MODULE_PATH.read_text(encoding="utf-8")
    lines = src.splitlines()
    patterns = [
        ("is_subgroup_member", "Prevenire small-subgroup attacks"),
        ("del sessions[session_id]", "Prevenire replay prin invalidare sesiune"),
        ("secrets.randbelow", "Challenge impredictibil"),
    ]
    out = ["# Security snippets", ""]
    for p, note in patterns:
        out.append(f"## {p}")
        out.append(f"> {note}")
        out.append("```python")
        idx = next((i for i, ln in enumerate(lines) if p in ln), None)
        if idx is None:
            out.append(f"# pattern {p} not found")
        else:
            start = max(0, idx - 3)
            end = min(len(lines), idx + 6)
            out.extend(lines[start:end])
        out.append("```")
        out.append("")
    Path(output_md).write_text("\n".join(out), encoding="utf-8")
    print(f"Wrote {output_md}")


def generate_charts(output_dir: str = "charts"):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed. Run: pip install matplotlib")
        return

    server.app.config["TESTING"] = True
    client_id = "chart_user"
    x = derive_password_x("chart-password")
    y = pow(server.G, x, server.P)
    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()
    client = server.app.test_client()

    verify_ms = []
    oauth_ms = []
    for _ in range(100):
        server.sessions.clear()
        r = secrets.randbelow(server.P - 2) + 1
        t = pow(server.G, r, server.P)
        c_resp = client.post("/login/commit", json={"client_id": client_id, "commitment_t": t})
        payload = c_resp.get_json()
        sid = payload["session_id"]
        c = int(payload["challenge_c"])
        s = (r + c * x) % server.Q

        t0 = time.perf_counter_ns()
        client.post("/login/verify", headers={"X-Auth-Session": sid}, json={"solution_s": s})
        t1 = time.perf_counter_ns()
        verify_ms.append((t1 - t0) / 1e6)

        t2 = time.perf_counter_ns()
        hashlib.sha256(b"chart-password").hexdigest()
        t3 = time.perf_counter_ns()
        oauth_ms.append((t3 - t2) / 1e6)

    out_dir = Path(output_dir)
    out_dir.mkdir(exist_ok=True)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.boxplot(verify_ms, patch_artist=True)
    ax.set_title("Distributia latentei /login/verify")
    ax.set_ylabel("ms")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out_dir / "boxplot_verify_latency.png", dpi=300)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(verify_ms, bins=20, alpha=0.7, label="ZKP verify")
    ax.hist(oauth_ms, bins=20, alpha=0.7, label="OAuth2 hash")
    ax.set_title("Comparatie latenta ZKP vs OAuth2")
    ax.set_xlabel("ms")
    ax.set_ylabel("frecventa")
    ax.legend()
    ax.grid(linestyle="--", alpha=0.4)
    fig.tight_layout()
    fig.savefig(out_dir / "histogram_zkp_vs_oauth2.png", dpi=300)
    plt.close(fig)
    print(f"Charts saved to {out_dir}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "--latency"
    if cmd == "--latency":
        print(generate_latency_table(iterations=100))
    elif cmd == "--audit":
        audit_traffic_content()
    elif cmd == "--snippets":
        extract_security_snippets()
    elif cmd == "--charts":
        generate_charts()
    elif cmd == "--params":
        generate_global_parameters(generate_new=True, use_library=False)
    else:
        print("Usage: python qa/measurement/generates.py [--latency|--audit|--snippets|--charts|--params]")




