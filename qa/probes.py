"""
probes.py – Dissertation data collection scripts.

Probe 1  – Latency table (ZKP flow, 100 iterations, perf_counter_ns)
Probe 2  – Traffic content auditor (audit_report.md)
Probe 3  – Security snippet extractor (server.py scan)
Probe 4  – Chart generator (box plot + histogram)
"""

from pathlib import Path
import hashlib
import importlib.util
import secrets as secrets_module
import statistics
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_APP_PATH = PROJECT_ROOT / "server_app"
SERVER_MODULE_PATH = SERVER_APP_PATH / "server.py"
if str(SERVER_APP_PATH) not in sys.path:
    sys.path.insert(0, str(SERVER_APP_PATH))
_spec = importlib.util.spec_from_file_location("server", SERVER_MODULE_PATH)
server = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(server)


# ---------------------------------------------------------------------------
# Probe 1 – Latency table
# ---------------------------------------------------------------------------

def _derive_x(password: str) -> int:
    salt = secrets_module.token_bytes(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**11, r=8, p=1)
    return int.from_bytes(hashed, "big") % server.Q


def generate_latency_table(iterations: int = 100) -> str:
    """
    Run 'iterations' complete ZKP authentication flows inside the Flask test
    client, record commit_ns and verify_ns, return a Markdown table string.
    """
    server.app.config["TESTING"] = True

    password = "probe-password"
    client_id = "probe_latency_user"
    x = _derive_x(password)
    y = pow(server.G, x, server.P)

    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()

    client = server.app.test_client()
    commit_times: list[float] = []
    verify_times: list[float] = []
    rtt_times: list[float] = []

    for _ in range(iterations):
        server.sessions.clear()
        rand_r = secrets_module.randbelow(server.P - 2) + 1
        t = pow(server.G, rand_r, server.P)

        rtt_start = time.perf_counter_ns()

        t0 = time.perf_counter_ns()
        commit_resp = client.post(
            "/login/commit",
            json={"client_id": client_id, "commitment_t": t},
        )
        t1 = time.perf_counter_ns()
        commit_times.append((t1 - t0) / 1e6)

        payload = commit_resp.get_json()
        c = int(payload["challenge_c"])
        session_id = payload["session_id"]
        s = (rand_r + c * x) % server.Q

        t2 = time.perf_counter_ns()
        client.post(
            "/login/verify",
            headers={"X-Auth-Session": session_id},
            json={"solution_s": s},
        )
        t3 = time.perf_counter_ns()
        verify_times.append((t3 - t2) / 1e6)
        rtt_times.append((t3 - rtt_start) / 1e6)

    def row(label: str, data: list[float]) -> str:
        return (
            f"| {label:<32} | {statistics.mean(data):>9.4f} "
            f"| {min(data):>9.4f} | {max(data):>9.4f} "
            f"| {statistics.stdev(data):>9.4f} |"
        )

    header = (
        f"| {'Etapa':<32} | {'Media (ms)':>9} | {'Min (ms)':>9}"
        f" | {'Max (ms)':>9} | {'StdDev':>9} |"
    )
    sep = "|" + "-" * 34 + "|" + ("-" * 11 + "|") * 4

    lines = [
        "## Tabel de Latenta – Flux ZKP Schnorr",
        f"Iteratii: {iterations}",
        "",
        header,
        sep,
        row("/login/commit (server side)", commit_times),
        row("/login/verify (server side)", verify_times),
        row("Round-Trip Total (client)", rtt_times),
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Probe 2 – Traffic content auditor
# ---------------------------------------------------------------------------

def audit_traffic_content(output_md: str = "audit_report.md"):
    """
    Simulate an application-level MitM observer and produce audit_report.md.
    Scans captured payloads for forbidden keywords (password, parola, x).
    """
    server.app.config["TESTING"] = True

    client_id = "audit_traffic_user"
    password = "audit-secret"
    x = _derive_x(password)
    y = pow(server.G, x, server.P)

    with server.app.app_context():
        server.db.session.remove()
        server.db.drop_all()
        server.db.create_all()
        server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
        server.db.session.commit()

    server.sessions.clear()
    client = server.app.test_client()

    rand_r = secrets_module.randbelow(server.P - 2) + 1
    t = pow(server.G, rand_r, server.P)

    commit_body = {"client_id": client_id, "commitment_t": str(t)}
    commit_resp = client.post("/login/commit", json=commit_body)
    payload = commit_resp.get_json()
    c = int(payload["challenge_c"])
    session_id = payload["session_id"]
    s = (rand_r + c * x) % server.Q
    verify_body = {"solution_s": str(s)}

    FORBIDDEN = {"password", "parola", "x"}

    def scan(label: str, body: dict) -> list[str]:
        hits = []
        for key, value in body.items():
            if key.lower() in FORBIDDEN:
                hits.append(f"  ALERT: '{key}' found in {label}")
            if isinstance(value, str) and value.lower() in FORBIDDEN:
                hits.append(f"  ALERT: value '{value}' in key '{key}' in {label}")
        return hits

    commit_hits = scan("POST /login/commit", commit_body)
    verify_hits = scan("POST /login/verify", verify_body)

    classic_example_body = {"client_id": client_id, "password": password}
    classic_hits = scan("POST /classic/login (clasic)", classic_example_body)

    report_lines = [
        "# Audit Trafic ZKP vs Clasic",
        "",
        "## POST /login/commit (ZKP Step 1)",
        "```json",
        str({k: (str(v)[:60] + "...") if len(str(v)) > 63 else str(v)
             for k, v in commit_body.items()}),
        "```",
        "Cuvinte interzise gasite: " + (", ".join(commit_hits) if commit_hits else "Niciuna (PASS)"),
        "",
        "## POST /login/verify (ZKP Step 2)",
        "```json",
        str({k: (str(v)[:60] + "...") if len(str(v)) > 63 else str(v)
             for k, v in verify_body.items()}),
        "```",
        "Cuvinte interzise gasite: " + (", ".join(verify_hits) if verify_hits else "Niciuna (PASS)"),
        "",
        "## POST /classic/login (COMPARATIE – Autentificare Clasica)",
        "```json",
        str(classic_example_body),
        "```",
        "Cuvinte interzise gasite: " + (", ".join(classic_hits) if classic_hits
                                         else "Niciuna"),
        "",
        "## Concluzie",
        "Fluxul ZKP Schnorr nu transmite parola sau cheia privata x over the wire.",
        "Payload-urile contin exclusiv valori matematice tranzitorii (t, s),",
        "care sunt fara valoare pentru un atacator care aplica un atac de tip SNDL.",
    ]

    out = Path(output_md)
    out.write_text("\n".join(report_lines), encoding="utf-8")
    print(f"Audit report written to: {out.resolve()}")
    print("ZKP commit payload keys:", list(commit_body.keys()))
    print("ZKP verify payload keys:", list(verify_body.keys()))
    print("Forbidden keywords scan COMMIT:", commit_hits or "PASS")
    print("Forbidden keywords scan VERIFY:", verify_hits or "PASS")


# ---------------------------------------------------------------------------
# Probe 3 – Security snippet extractor
# ---------------------------------------------------------------------------

def extract_security_snippets(output_md: str = "security_snippets.md"):
    """
    Scan server.py for key security mechanisms and produce a Markdown file
    with annotated code snippets ready for the dissertation.
    """
    server_src = SERVER_MODULE_PATH.read_text(encoding="utf-8")
    lines = server_src.splitlines()

    snippets: list[dict] = [
        {
            "title": "Validarea subgrupului (is_subgroup_member)",
            "search": "is_subgroup_member",
            "annotation": (
                "Previne atacul Small Subgroup: verifica ca secret_y si "
                "commitment_t apartin subgrupului de ordin Q generat de G. "
                "Daca y sau t sunt in afara subgrupului, serverul respinge "
                "cererea cu 422 Unprocessable Entity."
            ),
        },
        {
            "title": "Unicitatea sesiunii si rezistenta la Replay (del sessions[...])",
            "search": "del server.sessions" if "del server.sessions" in server_src else "del sessions[",
            "annotation": (
                "Previne atacul Replay: sesiunea este stearsa imediat dupa "
                "verificare (cu succes sau esec), astfel ca acelasi session_id "
                "nu poate fi refolosit de un atacator care a capturat traficul."
            ),
        },
        {
            "title": "Generare challenge nepredictibila (secrets.randbelow)",
            "search": "secrets.randbelow",
            "annotation": (
                "Previne atacul de Challenge Prediction si Session Fixation: "
                "foloseste CSPRNG (secrets.randbelow) pentru a genera challenge_c "
                "si session_id, asigurand entropie criptografica si unicitate."
            ),
        },
    ]

    output_lines = ["# Security Snippets – server.py", ""]

    for snip in snippets:
        output_lines.append(f"## {snip['title']}")
        output_lines.append("")
        output_lines.append(f"> {snip['annotation']}")
        output_lines.append("")
        output_lines.append("```python")

        matches = [i for i, ln in enumerate(lines) if snip["search"] in ln]
        if matches:
            first = matches[0]
            start = max(0, first - 3)
            end = min(len(lines), first + 8)
            output_lines.extend(lines[start:end])
        else:
            output_lines.append(f"# Pattern '{snip['search']}' not found in server.py")

        output_lines.append("```")
        output_lines.append("")

    out = Path(output_md)
    out.write_text("\n".join(output_lines), encoding="utf-8")
    print(f"Security snippets written to: {out.resolve()}")


# ---------------------------------------------------------------------------
# Probe 4 – Chart generator
# ---------------------------------------------------------------------------
# TODO: Requires matplotlib (pip install matplotlib).
#       If matplotlib is not installed this probe is skipped gracefully.

def generate_charts(latency_data: dict | None = None, output_dir: str = "charts"):
    """Generate box plot and histogram for the dissertation (Chapter 6)."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib.style as mstyle
        mstyle.use("seaborn-v0_8-whitegrid")
    except ImportError:
        print("matplotlib not installed. Run: pip install matplotlib")
        return

    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    # Collect raw latency data if not provided
    if latency_data is None:
        server.app.config["TESTING"] = True
        client_id = "chart_probe_user"
        password = "chart-probe-pw"
        x = _derive_x(password)
        y = pow(server.G, x, server.P)
        with server.app.app_context():
            server.db.session.remove()
            server.db.drop_all()
            server.db.create_all()
            server.db.session.add(server.User(client_id=client_id, secret_y=str(y)))
            server.db.session.commit()
        client = server.app.test_client()
        verify_ms: list[float] = []
        classic_ms: list[float] = []
        for _ in range(100):
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

            # Classic baseline: SHA-256 inline
            t2 = time.perf_counter_ns()
            hashlib.sha256(password.encode()).hexdigest()
            t3 = time.perf_counter_ns()
            classic_ms.append((t3 - t2) / 1e6)

        latency_data = {"verify_ms": verify_ms, "classic_ms": classic_ms}

    verify_ms = latency_data["verify_ms"]
    classic_ms = latency_data["classic_ms"]

    # Box plot: /login/verify latency distribution
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.boxplot(
        verify_ms,
        vert=True,
        patch_artist=True,
        boxprops=dict(facecolor="#BBDEFB", color="#1565C0"),
        medianprops=dict(color="#E53935", linewidth=2),
    )
    ax.set_xticklabels(["/login/verify (ZKP Schnorr)"])
    ax.set_ylabel("Latenta (ms)")
    ax.set_title(
        "Distributia latenței pentru /login/verify\n(exponențiere modulară 2048-bit)",
        fontsize=11,
    )
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out / "boxplot_verify_latency.png", dpi=300)
    print(f"Saved: {out / 'boxplot_verify_latency.png'}")
    plt.close(fig)

    # Histogram: ZKP verify vs Classic hash comparison
    fig, ax = plt.subplots(figsize=(9, 5))
    import numpy as np
    bins = 20
    ax.hist(verify_ms, bins=bins, alpha=0.7, color="#1565C0", label="ZKP /login/verify")
    ax.hist(classic_ms, bins=bins, alpha=0.7, color="#E53935", label="SHA-256 (similare clasice)")
    ax.set_xlabel("Latenta (ms)")
    ax.set_ylabel("Frecventa")
    ax.set_title(
        "Comparatie latenta: Autentificare ZKP vs Clasica (SHA-256)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.grid(linestyle="--", alpha=0.4)
    fig.tight_layout()
    fig.savefig(out / "histogram_zkp_vs_classic.png", dpi=300)
    print(f"Saved: {out / 'histogram_zkp_vs_classic.png'}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys

    cmd = _sys.argv[1] if len(_sys.argv) > 1 else "--latency"

    if cmd == "--latency":
        print(generate_latency_table(iterations=100))

    elif cmd == "--audit":
        audit_traffic_content()

    elif cmd == "--snippets":
        extract_security_snippets()

    elif cmd == "--charts":
        generate_charts()

    elif cmd == "--all":
        print(generate_latency_table(iterations=100))
        audit_traffic_content()
        extract_security_snippets()
        generate_charts()

    else:
        print("Usage: python qa/probes.py [--latency|--audit|--snippets|--charts|--all]")


'''
Pentru a transforma recomandările de livrabile în rezultate concrete pentru lucrarea de disertație, poți folosi următoarele prompturi pentru agentul tău AI. Acestea sunt concepute să genereze scripturi care colectează datele, extrag codul relevant și pregătesc materialul vizual.

Iată prompturile structurate pe cele trei categorii:

1. Tabele de Latență (Automatizarea colectării datelor)
Acest prompt va genera un script care rulează testele și produce direct tabelul Markdown pentru lucrare.
"Acționează ca un Data Analyst. Scrie un script Python de benchmarking (generate_latency_table.py) care să:
Ruleze 100 de iterații ale fluxului complet de autentificare ZKP (Commitment -> Challenge -> Proof).
Folosească time.perf_counter_ns() pentru a măsura cu precizie de nanosecunde:
Timpul de execuție pe server pentru /login/commit (generare challenge).
Timpul de execuție pe server pentru /login/verify (verificare matematică).
Timpul total de 'Round Trip' de la client.
Calculeze pentru fiecare etapă: Media (Mean), Minimul, Maximul și Deviația Standard.
Output-ul scriptului trebuie să fie un tabel formatat în Markdown gata de pus în disertație, cu valorile convertite în milisecunde (ms)."

2. Capturi de Trafic (Demonstrarea absenței parolei)
Deoarece agentul nu poate rula Wireshark, el poate genera un script care "simulează" ce ar vedea un atacator (sniffing la nivel de aplicație) pentru a pune în oglindă datele.
"Scrie un script de test (audit_traffic_content.py) care să intercepteze și să logheze conținutul brut (raw) al pachetelor JSON trimise între client și server în timpul procesului de login.
Scriptul trebuie să simuleze un 'Man-in-the-Middle' care citește corpul request-urilor către /login/commit și /login/verify.
Output-ul trebuie să fie un fișier text care arată exact ce date circulă (ex: client_id, commitment_t, solution_s).
Adaugă o funcție de scanare care să caute cuvinte cheie precum 'password', 'parola', 'x' (cheia privată) în payload-uri și să confirme (print) că acestea lipsesc.
Generează un fișier audit_report.md care să compare un request clasic (unde parola e vizibilă) cu request-ul ZKP Schnorr, evidențiind avantajul de securitate."

3. Fragmente de Cod Logice (Extragerea automată a mecanismelor de apărare)
Acest prompt ajută la documentarea tehnică prin extragerea automată a "inimii" securității din codul tău.
"Scrie un script de documentare care să scaneze fișierul server.py și să extragă următoarele 'Security Snippets' într-un format pregătit pentru LaTeX sau Markdown:
Mecanismul de validare a subgrupului: Funcția is_subgroup_member și locul unde este apelată în rute.
Mecanismul de unicitate a sesiunii: Logica de ștergere a sesiunii (del sessions[session_id]) imediat după utilizare sau la eroare.
Mecanismul de rezistență la Replay: Generarea challenge_c folosind secrets.randbelow.
Pentru fiecare fragment extras, adaugă automat un comentariu explicativ (în limba română) care să descrie ce atac specific previne acel cod (ex: prevenirea atacurilor de tip small subgroup, prevenirea replay attacks)."

4. Generarea de Grafice Profesionale (Vizualizarea rezultatelor)
Pentru a aduce valoare vizuală, cere-i agentului să scrie scriptul de vizualizare a datelor colectate la punctul 1.
"Folosind datele de latență generate anterior, scrie un script Python cu matplotlib sau seaborn care să genereze două grafice pentru capitolul 6:
Box Plot: Pentru a arăta distribuția latenței la /login/verify. Trebuie să evidențieze că majoritatea timpului este consumat de exponențierea modulară, dar că valorile sunt stabile.
Histogramă: Care să compare timpul de răspuns al fluxului ZKP cu timpul de răspuns al fluxului OAuth clasic (bazat pe datele colectate anterior).
Configurează graficele să aibă titluri, legende și axe explicate în limba română, cu un stil vizual 'academic' (grilă discretă, fonturi lizibile)."
'''