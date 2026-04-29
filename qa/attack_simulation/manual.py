from pathlib import Path


# TODO (Manual Intervention Required)


def manual_test_traffic_sniffing():
    """
    TODO: Manual Intervention Required

    Test:    Traffic Sniffing / Store-Now-Decrypt-Later
    Goal:    Prove that the ZKP Schnorr protocol never transmits the password
             or private key x over the network.

    Setup:
      1. Start the Flask server WITHOUT TLS (HTTP only):
             python server_app/server.py
         Confirm output: "WARNING: Running without HTTPS."

      2. Start Wireshark (or tshark) on the loopback interface:
         - Windows: capture on "Loopback Pseudo-Interface 1" or "\\Device\\NPF_Loopback"

      3. Open a browser, navigate to http://localhost:5000 and perform a
         complete ZKP login:
           a) Enter client_id and password on the login page.
           b) The browser executes auth.js which calls:
              - POST /login/commit  with {client_id, commitment_t}
              - POST /login/verify  with {solution_s}  (header: X-Auth-Session)

    Theoretical conclusion:
      Even if an adversary captures the full network exchange {t, c, s} they
      cannot invert the discrete logarithm relationship y = g^x mod p for a
      2048-bit safe prime.  The zero-knowledge property guarantees that the
      proof {t, c, s} reveals no information about x beyond the fact that
      the prover knows it.
"""
    pass


def manual_test_mitm_weak_parameters():
    """
    TODO: Manual Intervention Required

    Test:    Man-in-the-Middle on /get-parameters (Weak Parameter Injection)
    Goal:    Show that substituting a small prime P breaks the DLP hardness
             assumption and allows an attacker to recover x trivially.
             That means, the protocol would still need to be over https/tls to prevent this attack.

    Setup:
      1. Start the Flask server:
             python server_app/server.py

      2. Install and start Burp Suite (Community Edition is sufficient):
         - Configure your browser to proxy through 127.0.0.1:8080.
         - Enable "Intercept" in the Proxy tab.

    Attack steps:
      3. Open the browser and navigate to the login page.
         auth.js will call:  GET /get-parameters

      4. In Burp Suite, intercept the RESPONSE to GET /get-parameters.
         Modify the JSON body, replacing the safe prime with a small prime:
           Original:  { "P": "<2048-bit number>", "G": "4" }
           Modified:  { "P": "23",                "G": "4" }
         Forward the modified response to the browser.

      5. The browser now performs the ZKP protocol over the weak group Z_23.
         The attacker can solve the discrete logarithm trivially:
           For P=23, enumerate g^1, g^2, ..., g^22 mod 23 to find x from y.

    Consequences:
      - Once x is known, the attacker can compute a valid solution_s for any
        challenge c:  s = r + c*x mod Q_small.
      - This completely breaks authentication.

    Mitigation:
      - /get-parameters MUST be served over HTTPS with a valid TLS certificate.
      - Consider Certificate Pinning in auth.js to prevent proxy interception.
      - Alternatively, hard-code the known-safe parameters in the client JS
        and never fetch them from the network.

    Expected result: PASS if the server uses HTTPS / certificate pinning in prod.
    Document: Screenshot of Burp Suite showing the intercepted response
              and the trivial DLP solution for P=23.
    """
    # TODO: Execute the steps above and document findings for Chapter 6.
    pass


def generate_security_audit_manual(output_path: str = "qa/attack_simulation/SECURITY_AUDIT_MANUAL.md"):
    """Generate the requested manual-audit markdown artifact."""
    content = """# SECURITY_AUDIT_MANUAL

  ## Prompt 1: Traffic Sniffing (Store-Now Decrypt-Later)

  ### Obiectiv
  Demonstram ca parola in clar si cheia privata `x` nu tranziteaza reteaua in fluxul Schnorr ZKP.

  ### Setup
  1. Ruleaza serverul Flask pe HTTP (fara TLS): `python server_app/server.py`
  2. Porneste Wireshark/tshark pe loopback.
  3. Filtru recomandat: `http.request.method == \"POST\"`

  ### Pasii de reproducere
  1. Deschide `http://localhost:5000`.
  2. Ruleaza un login valid in UI.
  3. Captureaza payload-urile pentru:
     - `POST /login/commit`
     - `POST /login/verify`

  ### Ce trebuie sa gasesti
  - In commit: `client_id`, `commitment_t`
  - In verify: `solution_s`

  ### Ce NU trebuie sa gasesti
  - `password` in clar
  - cheia privata `x`

  ### Concluzie asteptata
  Valorile capturate `{t, c, s}` nu dezvaluie `x`; proprietatea zero-knowledge se mentine.

  ## Prompt 2: MitM pe /get-parameters

  ### Obiectiv
  Simulam injectarea unor parametri slabi (`P=23`, `G=4`) si documentam impactul.

  ### Setup
  1. Ruleaza serverul Flask.
  2. Configureaza browserul prin Burp Suite / OWASP ZAP.
  3. Intercepteaza `GET /get-parameters`.

  ### Pasii de reproducere
  1. Intercepteaza raspunsul cu parametri globali.
  2. Inlocuieste valorile cu `P=23`, `G=4`.
  3. Forward raspunsul modificat catre client.
  4. Continua loginul si observa ca DLP devine trivial pe grup mic.

  ### Consecinte
  Atacatorul poate recupera `x` in grup slab si poate forja `s` valid.

  ### Mitigare
  1. HTTPS/TLS obligatoriu pentru `/get-parameters` in productie.
  2. Optional certificate pinning in client.
  3. Optional hardcodare parametri siguri in frontend.

  ## Dovezi de atasat in disertatie
  1. Captura Wireshark/tshark cu payload-urile `commit/verify`.
  2. Captura Burp/ZAP cu raspunsul modificat pe `/get-parameters`.
  3. Observatii privind imposibilitatea extragerii parolei in fluxul normal.
  """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    print(f"Generated: {out.resolve()}")


if __name__ == "__main__":
    generate_security_audit_manual()


'''
Prompt 1: Traffic Sniffing (Store Now, Decrypt Later)
Acesta este testul suprem pentru proprietatea de "Zero-Knowledge" (Parola nu călătorește pe rețea).
"Generează o secțiune în fișierul SECURITY_AUDIT_MANUAL.md care descrie procedura de testare a atacului de tip Traffic Sniffing.
Descrie setup-ul necesar: Serverul Flask rulând intenționat pe HTTP simplu (fără TLS) și pornirea unui interceptor
de pachete (Wireshark sau tshark) pe interfața de loopback (localhost).
Oferă pașii exacți prin care testerul efectuează un login valid din browser.
Descrie cum să filtrezi pachetele în Wireshark (ex: http.request.method == "POST").
Specifică exact ce trebuie să caute testerul în payload-urile interceptate (t, c, s) și ce NU trebuie să găsească
niciodată (parola în clar sau cheia privată $x$).
Adaugă o concluzie teoretică care explică de ce, deși atacatorul are interceptat traficul,
nu poate extrage parola din valorile tranzitorii capturate."

Prompt 2: Atacul de tip Man-in-the-Middle (MitM) pe obținerea parametrilor
Ce se întâmplă dacă un atacator interceptează cererea /get-parameters și îi dă clientului un $P$ și un $G$ slab?
"Adaugă o secțiune în SECURITY_AUDIT_MANUAL.md pentru a simula și documenta un atac MitM asupra parametrilor globali.
Descrie utilizarea unui proxy de interceptare (precum Burp Suite sau OWASP ZAP).
Oferă pașii prin care testerul interceptează request-ul GET /get-parameters realizat de frontend (auth.js)
și modifică răspunsul serverului, înlocuind numărul Safe Prime uriaș cu un număr prim mic (ex: $P=23, G=4$).
Documentează consecințele acestui atac (atacul logaritmului discret devine trivial de rezolvat pentru atacator pe acești parametri slabi).
Redactează o concluzie și o propunere de mitigare arhitecturală (ex: de ce endpoint-ul /get-parameters
trebuie obligatoriu protejat cu HTTPS/TLS în producție sau folosirea de Certificate Pinning pe client)."
'''