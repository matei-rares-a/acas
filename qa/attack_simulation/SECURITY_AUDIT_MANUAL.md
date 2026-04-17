# SECURITY_AUDIT_MANUAL

  ## Prompt 1: Traffic Sniffing (Store-Now Decrypt-Later)

  ### Obiectiv
  Demonstram ca parola in clar si cheia privata `x` nu tranziteaza reteaua in fluxul Schnorr ZKP.

  ### Setup
  1. Ruleaza serverul Flask pe HTTP (fara TLS): `python server_app/server.py`
  2. Porneste Wireshark/tshark pe loopback.
  3. Filtru recomandat: `http.request.method == "POST"`

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
  