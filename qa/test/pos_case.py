'''
Context inițial (dă-i asta prima dată)
"Acționează ca un Senior QA Engineer / Backend Developer. Scrie teste de integrare în Python folosind framework-ul pytest și Flask test_client pentru un sistem de autentificare bazat pe Zero-Knowledge Proof (protocolul Schnorr). Sistemul folosește baza de date în memorie (SQLite) pentru testare."

Prompt 1: Testarea înregistrării (Setup Phase)
"Scrie un test de integrare pentru endpoint-ul POST /register.
Creează un payload JSON cu client_id="test_user" și o valoare numerică validă pentru secret_y (ex: 12345).
Trimite request-ul către endpoint.
Validează că răspunsul HTTP are statusul 201 Created și că body-ul JSON este {"status": "Registered"}.
Folosind contextul aplicației Flask, interoghează baza de date (modelul User) și validează (assert) că utilizatorul 'test_user' a fost salvat și că parola în clar nu se regăsește nicăieri în obiectul salvat."

Prompt 2: Testarea actualizării (Idempotency)
"Scrie un test unitar/de integrare pentru a valida logica de actualizare a cheii publice pe endpoint-ul POST /register.
Întâi, populează baza de date de test cu un utilizator (client_id="test_user", secret_y="1111").
Execută un nou request POST /register folosind același client_id dar un secret_y diferit (ex: "2222").
Validează (assert) că status code-ul HTTP returnat este 200 OK (nu 201) și că mesajul JSON este {"status": "Updated"}.
Verifică în baza de date că nu s-a creat un utilizator duplicat, iar proprietatea secret_y a fost suprascrisă cu noua valoare."

Prompt 3: Testarea fluxului de Autentificare ZKP
"Scrie un test E2E complex care validează fluxul de logare în doi pași (Commitment și Verify) bazat pe ZKP Schnorr.
Formează starea inițială: adaugă în DB un utilizator test_zkp cu un secret_y cunoscut (pentru a putea face matematica să treacă pe server).
Pasul 1 (Commit): Fă un request POST /login/commit cu client_id="test_zkp" și un angajament valid commitment_t. Verifică statusul 200 și extrage din răspuns challenge_c și session_id.
Pasul intermediar: Mock-uiește sau calculează valid o soluție solution_s astfel încât ecuația din backend pow(G, s, P) == (t * pow(y, c, P)) % P să returneze True.
Pasul 2 (Verify): Fă un request POST /login/verify, adăugând header-ul X-Auth-Session cu valoarea salvată anterior, și trimite solution_s.
Validează (assert) statusul 200 OK, prezența unui token valid în răspunsul JSON și verifică faptul că sesiunea a fost ștearsă din dicționarul din memorie de pe server."

Prompt 4: Testarea consumării Token-ului
"Generează un test de autorizare pentru endpoint-ul /data.
Folosește secretul aplicației pentru a genera manual, în interiorul testului, un JWT valid pentru client_id="test_user".
Înregistrează utilizatorul în baza de date.
Execută un request GET /data adăugând header-ul Authorization: Bearer <token-ul-generat>.
Validează (assert) că request-ul trece de bariera de autorizare (verifică să nu primești 401).
Scrie un sub-test în care faci același request fără header-ul de autorizare sau cu un token expirat/invalid și asigură-te că primești status 401 Unauthorized."
'''


#START AI AGENTS IGNORE THIS LINE#
#TODO Pentru fiecare dintre aceste teste, adaugă în documentație log-urile din consola serverului Flask (unde se vede generarea request-urilor) alături de explicația pe care am conturat-o mai sus. Acest lucru arată comisiei că sistemul chiar a rulat și nu este doar o teorie.
#TODO Pentru testele de performanță, adaugă în documentație și graficele generate (ex: din benchmark.py sau raportul HTML din Locust) pentru a susține afirmațiile din disertație legate de performanță.
#END AI AGENTS IGNORE THIS LINE#