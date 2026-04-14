'''
Context inițial (de reamintit agentului)
"Acționează ca un Security QA Automation Engineer. Scrie teste de integrare avansate (corner cases/boundary tests) în Python cu pytest și Flask test_client pentru un sistem ZKP Schnorr. Concentrează-te pe endpoint-urile /register, /login/commit și /login/verify. Nu testa JWT-ul, ci strict matematica, limitele parametrilor și starea sesiunilor din memoria serverului."

Prompt 1: Testarea limitelor matematice ale soluției (Boundary Values pe $S$)Codul tău validează if s < 0 or s >= Q:. Trebuie să ne asigurăm că extremele absolute sunt gestionate corect și nu produc crash-uri (ex: Overflow sau excepții de parsare)."Scrie un test parametrizat (@pytest.mark.parametrize) care să testeze limitele valorii solution_s pe endpoint-ul POST /login/verify.
1. Formează o sesiune validă în prealabil (POST /login/commit) pentru a avea un session_id valid.
2. Testează următoarele valori extreme (corner cases) pentru solution_s:O valoare negativă: -1Limita superioară exactă: Q (adică (P - 1) // 2)O valoare peste limită: Q + 1O valoare extrem de mare: P * 10 (pentru a testa comportamentul memoriei/parserului la BigInt)
3. Validează (assert) că serverul respinge toate aceste cereri cu HTTP 422 Unprocessable Entity și motivul invalid solution.Asigură-te că testul verifică eliberarea dicționarului sessions chiar și după un solution_s formatat ciudat."


Prompt 2: "The Trivial Zero/One Attack" (Extremele pe Subgrup)Un atacator ar putea trimite valori matematice banale ($0$ sau $1$) sperând să "anuleze" o ecuație de pe server (deoarece $1^X = 1$ și $0^X = 0$)."Scrie un test criptografic de tip Corner Case pentru endpoint-urile de Setup și Commit, încercând atacul valorilor banale.Încearcă să înregistrezi un utilizator (POST /register) trimițând secret_y cu valorile: 0, 1, -1 și P-1.
2. Validează că funcția is_subgroup_member blochează cu succes aceste valori, returnând 422 Unprocessable Entity.
3. Încearcă un request POST /login/commit trimițând commitment_t cu aceleași valori: 0, 1, -1, P-1.Validează (assert) că serverul returnează HTTP 422 pentru toate și NU creează o sesiune orfană în dicționarul din memorie pentru aceste intrări invalide."


Prompt 3: Race Conditions la Crearea Sesiunilor (Concurență asincronă)
Ce se întâmplă dacă un client are un bug de rețea sau un atacator rulează un script care dă "spam" pe butonul de login în aceeași milisecundă?
"Scrie un test de concurență (Race Condition) folosind concurrent.futures.ThreadPoolExecutor pentru a apela POST /login/commit simultan.
1. Creează un utilizator valid de test în baza de date.
2. Lansează 10 request-uri POST /login/commit PENTRU ACELAȘI client_id, rulând în thread-uri paralele (cât mai aproape de aceeași milisecundă).
3. Capturează toate răspunsurile HTTP.
4. Validează (assert) următoarele condiții stricte de stabilitate a stării:
Nu există erori de tip HTTP 500 (Server Crash).
Cel puțin un request a primit 409 Conflict (dovedind că serverul a curățat o sesiune concurentă).
- La finalul testului, în dicționarul sessions există exact o singură sesiune activă pentru acel client_id, prevenind memory leaks."


Prompt 4: Manipularea tipurilor de date (Type Confusion & Payload malformat)
Serverul așteaptă stringuri care pot fi convertite în numere întregi mari (BigInt). Ce se întâmplă dacă îi dăm formate ciudate?
"Scrie un test de validare a parserului de date (validate_int_field) pentru endpoint-ul POST /login/verify.
Creează un session_id valid prin POST /login/commit.
Trimite request-ul către /login/verify manipulând câmpul solution_s în următoarele moduri:
Ca string cu zecimale (Float): "12345.67"
Ca notație științifică: "1e20"
Ca string non-numeric: "abc123"
Null/None: null
Validează (assert) că aplicația nu dă crash cu ValueError sau TypeError (HTTP 500), ci tratează elegant eroarea returnând 422 (sau 400) conform comportamentului de fallback din funcția validate_int_field."

Prompt 5: Manipularea la limită a Header-ului de Sesiune
Sesiunea dintre Commit și Verify este legată doar de un header HTTP. Acesta poate fi manipulat de un proxy sau de un atacator.
"Scrie un test E2E care acoperă corner cases pentru header-ul X-Auth-Session folosit în etapa de verificare a protocolului Schnorr.
Realizează pasul POST /login/commit cu succes.
Apelează POST /login/verify dar cu următoarele scenarii pentru header-ul X-Auth-Session:
Omiterea totală a header-ului. (Assert: HTTP 400 "missing session_id")
Un header complet gol (Empty string).
Un header care conține doar spații albe ("   ").
Un session_id extrem de lung (peste 1000 caractere) pentru a verifica dacă dicționarul de sesiuni crapă la căutare.
Validează (assert) că serverul returnează erorile corecte (400 sau 404) și menține o stare stabilă (fără Internal Server Error)."

'''