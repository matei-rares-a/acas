'''
Context inițial (de reamintit agentului)
"Acționează ca un Security QA Automation Engineer. Scrie teste pentru urmatoarele prompturi"

Prompt 1: Testarea validării matematice (Parolă/Dovadă greșită)Acest test demonstrează că o persoană care ghicește sau greșește parola nu poate trece de ecuația $G^s == t \cdot y^c \pmod P$."Scrie un test de integrare E2E pentru fluxul de login ZKP care simulează introducerea unei parole greșite.Înregistrează în baza de date de test utilizatorul hacker_test cu un secret_y valid calculat pe baza unei parole corecte.Execută un request POST /login/commit valid și obține challenge_c și session_id.Calculează solution_s folosind o valoare $x$ (parolă) greșită/diferită față de cea cu care a fost generat secret_y.Trimite request-ul POST /login/verify cu acest solution_s invalid.Validează (assert) că răspunsul HTTP are statusul 401 Unauthorized și corpul {"reason": "verification failed"}.Asigură-te că sesiunea a fost distrusă (ștearsă din memorie) chiar și în caz de eșec."
Prompt 2: Simulare Replay Attack (Refolosirea soluției/sesiunii interceptate)Acest test validează afirmația din disertație conform căreia "Traffic Sniffing" nu permite refolosirea mesajelor."Scrie un test de securitate care simulează un Replay Attack asupra endpoint-ului /login/verify.Parcurge un flux complet și valid de autentificare ZKP pentru un utilizator de test (Commitment -> primire $c$ -> calculare $s$ valid).Execută request-ul POST /login/verify cu soluția calculată și validează că returnează 200 OK (Autentificare reușită).Imediat după, simulează un atacator care a interceptat traficul: execută exact același request POST /login/verify, cu același session_id și același solution_s.Validează (assert) că al doilea request este respins cu 404 Not Found și mesajul {"reason": "invalid session_id"}, demonstrând că starea (nonce-ul de sesiune) este de unică folosință și previne replay-urile."
Prompt 3: Atacul Subgrupurilor (Subgroup Confinement Attack)
Aici demonstrezi de ce ai funcția is_subgroup_member în cod. E un test criptografic avansat care va impresiona comisia.
"Scrie un test de securitate care simulează trimiterea unor parametri criptografici malițioși (în afara subgrupului valid).
Creează un test parametrizat (folosind @pytest.mark.parametrize) care să testeze endpoint-ul POST /login/commit.
Folosește valori malițioase pentru commitment_t: 0, 1, o valoare negativă (-5), și o valoare mai mare decât P (P + 10).
Pentru fiecare valoare, trimite request-ul către /login/commit.
Validează (assert) că serverul respinge TOATE aceste cereri cu status 422 Unprocessable Entity și mesajul {"reason": "invalid commitment"}.
Scrie un sub-test identic pentru endpoint-ul POST /register care să trimită aceste valori malițioase în câmpul secret_y și validează că se returnează status 422 cu {"reason": "invalid public value"}."

Prompt 4: Expirarea ferestrei de timp (Session Timeout)
Protocolul nu lasă atacatorului timp infinit să încerce să spargă criptografia sau să facă brute-force pe challenge.
"Scrie un test de integrare care validează mecanismul de timeout al sesiunilor ZKP.
Execută POST /login/commit pentru un utilizator valid și obține session_id.
Folosește librăria freezegun sau fă un mock pe time.time() în Python pentru a simula trecerea a 6 secunde în sistem (deoarece pragul din cod este de 5 secunde).
Trimite request-ul POST /login/verify cu un solution_s matematic corect, asociat acelui session_id.
Validează (assert) că răspunsul serverului este status 300 Multiple Choices cu mesajul {"reason": "session expired"}.
Verifică în memoria serverului (dicționarul sessions) că sesiunea respectivă a fost ștearsă automat."

Prompt 5: Conflict de Sesiune (Hijacking / Overwrite prevention)
Ce se întâmplă dacă un atacator trimite un nou "commit" în timp ce tu ești deja în faza de rezolvare a challenge-ului?
"Scrie un test care validează protecția la concurența sesiunilor de login (prevenirea stării corupte).
Execută un POST /login/commit pentru utilizatorul alice_test. Sesiunea 1 este creată.
Simulează un comportament malițios sau o eroare de client: execută un al doilea request POST /login/commit PENTRU ACELAȘI client_id="alice_test", fără a finaliza prima sesiune.
Validează (assert) că serverul detectează conflictul și returnează status 409 Conflict cu mesajul {"reason": "existing commitment found, start a new session"}.
Validează că, drept măsură de securitate defensivă, Sesiunea 1 (cea veche) a fost invalidată/ștearsă din dicționarul sessions."
'''