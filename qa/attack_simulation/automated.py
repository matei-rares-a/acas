'''
Context inițial pentru Agent
"Acționează ca un Penetration Tester / Security Researcher. Trebuie să validăm securitatea unui sistem de autentificare Zero-Knowledge Proof (Schnorr) implementat în Flask. Voi avea nevoie de teste automate (pytest) pentru simulările care pot rula în CI/CD. Pentru atacurile care necesită interceptarea fizică a rețelei sau interacțiune umană cu unelte externe (ex: Wireshark), nu scrie cod Python, ci generează un fișier SECURITY_AUDIT_MANUAL.md cu pașii exacți de reproducere, așteptările matematice și dovezile necesare."


Prompt 1: Simulare Data Breach (Server Compromise)Acest test demonstrează că un atacator care obține un dump al bazei de date nu poate folosi datele pentru a se autentifica, rezolvând problema scurgerilor de parole."Scrie un test de securitate E2E care simulează compromiterea bazei de date.Înregistrează un utilizator valid (alice_test) cu o parolă sigură, astfel încât secret_y să fie salvat în DB.Simularea breșei: Extrage direct din baza de date valoarea secret_y a lui alice_test (așa cum ar face un hacker cu acces SQL).Atacul: Încearcă să parcurgi fluxul de autentificare (POST /login/commit urmat de POST /login/verify), dar în etapa de calculare a lui solution_s, folosește valoarea furată secret_y în loc de cheia privată $x$ (ex: calculează $s = r + c \cdot y \pmod q$).Validează (assert) că serverul respinge acest răspuns cu 401 Unauthorized și mesajul verification failed, demonstrând că furtul cheii publice nu compromite contul."


Prompt 2: Simulare Replay Attack strict pe sesiune
Aici testăm dacă atacatorul poate captura session_id și solution_s pentru a le refolosi.
"Scrie un test automat care simulează un Replay Attack asupra payload-ului de validare.
Execută un flux de login ZKP complet și valid pentru un utilizator (Commitment -> primire challenge -> calculare răspuns -> Verify).
Salvează exact header-ul X-Auth-Session și body-ul JSON {"solution_s": "..."} folosite la pasul de Verify.
Atacul: Execută imediat un nou request POST /login/verify folosind datele salvate la pasul 2.
Validează (assert) că request-ul malițios primește HTTP 404 cu invalid session_id. Dicționarul de sesiuni trebuie să împiedice orice refolosire a nonce-ului de sesiune."


Prompt 3: Testarea impredictibilității (Weak RNG & Session Fixation)Un atacator ar putea încerca să ghicească challenge_c sau session_id dacă serverul folosește un generator de numere slabe."Scrie un test de securitate care validează entropia și unicitatea funcțiilor de generare (secrets.randbelow și secrets.token_urlsafe) folosite în /login/commit.Execută request-ul POST /login/commit de 1000 de ori consecutiv într-o buclă pentru același client_id.Stochează toate valorile challenge_c și session_id primite.Validează (assert) următoarele:Lungimea listei de session_id-uri unice este exact 1000 (0 coliziuni, prevenind Session Fixation).Lungimea listei de challenge_c unice este exact 1000 (0 coliziuni, prevenind Challenge Prediction).Toate valorile challenge_c se încadrează strict în intervalul $[1, Q-1]$."
'''