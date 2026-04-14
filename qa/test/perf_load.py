'''
Context inițial (de reamintit agentului)
"Acționează ca un Security QA Automation Engineer. Scrie teste pentru urmatoarele prompturi"

Prompt 1: Crearea unui Baseline (Endpoint Clasic de Referință)
Înainte de a testa performanța, ai nevoie de un termen de comparație. Acest prompt generează un flux "clasic" de login pe același server, pentru a putea compara merele cu merele.
"Adaugă un endpoint nou în aplicația Flask (POST /login/classic) care să simuleze un flux de login clasic.
Acest endpoint va primi {"client_id": "user", "password": "parola"} în clar.
Implementează validarea: verifică dacă client_id există în baza de date.
Folosește librăria bcrypt sau passlib (sau un hash SHA256 simplu pentru simulare) pentru a valida parola (comparativ cu un hash stocat).
Dacă validarea trece, generează un JWT (exact la fel ca la login/verify) și returnează-l.
Adaugă și acestui endpoint header-ul X-Response-Time.
Adaugă teste unitare de bază pentru acest endpoint ca să fim siguri că funcționează corect ca referință (baseline)."

Prompt 2: Testarea de Latență (Micro-Benchmarking Client și Server)Acest test măsoară exact cât timp durează operațiunile matematice grele (exponențierile modulare de 2048 de biți)."Scrie un script Python separat (ex: benchmark.py) folosind librăria timeit pentru a măsura latența componentelor individuale ale sistemului nostru ZKP vs. Clasic.Măsoară timpul de execuție pentru funcțiile de client: derivarea parolei (derivePasswordX) și generarea angajamentului $t = g^r \pmod p$.Măsoară timpul de execuție pentru funcțiile de server ZKP: Endpoint-urile /login/commit (generare $c$) și /login/verify (calculul complex $t \cdot y^c \pmod p$).Măsoară timpul de execuție pentru funcția de server Clasic: Endpoint-ul /login/classic (verificare parolă + generare JWT).Rulează fiecare măsurătoare de 100 de ori și calculează Timpul Mediu (Average Response Time) și Percentila 95 (P95) în milisecunde (ms).Afișează rezultatele într-un format tabelar în consolă (pentru a putea fi extrase ușor pentru lucrare)."

Prompt 3: Testarea de Scalabilitate (Load Testing cu Locust)Acest prompt îți va genera un instrument cu care să simulezi sute de utilizatori simultani (pentru a vedea cum se comportă dicționarul de sesiuni și calculele asincrone)."Creează un fișier locustfile.py pentru a efectua teste de sarcină (Load Testing) folosind framework-ul Locust.Definește un HttpUser (simulând un client).Sarcina 1 (ZKP Login): Implementează fluxul complet ZKP: trimite request la /login/commit, extrage challenge_c și session_id, calculează o soluție validă $s$ local (în Locust) și trimite request la /login/verify. Măsoară întregul flux ca o singură tranzacție de login (folosind self.environment.events.request.fire).Sarcina 2 (Classic Login): Implementează trimiterea unui request simplu către /login/classic.Asigură-te că Locust generează date dinamice/unice (client_id, password) la fiecare cerere pentru a evita caching-ul.Configurația trebuie să permită lansarea din linia de comandă, generând un raport HTML comparativ."

Prompt 4: Testarea Amprentei de Memorie (Sesiuni Concurente)
Acest test adresează una din criticile principale ale protocolului tău din disertație: necesitatea de a menține o stare (stateful) între pașii Commit și Verify.
"Scrie un script Python care testează consumul de memorie al dicționarului sessions din serverul Flask.
Injectează treptat 1.000, apoi 10.000, apoi 50.000 de cereri invalide de POST /login/commit (fără a apela vreodată /login/verify).
Măsoară dimensiunea în memorie (RAM) a dicționarului sessions la fiecare pas.
După trecerea timeout-ului de 5 secunde, validează că memoria a fost eliberată corect. (Acest test este crucial pentru a demonstra că un atacator nu poate doborî serverul prin epuizarea memoriei cu angajamente false - un atac DoS pe resursa de memorie)."

'''



