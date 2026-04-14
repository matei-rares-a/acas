'''
1. Prompt pentru Implementarea OAuth Local (Baseline)
Acesta este primul pas necesar pentru a avea un termen de comparație valid.
"Acționează ca un Backend Developer. Adaugă în server.py un endpoint nou /login/classic pentru a simula un flux de autentificare tradițional.
Endpoint-ul trebuie să primească client_id și password în clar.
Folosește librăria bcrypt pentru a verifica parola (simulează extragerea hash-ului din baza de date și verificarea lui).
Dacă verificarea reușește, returnează un JWT identic cu cel din fluxul Schnorr.
Include header-ul X-Response-Time pentru a măsura latența acestui proces.
Asigură-te că endpoint-ul este izolat și nu afectează logica ZKP existentă."

2. Prompt pentru Micro-Benchmarking Client-Side (JS)
Măsurarea costului computațional pe dispozitivul utilizatorului este critică pentru ZKP, deoarece mută efortul de la server la client.
"Scrie un script de test în JavaScript (care poate fi rulat în consola browserului sau integrat în auth.js) pentru a măsura performanța operațiunilor criptografice pe client:
Măsoară timpul necesar pentru 100 de iterații ale funcției modPow folosind numere de 2048 biți.
Măsoară timpul pentru derivarea parolei folosind derivePasswordX (SHA-256).
Calculează media, minimul și maximul în milisecunde.
Rezultatele trebuie să fie afișate într-un tabel formatat în consolă, gata pentru a fi incluse în documentația de performanță."

3. Prompt pentru Profilarea Consumului de Resurse (CPU/RAM)
O critică comună a sistemelor stateful (care mențin sesiuni în memorie) este consumul de RAM sub asediu.
"Scrie un script Python de monitorizare (monitor_resources.py) care să ruleze în paralel cu serverul Flask în timpul testelor de sarcină:
Folosește librăria psutil pentru a înregistra consumul de CPU (%) și RAM (MB) al procesului Flask.
Măsoară dimensiunea obiectului sessions (numărul de intrări active) la fiecare secundă.
Salvează datele într-un fișier CSV cu timestamp-uri.
Scriptul trebuie să poată detecta momentul în care sesiunile expiră (după cele 5 secunde setate) și să evidențieze eliberarea memoriei."

4. Prompt pentru Teste de Sarcină (Locust - Throughput)Acesta generează scriptul pentru a măsura câte cereri pe secundă (RPS) poate duce serverul tău."Creează un fișier locustfile.py pentru a compara Throughput-ul celor două metode:Definește două task-uri: test_schnorr_login (care face fluxul /login/commit urmat de /login/verify) și test_classic_login (care apelează /login/classic).Pentru test_schnorr_login, simulează corect logica de client: primește challenge-ul și calculează soluția $s$ înainte de a trimite verificarea.Configurează Locust să ruleze teste incrementale (10, 50, 100 de utilizatori concurenți).Raportul final trebuie să compare Requests Per Second (RPS) și Failure Rate pentru ambele metode."

5. Prompt pentru Analiza Statistică și Vizualizare (Grafice)
După ce ai datele, ai nevoie de o modalitate de a le prezenta academic.
"Scrie un script Python folosind pandas și matplotlib care să preia rezultatele din testele anterioare (CSV-uri) și să genereze următoarele grafice pentru disertație:
Bar Chart: Compararea latenței medii (ms) între Schnorr Verify și Bcrypt Verify.
Line Chart: Evoluția consumului de RAM în funcție de numărul de sesiuni active în dicționarul sessions.
Throughput Comparison: Un grafic care să arate RPS pentru ZKP vs Clasic la diferite niveluri de sarcină.
Salvează imaginile la rezoluție înaltă (300 DPI) potrivite pentru print."


'''