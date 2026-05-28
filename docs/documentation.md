3: Descrierea Cerințelor Funcționale 
Focus pe comportamentul actorilor și regulile de business. 
  
3.1. Actorii Sistemului 
1. Clientul (Prover / Solicitant): Poate fi o aplicație web, mobilă sau un script .  Dorește să obțină acces. 
2. Resource owner: Acesta deține secretul (parola/cheia privată) local. 
3. Serverul de Autentificare (Verifier / Emitent de Token): Verifică identitatea clientului fără a-i cunoaște parola, ci doar cheia publică/secretul, și emite token-uri de acces (OAuth Access Tokens). 
  
3.2. Cerințe Funcționale Principale 
A. Înregistrarea (Setup - Precondiție) 
1.	Generarea Identității:   Sistemul trebuie să permită clientului să își genereze cheia public/secretul criptografice  local. 
2.	Înregistrarea Cheii Publice:   Clientul trebuie să poată transmite doar Cheia Publică și un identificator (ex: `client_id` sau `username`) către server. Serverul stochează asocierea `client_id` <-> `public_key`.  Cheia privata/parola nu paraseste niciodata clientul  
  
B. Autentificarea ZKP (Protocolul Schnorr)   
1.	Inițierea Sesiunii (Commitment):   Clientul trebuie să poată iniția o cerere de login trimițând un angajament criptografic temporar (fără a trimite `client_id` și `password` în clar). 
2.	Emiterea Provocării (Challenge):   Serverul trebuie să răspundă automat la inițiere cu o "provocare" (un număr aleatoriu unic), pe care clientul nu o putea anticipa. 
3.	Generarea Răspunsului:   Clientul trebuie să poată calcula o dovadă matematică folosind: secretul său, angajamentul inițial și provocarea primită. 
4.	Verificarea:   Serverul trebuie să valideze dovada. Dacă matematica este corectă, serverul are garanția matematică că utilizatorul este cine pretinde a fi. 
 
C. Autorizarea și Sesiunea (OAuth)   
1.	Emiterea Tokenului:   Dacă verificarea (B.4) reușește, serverul trebuie să genereze și să returneze un   Access Token   (ex: JWT) semnat, cu o valabilitate limitată. 
2.	 Accesarea Resurselor:   Pentru cererile ulterioare, clientul trebuie să se autentifice folosind doar Tokenul primit (Bearer Token), fără a repeta procesul ZKP la fiecare request. 
  
D. Securitate și Constrângeri   
1.	Zero-Knowledge:   În niciun moment al procesului de autentificare, parola/cheia privată nu trebuie să fie transmisă prin rețea, nici măcar criptată. 
2.	 Protecție la Replay:   O interceptare a traficului (sniffing) nu trebuie să permită unui atacator să refolosească datele capturate pentru a se autentifica ulterior. 
 
3.3. Cerințe de Autorizare Delegată:
Binding între Identitate și Token: Sistemul trebuie să garanteze că un Access Token emis este legat de sesiunea ZKP care l-a generat. Această proprietate este asigurată prin includerea identificatorului de sesiune, a adresei de rețea și a angajamentului criptografic în calculul provocării, realizând o legare de canal (session binding) care împiedică transferul token-ului între sesiuni sau contexte de rețea diferite.
Separarea Resurselor: Serverul de Autorizare trebuie să poată valida token-ul fără a re-executa protocolul Schnorr, utilizând exclusiv cheia publică a utilizatorului stocată la momentul înregistrării. Această proprietate asigură că procesul de verificare a autorizării este stateless și eficient din punct de vedere computațional.

3.4. Reziliență la Interceptare (Anti-Sniffing):
Sistemul trebuie să permită autentificarea chiar și pe canale nesigure sau compromise (Perfect Forward Secrecy la nivel de aplicație). Securitatea nu este condiționată de confidențialitatea canalului de transport: chiar dacă un adversar înregistrează integral traficul HTTP în clar, el nu poate extrage secretul x al utilizatorului, deoarece valorile transmise (t, c, s) nu determină matematic valoarea x în absența nonce-ului efemer r, necunoscut atacatorului. Utilizarea HTTPS adaugă un nivel suplimentar de securitate a canalului, dar nu este o precondiție pentru proprietatea zero-knowledge a protocolului.
 
4: Arhitectura Aplicației / Sistemului  
Detaliile tehnice, explicând matematica din spatele codului tău și cum se integrează în fluxul OAuth. 
  
4.1. Arhitectura  
Sistemul este compus dintr-o arhitectură Client-Server RESTful. 
Limbaj:   Python (conform fișierelor tale). 
Framework:   Flask (pentru API). 
Model Criptografic:   Logaritm Discret pe Grupuri Finite (Schnorr pe grupuri multiplicative modulo ). 
 
4.2. Detalii Tehnice ale Schemei de identificare Schnorr (Matematica) 
Fie p un numar prim sigur (safe prime), astfel incat: 
p = 2 * q + 1, unde q este de asemenea numar prim. Se considera grupul multiplicativ Zp* = {1, 2, ..., p-1}. 
Se alege un generator g din Zp* al subgrupului de ordin q, definit astfel: 
g = h^2 mod p, cu g diferit de 1 si g^q mod p = 1, unde h apartine Zp*. 

Cheia privata: 
x apartine Zq 
Cheia publica: 
y = g^x mod p 
1.	Alegerea valorii aleatoare: 
r este ales aleator din Zq 
2.	Calculul angajamentului: 
t = g^r mod p din Zp*
3.	Generarea provocarii (challenge): 
c apartine Zq 
4.	Calculul raspunsului: 
s = (r + c * x) mod q din Zq
5.	Verificare: 
Se verifica egalitatea: 
g^s mod p = t * y^c mod p 
unde: 
left = g^s mod p 
right = t * y^c mod p 
Autentificarea este acceptata daca left = right. 
 
 
4.3 Fluxul de mesaje teoretic folosind Schnorr intr-o arhitectura Client- Server:   
Setup: Pre-Calcularea numerelor P (p>2048 biti) si G, alegerea unui numar/parola X 
Parametri Publici:   P si G 
Cheia Privată ():   Parola X 
Cheia Publică ():  Secret y = g^x mod p) 
 
Etapa 0: Inregistrarea (Client -> Server) 
Clientul trimite catre server secretul y impreuna cu un id pentru asocierea id -> y 
 
Etapa 1: Commitment (Client -> Server)   
Clientul alege un număr aleatoriu  r=[1, p-1] si calculeaza commitment t= g^r mop p 
Trimite id și t către server. 
 Note: un angajament de la client că știe un secret legat de ceva, fără a-l dezvălui. 
  
Etapa 2: Challenge (Server -> Client)   
Serverul primește  commitment-ul și îl memorează temporar. 
Generează un număr aleatoriu ca challenge c = [1, p-2] si il trimite la client. 
Note: Numarul aleator  previne atacurile de tip "Replay". Dacă un atacator înregistrează traficul, nu va putea refolosi -ul vechi pentru un nou . 
 
Etapa 3: Response/Solution (Client -> Server)   
Clientul calculează solutia s = r + c*x mod p si il trimite catre server 
   
Etapa 4: Verification (Server)   
Serverul verifică daca left == right, unde left = g^s mod p si right = t* y^c mod p 
Dacă egalitatea ține, serverul emite Tokenul catre client. 
 
 
   
4.4. Diagrama Procesului   (https://mermaid.js.org/ )
Diagrama 1: Fluxul de înregistrare
Fluxul de înregistrare descrie modul în care un client derivă cheia privată x din credențialele locale (utilizând scrypt ca funcție de derivare a cheii), calculează cheia publică Schnorr y = G^x mod P și transmite exclusiv perechea (client_id, y) către server. Serverul validează apartenența lui y la subgrupul de ordin Q (verificând y^Q ≡ 1 mod P) și stochează asocierea client_id → y. Credențialele brute nu traversează niciodată canalul de comunicație. Diagrama completă este disponibilă în fișierul diagrams/diagram_registration_flow.mmd.

Diagrama 2: Fluxul de Autentificare (Sequence Diagram)
Fluxul de autentificare acoperă cei patru pași ai protocolului Schnorr: (1) clientul generează un nonce r și calculează angajamentul t = G^r mod P, pe care îl transmite împreună cu client_id; (2) serverul calculează provocarea c ca funcție hash deterministă a contextului sesiunii (adresă IP, User-Agent, session_id, client_id, t), realizând legarea de canal; (3) clientul calculează dovada s = (r + c·x) mod Q și o transmite cu identificatorul de sesiune în antet; (4) serverul verifică egalitatea G^s ≡ t · y^c (mod P) și, în caz de succes, emite un JWT semnat HS256. Diagrama completă este disponibilă în fișierul diagrams/diagram_login_flow.mmd.

Diagrama 3: Consumul Tokenului (Post-Autentificare)
Mașina de stări a clientului descrie ciclul de viață complet: de la starea inițială Idle, prin derivarea cheii, angajament, provocare, verificare, până la starea Authenticated. Token-ul JWT obținut este utilizat ca Bearer Token pentru accesul la resursele protejate. La expirarea token-ului (după 3600 de secunde), clientul revine la starea Idle și reia protocolul. Diagrama completă este disponibilă în fișierul diagrams/diagram_auth_state_machine.mmd.

Diagrama 4: comparatie intre ZKP si OAuth 2.0
Diagramă care să arate unde se încadrează Schnorr în fluxul OAuth 2.0 (înlocuind client_secret cu ZKP Proof). 
 Etapa 	  Metoda HTTP 	Parametri Cheie 	Rol în OAuth 
Commitment 	POST /login/commit 	client_id, t = g^r 	Inițiere Grant 
Challenge 	Response 	c (random challenge) 	Nonce de sesiune 
Proof 	POST /login/verify 	s = r + cx 	Client Authentication 
Token Issue 	Response 	access_token (JWT) 	Access Grant 
  
 
 
5. Structura si Serializarea Mesajelor in Protocolul HTTP 
Pentru a asigura interoperabilitatea si o comunicare determinista intre client si server, prezentul protocol defineste in mod formal schema de date, antetele necesare si formatul mesajelor transmise. 
5.1. Antete HTTP si Autentificarea de tip Bearer 
In urma finalizarii cu succes a protocolului de autentificare Schnorr, serverul de autorizare emite un token de acces de tip JSON Web Token (JWT). Pentru cererile ulterioare destinate accesarii resurselor protejate, reluarea demonstratiei Zero-Knowledge nu mai este necesara. Clientul va atasa tokenul de acces la fiecare cerere HTTP subsecventa. Toate schimburile de date vor utiliza tipul de continut application/json. 
Cerinte pentru antete in faza de autorizare: 
Authorization: Bearer <token_jwt> 
Content-Type: application/json 
5.2. Structura Sarcinii Utile (JSON Payload) 
Mesajele schimbate intre entitati pe parcursul procesului de autentificare vor respecta o structura JSON stricta. Definitia campurilor pentru fiecare etapa este detaliata mai jos. 
Etapa de Angajament (Commitment) Aceasta faza initiaza procesul, solicitantul trimitand un angajament criptografic.  
Cerere POST catre punctul terminal /login/commit { "client_id": "string", "commitment_t": "number" }  
Raspunsul emitentului (Server) { "status": "committed", "challenge_c": "number" } 
Etapa de Verificare (Verify) In aceasta faza, solicitantul raspunde provocarii primite de la emitent, oferind o solutie matematica valabila.  
Cerere POST catre punctul terminal /login/verify { "client_id": "string", "solution_s": "number" }  
Raspunsul emitentului in caz de succes { "status": "authenticated", "token": "string", "client_id": "string" } 
5.3. Gestionarea Starii si Securitatea la Nivel HTTP 
Mentinerea Starii (Stateful vs. Stateless) Protocolul Schnorr necesita retinerea unei stari temporare intre faza de angajament si cea de verificare. In implementarile de referinta singulare, serverul poate stoca valorile asociate angajamentului si provocarii in memoria volatila. Pentru implementari in sisteme distribuite si scalabile, se impune externalizarea acestei stari catre baze de date in memorie, cu timp scurt de retinere, sau utilizarea unor mecanisme de directionare persistenta a sesiunilor catre acelasi nod. 
Politici de Partajare a Resurselor (CORS) In scenariile arhitecturale in care aplicatia client si componenta server sunt gazduite pe origini diferite, serverul trebuie sa implementeze restrictii si permisiuni Cross-Origin Resource Sharing (CORS) explicite. Acestea asigura functionalitatea cererilor preflight si permit clientilor sa interactioneze programatic cu punctele terminale de autentificare. 
Gestionarea token-urilor la Nivelul Clientului se recomanda evitarea stocarii jetonului de acces in mecanisme de stocare persistenta accesibile prin scripturi, cum ar fi localStorage, pentru a diminua suprafata de atac in cazul vulnerabilitatilor Cross-Site Scripting (XSS). O abordare superioara din punct de vedere al securitatii este incapsularea jetonului in cookie-uri gestionate exclusiv de browser, configurate strict cu atributele HttpOnly, Secure si o politica SameSite limitativa. 
 
  
5.4. Definirea Protocolului în Notație ABNF 
Pentru a asigura interoperabilitatea, mesajele schimbate între Client (Prover) și Server (Verifier) trebuie să respecte următoarea structură de date.A. Parametrii de Identitate și ZKPValorile numerice rezultate din calculele Schnorr (peste grupul Zp) sunt reprezentate ca șiruri de caractere hexazecimale sau întregi mari în format JSON. 
 
Definiții de bază 
client-id  	= 1*( ALPHA / DIGIT / "-" / "_" ) 
schnorr-value  = 1*DIGIT ; Reprezentarea întreagă a valorilor (g^x, g^r, etc.) 
jwt-token  	= 1*( ALPHA / DIGIT / "." / "-" / "_" ) 
  
Structura mesajelor JSON 
registration-payload = "{" "client_id" ":" q-string "," "secret_y" ":" schnorr-value "}" 
commitment-payload   = "{" "client_id" ":" q-string "," "commitment_t" ":" schnorr-value "}" 
challenge-payload	= "{" "status" ":" q-string "," "challenge_c" ":" schnorr-value "}" 
verify-payload   	= "{" "client_id" ":" q-string "," "solution_s" ":" schnorr-value "}" 
auth-success-payload = "{" "status" ":" q-string "," "token" ":" q-string "}" 
  
q-string         	= DQUOTE 1*(VCHAR) DQUOTE 

5.5. Detalierea Câmpurilor și Semantica Mesajelor 
Fiecare câmp are un rol critic în prevenirea atacurilor de tip Traffic Sniffing și Replay: 
●	client_id: Identificatorul unic al utilizatorului. Serverul îl folosește pentru a regăsi cheia publică y stocată la înregistrare. 
●	commitment_t (t = g^r mod p): Angajamentul efemer. Acesta "leagă" sesiunea curentă de un număr aleatoriu r care nu este niciodată dezvăluit. 
●	challenge_c (c): Provocarea generată de server. Aceasta forțează clientul să demonstreze că deține secretul x în timp real, făcând interceptările anterioare inutile (protecție la replay). 
●	solution_s (s = r + cx mod q): Dovada matematică. Aceasta este singura valoare care "atestă că ești eligibil pentru a fi autentificat" fără a partaja secretul. 
●	token: Un JSON Web Token (JWT) semnat de server. Acesta servește drept dovadă de autorizare pentru resurse, eliminând nevoia de a repeta procesul ZKP la fiecare request. 
 
6. Considerente de securitate 
Sistemul propus este conceput pentru a rezolva vulnerabilitățile fundamentale ale metodelor tradiționale de autentificare, bazându-se pe proprietăți matematice demonstrabile. 
Fundamentul Criptografic și Rezistența la "Store Now, Decrypt Later" (Traffic Sniffing) 
Securitatea sistemului nu se bazează pe criptarea canalului de transport (TLS), ci pe dificultatea computațională a calculării problemei logaritmului discret într-un grup de ordin prim q. 
În TLS clasic (HTTPS), clientul trimite parola prin tunel. Dacă cineva interceptează traficul criptat și, ulterior, sparge cheia privată a serverului (sau folosește un calculator cuantic), parola va fi expusă în clar (ex: POST /login {password: "secret"}). 
În arhitectura Schnorr, atacatorul va vedea doar numere asociate unui proces tranzitoriu (t, c, s). Ecuația de verificare pe server este g^s = t * y^c mod p. Chiar dacă atacatorul salvează aceste mesaje decriptate, extragerea lui x (parola) din ele necesită rezolvarea ecuației s = r + c * x mod q. Deoarece r este un nonce unic (randomness necunoscut atacatorului), x este protejat de secretul perfect al acestuia. Astfel, arhitectura este imună la compromiterea canalului de transport. 
Fără "Shared Secret" (Eliminarea riscurilor la scurgeri de date) 
Spre deosebire de modelele clasice, clientul nu transmite parola, ci doar o dovadă de cunoaștere a acesteia. Serverul nu stochează x-ul, ci deține doar cheia publică asociată y = g^x mod p. Dacă baza de date a serverului este compromisă (ex: SQL Injection, leak de date), atacatorii pot fura doar cheile publice. Aceștia nu pot impersona utilizatorii, deoarece x-ul a rămas mereu exclusiv pe dispozitivul clientului. 
Reziliența la Replay și Session Hijacking 
Structura protocolului previne refolosirea mesajelor interceptate datorită challenge-ului unic (c). Serverul generează un c nou la fiecare încercare de conectare. Chiar dacă un atacator interceptează soluția s, aceasta este validă strict și exclusiv pentru acel c și pentru angajamentul inițial t generate în respectiva sesiune. Suplimentar, token-ul JWT emis la finalizare are un câmp de expirare (exp), limitând fereastra de oportunitate pentru un atacator care ar reuși să fure token-ul. 
Eliminarea Intermediarilor (Self-Sovereign Identity) 
Arhitectura funcționează într-un mod descentralizat din perspectiva validării: serverul tău devine propria Autoritate de Certificare pentru sesiunea curentă. Sistemul nu depinde de entități terțe (ex: validări de tip Google Sign-In sau Facebook) pentru a dovedi identitatea; clientul demonstrează identitatea sa matematic și direct către serverul cu care dorește să comunice. 


7. Validarea și Testarea

7.1. Strategia și Metodologia de Testare

Validarea sistemului a fost realizată printr-o strategie de testare pe mai multe niveluri, care acoperă corectitudinea funcțională, robustețea la intrări neașteptate, securitatea criptografică, integrarea cu fluxurile OAuth2 și performanța sub sarcină. Suita de testare automatizată, implementată cu framework-ul pytest, este organizată în cinci categorii distincte, fiecare adresând o dimensiune specifică a calității sistemului:

1. Cazuri pozitive (pos_case.py) — validează fluxurile nominale ale protocolului.
2. Cazuri negative (neg_case.py) — verifică respingerea corectă a cererilor neautorizate și a atacurilor cunoscute.
3. Cazuri limită (corner_case.py) — testează comportamentul la frontierele matematice ale grupului Schnorr și la intrări malformate.
4. Teste de securitate (security_case.py) — evaluează rezistența față de vectori criptografici de atac specifici schemei Schnorr.
5. Teste OAuth2 (oauth_case.py) — validează fluxurile de autorizare delegată (PKCE, Simple, Authlib).

Testele rulează împotriva unui client Flask de test fără server HTTP activ, garantând izolarea și reproductibilitatea. Starea bazei de date și sesiunile în memorie sunt reinițializate înaintea fiecărei suite, eliminând dependențele de ordine între teste.


7.2. Teste Funcționale

7.2.1. Cazuri Pozitive

Cazurile pozitive validează comportamentul corect al sistemului pe traseul nominal. Principalele scenarii acoperite sunt:

- Înregistrarea unui utilizator nou: serverul stochează exclusiv cheia publică y = G^x mod P, fără a reține parola în formă brută sau sub orice formă de hash calculabil din aceasta. Testul verifică explicit că înregistrarea serializată nu conține nici parola brută, nici hash-urile SHA-256, SHA-512 sau MD5 ale acesteia.

- Fluxul complet de autentificare (commit → verify): clientul generează un nonce r, calculează angajamentul t = G^r mod P, primește provocarea c, calculează dovada s = (r + c·x) mod Q și o transmite serverului. Serverul verifică egalitatea G^s ≡ t · y^c (mod P), emite un JWT și elimină sesiunea utilizată, prevenind reutilizarea.

- Consumul token-ului: un JWT valid permite accesul la resurse protejate (HTTP 200); un token absent, expirat sau invalid produce răspunsul HTTP 401.

7.2.2. Cazuri Negative

Cazurile negative validează că sistemul refuză explicit accesul în scenarii de autentificare eșuată sau de tentativă de fraudă:

- Parolă incorectă: dovada calculată cu un x greșit nu satisface ecuația de verificare; serverul returnează HTTP 401 și elimină sesiunea consumată, prevenind tentativele repetate pe aceeași sesiune.

- Atac de tip replay: reutilizarea unui (session_id, solution_s) deja utilizat cu succes produce HTTP 404, deoarece sesiunea a fost eliminată după prima verificare reușită.

- Expirarea sesiunii: dacă intervalul dintre commit și verify depășește fereastra TTL de 5 secunde, serverul returnează HTTP 401 cu motivul „session expired" și curăță starea aferentă.

- Commit dublu (Hijacking Prevention): o a doua cerere de commit pentru același client_id, înainte de finalizarea sesiunii existente, produce HTTP 409 și invalidează ambele sesiuni, eliminând posibilitatea de suprascriere silențioasă.

- Înregistrare duplicată: o a doua înregistrare cu același client_id produce HTTP 409, fără a modifica cheia publică deja stocată.

7.2.3. Cazuri Limită

Cazurile limită adresează frontierele matematice ale grupului Schnorr și robustețea la intrări malformate:

- Valori ale soluției solution_s în afara intervalului admis (negative, egale cu Q sau superioare lui Q) produc HTTP 422 cu mesajul „invalid solution" și elimină sesiunea.

- Valori triviale ale cheii publice y ∈ {0, 1, −1, P−1} la înregistrare sunt respinse cu HTTP 422, prevenind atacurile de subgrup mic (Small Subgroup Attack).

- Valori triviale ale angajamentului t la commit sunt respinse cu HTTP 422, fără crearea de sesiuni orfane.

- Cereri concurente de commit pentru același utilizator (10 fire de execuție simultane) nu produc eroare de server și lasă cel mult o sesiune activă, validând corectitudinea mecanismului de blocare cu mutex.

- Tipuri de date malformate pentru câmpurile numerice (float, notație științifică, șiruri, null, liste, obiecte) produc HTTP 400 sau 422, fără excepții negestionate.


7.3. Teste de Securitate

Testele de securitate evaluează rezistența protocolului față de vectori de atac specifici schemei de identificare Schnorr, organizați în trei categorii principale.

7.3.1. Legarea Angajamentului (Commitment Binding)

Un adversar care construiește un transcript simulator valid (t_sim, c, s_forged), unde t_sim = G^s · y^(−c) mod P este derivat liber fără cunoașterea lui r, nu poate reutiliza dovada s_forged împotriva sesiunii legate de t_real ≠ t_sim. Serverul respinge cu HTTP 401 orice soluție al cărei angajament corespunzător nu coincide cu cel stocat în sesiune, chiar dacă dovada este matematic consistentă față de t_sim. Testul confirmă că legarea de canal (session binding) previne atacul simulatorului Schnorr în implementare.

7.3.2. Forjarea Soluției fără Cheia Privată

Seria de teste validează că, în absența cunoașterii lui x, niciun atacator nu poate construi o soluție acceptabilă:

- Trimiterea nonce-ului brut (s = r, fără termenul c·x) eșuează la verificare, deoarece G^r ≠ G^r · y^c în general.
- Modificarea cu ±1 a soluției corecte (atac de tip bit-flip / integer forgery) eșuează, deoarece G^(s±1) ≠ G^s în subgrupul de ordin prim.
- Trimiterea valorilor-limită ale soluției (s = 0 sau s = Q) este respinsă prin validarea domeniului înaintea verificării matematice.

7.3.3. Securitatea Sesiunilor

Un angajament t = y (cheia publică utilizată ca nonce) permite autentificarea doar dacă utilizatorul cunoaște x și calculează corect s = x·(1 + c) mod Q, confirmând că validarea matematică este corectă indiferent de valoarea concretă a lui t, cu condiția că aceasta aparține subgrupului. Testele de izolare cross-user confirmă că provocările și sesiunile nu pot fi transferate între utilizatori diferiți.


7.4. Teste de Integrare OAuth2

Sistemul integrează trei variante de flux OAuth2, fiecare validată funcțional:

- OAuth2 PKCE (Proof Key for Code Exchange, RFC 7636): fluxul de autorizare cu code_challenge S256, schimbul codului de autorizare contra token Bearer și Refresh Token, și invalidarea codului după o singură utilizare.

- OAuth2 Simple (Authorization Code fără PKCE): variantă simplificată pentru clienți de server cu canal securizat, validată funcțional prin emitere de cod și schimb contra token.

- Authlib PKCE: implementare echivalentă PKCE utilizând biblioteca Authlib, cu parametri form-encoded, validând interoperabilitatea cu un provider OAuth2 standardizat.

Testele verifică emiterea codului de autorizare, schimbul cod → token, accesul la resurse cu token valid, și respingerea accesului cu token expirat sau cu code_verifier incorect.


7.5. Evaluarea Performanței

7.5.1. Latențele Operațiilor Criptografice

Latența individuală a principalelor operații criptografice ale protocolului a fost măsurată utilizând platforma Flask Test Client, eliminând penalitățile de rețea și serializare HTTP. Rezultatele (medii pe 100 de iterații) sunt sintetizate în tabelul următor:

| Operație                                      | Medie (ms) | Min (ms) | Max (ms) | P95 (ms) | StdDev (ms) |
|-----------------------------------------------|-----------|---------|---------|---------|-------------|
| Calculul angajamentului: t = G^r mod P        | 0,516     | 0,506   | 0,542   | 0,527   | 0,005       |
| Verificarea Schnorr: G^s ≡ t · y^c (mod P)   | 1,121     | 1,113   | 1,148   | 1,138   | 0,006       |
| Challenge PKCE S256 (SHA-256)                 | 0,004     | 0,003   | 0,022   | 0,006   | 0,002       |
| Hash check OAuth2 Simple                      | 0,003     | 0,002   | 0,005   | 0,003   | 0,0004      |

Costul dominant al protocolului ZKP este exponențierea modulară (G^r mod P, respectiv G^s mod P și y^c mod P), cu o latență totală de verificare de aproximativ 1,12 ms. Aceasta este cu cel puțin două ordine de mărime mai mare față de operațiile hash utilizate de metodele OAuth2 clasice, dar rămâne în domeniul acceptabil pentru autentificarea interactivă.

7.5.2. Debitul (Throughput)

Benchmark-ul de debit a măsurat numărul de fluxuri complete de autentificare pe secundă (RPS) pentru fiecare protocol, la dimensiuni de lot de 10, 25, 50 și 100 de utilizatori secvențiali simulați:

| Utilizatori | ZKP (RPS) | OAuth2 PKCE (RPS) | OAuth2 Simple (RPS) | Authlib PKCE (RPS) |
|------------|-----------|-------------------|---------------------|---------------------|
| 10         | 172,4     | 288,1             | 286,7               | 406,4               |
| 25         | 183,5     | 296,2             | 309,3               | 742,0               |
| 50         | 171,2     | 301,3             | 329,3               | 841,8               |
| 100        | 167,4     | 297,7             | 289,2               | 822,0               |

Protocolul ZKP prezintă un debit consistent de aproximativ 170 RPS, relativ stabil față de creșterea numărului de utilizatori, datorită costului fix al exponențierilor modulare pe grupul de 2048 de biți. Metodele OAuth2 bazate pe operații hash ating 290–830 RPS, numeric superioare, dar cu compromiteri la nivelul transmiterii credențialelor (parola traversează serverul în cazul OAuth2). Raportul de performanță ZKP / OAuth2 (~1:1,7) este justificat prin garanțiile criptografice suplimentare ale schemei zero-knowledge.


7.6. Auditul de Trafic

Auditul de trafic a comparat conținutul mesajelor HTTP transmise în cadrul fiecărui protocol, cu scopul de a valida proprietatea zero-knowledge la nivelul canalului de comunicație:

- Protocolul ZKP (POST /login/commit, POST /login/verify): mesajele conțin exclusiv valori numerice efemere — angajamentul t (~617 cifre zecimale) și dovada s (~308 cifre). Parola sau orice derivat al acesteia nu apare în niciun mesaj.

- Autentificarea clasică (POST /classic/login): parola este transmisă în clar în corpul cererii, vizibilă oricărui adversar care interceptează traficul neprotejat.

- OAuth2 PKCE și Simple (POST /oauth/*/authorize): parola este transmisă serverului de autorizare în primul pas; aceasta nu ajunge la serverul de resurse, dar rămâne expusă față de serverul de autorizare și față de orice interceptor al canalului.

Protocolul ZKP Schnorr este singurul flux în care parola nu traversează niciodată rețeaua, în nicio formă. Captarea integrală a unui schimb ZKP nu furnizează adversarului informații utilizabile pentru autentificare ulterioară sau pentru recuperarea credențialelor.


7.7. Simularea Atacurilor

7.7.1. Atac cu Cheie Publică Furată (Data Breach Simulation)

Testul simulează scenariul în care adversarul obține accesul complet la baza de date a serverului și extrage valoarea y = G^x mod P. Adversarul încearcă autentificarea construind o dovadă cu y în locul lui x: s_attacker = (r + c·y) mod Q. Verificarea G^(s_attacker) ≡ t · y^c (mod P) eșuează, deoarece y ≠ x în spațiul exponenților. Rezultat: HTTP 401. Comprometerea bazei de date nu furnizează adversarului capacitatea de impersonare.

7.7.2. Unicitatea Provocărilor (Validarea Entropiei RNG)

Pe 10.000 de cereri de commit consecutive, s-a verificat absența coliziunilor atât în valorile challenge_c, cât și în identificatorii de sesiune session_id generați. Toate valorile challenge_c s-au încadrat în intervalul [1, P−2]. Testul validează calitatea sursei de entropie criptografice (CSPRNG — secrets.randbelow) utilizate în implementare.

7.7.3. Atac de Injectare a Parametrilor Slabi (MitM)

Testul demonstrează că, dacă un adversar Man-in-the-Middle substituie parametrii de grup cu valori slabe (P=23, Q=11, G=4), logaritmul discret devine calculabil prin forță brută în cel mult P−2 pași. Adversarul recuperează cheia privată x a victimei și completează cu succes un flux ZKP în calitate de imposteur. Concluzie: clientul de producție trebuie să ancoreze (pin) valorile P și G și să refuze orice deviere față de parametrii de referință, indiferent de răspunsul serverului la GET /parameters.

7.7.4. Demonstrarea Imposibilității Forței Brute (DLP)

Scriptul de benchmark al logaritmului discret demonstrează escaladarea dificultății atacului de forță brută, pornind de la grupuri de 8 biți (rezolvabile în milisecunde) și urcând până la 128 de biți și la grupul de protocol (~1023 biți pentru Q). La dimensiunile de grup utilizate în protocol, un atac exhaustiv este computațional nefezabil în ipoteze standard de complexitate, validând alegerea unui safe prime de 2048 de biți ca fundament criptografic al sistemului.


7.8. Concluziile Validării

Campania de testare a demonstrat că implementarea protocolului Schnorr satisface cerințele funcționale, de securitate și de performanță stabilite în capitolele anterioare:

1. Corectitudine matematică: ecuația de verificare G^s ≡ t · y^c (mod P) este satisfăcută în toate scenariile cu credențiale corecte și respinsă în toate scenariile cu credențiale incorecte sau dovezi forjate.

2. Proprietatea zero-knowledge la nivel de transport: niciun mesaj HTTP transmis în cursul autentificării ZKP nu conține parola sau orice derivat direct al acesteia, proprietate confirmată prin auditul de trafic.

3. Rezistență la atacuri: sistemul respinge corect atacurile de tip replay, session hijacking, forjare de soluție, data breach și injectare de angajament simulat (simulator attack).

4. Performanță acceptabilă: latența verificării criptografice (~1,12 ms per operație) și debitul susținut (~170 RPS) plasează protocolul în domeniul aplicabil autentificării interactive, cu un compromis de performanță față de schemele bazate exclusiv pe operații hash, justificat prin garanțiile criptografice suplimentare.

5. Limite ale prototipului: parametrul G=4 și scrypt cu n=2^11 sunt adecvați unui prototip de cercetare, dar necesită înlocuire cu un generator standardizat (RFC 3526) și parametri scrypt conformi recomandărilor OWASP (n ≥ 2^14) pentru o implementare de producție.





















