# Sistem de autentificare și autorizare rezilient la interceptare, bazat pe Zero-Knowledge Proof și OAuth 2.0

Matei Rareș

## Rezumat

În majoritatea aplicațiilor web contemporane, autentificarea utilizatorilor continuă să se sprijine pe modelul clasic în care parola este transmisă către server, direct sau indirect, printr-un canal protejat cu TLS. Deși această abordare rămâne adecvată pentru numeroase scenarii practice, ea depinde în mod fundamental de confidențialitatea transportului și de corectitudinea infrastructurii serverului. În prezența scurgerilor de date, a erorilor de configurare, a interceptărilor de trafic sau a reutilizării credențialelor, acest model devine vulnerabil. În acest context, interesul pentru mecanisme de autentificare care permit demonstrarea cunoașterii unui secret fără transmiterea lui efectivă prin rețea este pe deplin justificat.

Lucrarea de față propune și documentează un prototip de sistem de autentificare construit în jurul schemei de identificare Schnorr, integrată într-o arhitectură client-server de tip REST. Sistemul este implementat printr-un client web HTML/CSS/JavaScript și un server Flask în Python, iar după finalizarea cu succes a autentificării bazate pe dovadă de cunoaștere zero, serverul emite un JSON Web Token utilizat ulterior ca token de tip Bearer pentru accesarea resurselor protejate. În acest mod, protocolul Schnorr este folosit pentru autentificarea inițială, iar modelul bazat pe token-uri este păstrat pentru eficiența accesului ulterior, într-o manieră compatibilă conceptual cu ecosistemul OAuth 2.0 [1], [2], [3].

Proiectul este însoțit de o suită completă de testare și de măsurare, care include teste funcționale, teste negative, cazuri-limită, teste de securitate, fluxuri OAuth2 comparative și benchmark-uri de latență, debit de procesare și amprentă de memorie. În mediul analizat, suita principală de QA a executat 56 de teste, toate încheiate cu succes. Rezultatele experimentale arată că fluxul ZKP oferă un avantaj clar din perspectiva protejării credențialelor la interceptarea traficului, cu prețul unei complexități mai mari și al unui cost computațional superior fluxurilor OAuth2 clasice.

Contribuția principală a proiectului constă în articularea unei autentificări bazate pe dovadă de cunoaștere zero cu o fază de autorizare bazată pe token-uri, însoțită de un strat de observabilitate a traficului, de o comparație cu fluxuri OAuth2 tradiționale și de o analiză critică a avantajelor, limitărilor și pașilor necesari pentru maturizarea soluției într-un mediu de producție.

## Introducere

Aplicațiile web moderne depind în mod structural de mecanisme de autentificare la distanță. Utilizatorul trebuie să demonstreze că este titularul legitim al unei identități digitale, iar serverul trebuie să decidă dacă acordă sau nu accesul solicitat. În forma sa cea mai răspândită, acest proces presupune utilizarea unei parole, a unui cod temporar sau a unui alt secret partajat. Deși protecția transportului prin HTTPS reduce semnificativ riscul interceptării, modelul rămâne expus unei clase ample de probleme: baze de date compromise, parole reutilizate, configurări eronate ale infrastructurii, capturarea traficului pentru analize ulterioare sau atacuri de tip replay asupra unor materiale de autentificare insuficient legate de contextul sesiunii.

În paralel, OAuth 2.0 s-a impus ca standard dominant pentru autorizare delegată [1]. Totuși, acest cadru nu rezolvă, prin el însuși, problema dovedirii identității utilizatorului fără transmiterea credențialelor. În numeroase implementări, faza de autentificare în fața serverului de autorizare rămâne un login clasic bazat pe parolă. Prin urmare, se conturează un spațiu legitim pentru integrarea unei metode de autentificare mai robuste în etapa care precedă emiterea token-ului.

Lucrarea urmărește tocmai acest obiectiv: proiectarea și documentarea unui sistem în care utilizatorul își dovedește identitatea printr-o schemă Schnorr bazată pe dovadă de cunoaștere zero, iar serverul emite ulterior un token JWT pentru accesul la resurse. Ideea centrală este că parola sau cheia privată nu trebuie să părăsească niciodată dispozitivul clientului. Serverul păstrează exclusiv valoarea publică asociată utilizatorului și verifică dovada matematică fără a cunoaște secretul originar.

Proiectul are și o componentă experimentală substanțială. Pe lângă implementarea fluxului ZKP, sistemul include două implementări OAuth2 dezvoltate manual, una cu PKCE și una simplificată, precum și o a treia variantă bazată pe biblioteca Authlib. Aceste implementări nu înlocuiesc fluxul principal Schnorr, ci oferă un punct de comparație privind costul operațional, structura mesajelor și expunerea credențialelor pe rețea.

În plan practic, lucrarea își propune să răspundă la următoarele întrebări:

1. Poate fi realizată o autentificare web funcțională fără transmiterea parolei către server?
2. Poate fi integrată această autentificare într-un model de autorizare bazat pe token, compatibil conceptual cu ecosistemul OAuth?
3. Ce avantaje reale de securitate oferă protocolul în raport cu soluțiile clasice și ce costuri introduce?
4. Ce limitări are implementarea curentă și ce modificări ar fi necesare pentru trecerea către un sistem de producție?

Pentru a răspunde acestor întrebări, documentația este organizată în trei capitole principale. Primul capitol introduce fundamentele teoretice, tehnologiile și arhitectura sistemului. Al doilea capitol descrie cerințele funcționale, modelul matematic și implementarea concretă a protocolului și a API-ului. Al treilea capitol prezintă metodologia de testare, rezultatele experimentale, avantajele și limitele protocolului propus, precum și direcțiile de dezvoltare viitoare.

## Capitolul I. Concepte, tehnologii, arhitectură

În acest capitol sunt prezentate fundamentele teoretice ale autentificării bazate pe dovezi de cunoaștere zero, locul ocupat de OAuth 2.0 și JWT în arhitectura propusă, tehnologiile utilizate și organizarea aplicației pe niveluri. Scopul său este definirea cadrului conceptual în care a fost construit proiectul și explicarea modului în care fiecare componentă contribuie la funcționarea sistemului.

### I.1. Noțiuni teoretice

#### I.1.1. Zero-Knowledge Proof și problema autentificării

O dovadă de cunoaștere zero (Zero-Knowledge Proof, ZKP) reprezintă un protocol prin care un participant, numit în continuare doveditor, demonstrează unui alt participant, numit verificator, că posedă un anumit secret sau că o anumită afirmație este adevărată, fără a dezvălui secretul însuși. Ideea este deosebit de valoroasă în autentificare, unde sistemul nu urmărește să afle parola utilizatorului, ci doar să se convingă că utilizatorul o cunoaște.

Avantajul conceptual major față de autentificarea clasică este eliminarea nevoii de a transmite un secret reutilizabil prin rețea. Într-un sistem tradițional, chiar dacă parola este trimisă prin HTTPS, serverul primește un material sensibil și trebuie să îl protejeze. Într-un protocol Zero-Knowledge, rețeaua transportă doar transcrisul unei dovezi, iar acesta nu poate fi reutilizat în afara contextului în care a fost generat, dacă protocolul este implementat corect.

În contextul acestei lucrări, această proprietate este importantă pentru protecția împotriva interceptării traficului. Dacă un adversar observă schimbul de mesaje, el vede doar valori matematice efemere și o dovadă valabilă exclusiv pentru sesiunea respectivă. Secretul din care a fost construită dovada rămâne local pe client, iar transcrisul protocolului nu oferă, în forma corect implementată, informații reutilizabile pentru autentificări ulterioare.

#### I.1.2. Schema Schnorr de identificare

Schema Schnorr este una dintre cele mai cunoscute construcții de identificare bazate pe problema logaritmului discret [4], [5], [6]. Se lucrează într-un grup finit în care calcularea logaritmului discret este considerată dificilă din punct de vedere computațional. Utilizatorul alege o valoare secretă x și publică valoarea y, unde:

`y = G^x mod P`

Pentru autentificare, utilizatorul alege un nonce aleator r, calculează:

`t = G^r mod P`

primește sau derivă o provocare c și trimite răspunsul:

`s = (r + c * x) mod Q`

Serverul verifică egalitatea:

`G^s mod P = t * y^c mod P`

Dacă egalitatea este adevărată, atunci utilizatorul a demonstrat că știe secretul x fără a-l dezvălui. În forma clasică, provocarea c este aleasă aleator de verificator. În implementarea de față, provocarea este derivată determinist din contextul sesiunii și dintr-un identificator aleator de sesiune generat de server. Această alegere leagă explicit transcrisul protocolului de contextul HTTP curent și întărește protecția împotriva relay-ului și a replay-ului.

#### I.1.3. OAuth 2.0, JWT și PKCE

OAuth 2.0 este un cadru de autorizare delegată prin care un client poate obține token-uri de acces pentru a apela resurse protejate [1]. În practică, acesta este utilizat atât în scenarii cu terți, cât și în platforme proprii în care serverul de autorizare și serverul de resurse aparțin aceleiași aplicații. Extensia PKCE, definită prin RFC 7636, adaugă protecție împotriva interceptării codului de autorizare, în special în cazul clienților publici [2].

JSON Web Token, standardizat prin RFC 7519, oferă un mod compact de a transmite afirmații semnate între două părți [3]. În această lucrare, JWT-ul este utilizat după autentificarea ZKP pentru a evita reluarea demonstrației matematice la fiecare cerere către resursa protejată. Acest lucru reduce costul operațional pentru accesul repetat la date și reproduce un model de lucru familiar aplicațiilor web moderne.

Din punct de vedere arhitectural, combinația dintre Schnorr și JWT poate fi descrisă astfel: protocolul ZKP rezolvă problema autentificării inițiale fără transmiterea parolei, iar JWT rezolvă problema sesiunii și a autorizării ulterioare. Astfel, proiectul nu încearcă să înlocuiască întregul ecosistem bazat pe token-uri, ci să fortifice exact etapa cea mai sensibilă: validarea identității inițiale.

### I.2. Tehnologii utilizate

#### I.2.1. Python, Flask și SQLAlchemy

Nucleul aplicației, aflat pe partea de server, este scris în Python, limbaj ales pentru claritatea sintaxei, viteza de dezvoltare și disponibilitatea unui ecosistem foarte bogat de biblioteci. Componenta web este construită cu Flask 3.0.0, un micro-framework potrivit pentru aplicații REST și prototipuri de cercetare [7]. Flask gestionează rutarea, parsarea cererilor HTTP, serializarea răspunsurilor JSON și integrarea cu celelalte componente ale aplicației.

Persistența datelor este realizată cu Flask-SQLAlchemy 3.1.1, peste o bază de date SQLite locală [8]. Alegerea este potrivită pentru un prototip de laborator deoarece simplifică instalarea, reduce dependențele externe și permite resetarea rapidă a stării în timpul testelor automate. Baza de date conține trei tabele principale: utilizatorii înregistrați, token-urile emise și un set minimal de date protejate accesibile doar pe baza token-ului.

#### I.2.2. JavaScript, HTML și CSS în clientul web

Clientul este o aplicație web statică bazată pe HTML, CSS și JavaScript, împărțită în pagini separate pentru ecranul de start, înregistrare și login. Codul JavaScript folosește tipul `BigInt` pentru operațiile aritmetice necesare schemei Schnorr și API-ul Web Crypto al browserului pentru funcții criptografice și pentru generarea de entropie.

Fișierul `auth.js` conține utilitarele comune: preluarea parametrilor publici de la server, derivarea secretului local, exponențiere modulară, generarea lui r și funcțiile auxiliare de interfață. Fișierele `register.js` și `login.js` implementează fluxurile de înregistrare și autentificare, iar `network-monitor.js` interceptează toate apelurile `fetch` și afișează într-un panou lateral atât cererile, cât și răspunsurile HTTP. Acest mecanism de observabilitate este util atât didactic, cât și experimental, deoarece permite compararea vizuală a fluxului ZKP cu fluxurile OAuth2.

#### I.2.3. PyJWT, Authlib și instrumente auxiliare

Generarea și validarea token-urilor sunt realizate cu PyJWT [9]. Pentru comparația cu o implementare OAuth2 de referință, proiectul include și biblioteca Authlib [10], folosită într-un modul separat. Pe lângă aceasta, aplicația folosește Flask-CORS pentru suport cross-origin în scenariul de dezvoltare și `cryptography` pentru dependințele tranzitive și suportul criptografic necesar mediului Python.

#### I.2.4. Pytest, Locust și Mermaid

Calitatea soluției este evaluată cu `pytest`, care susține toate suitele de test funcțional și de securitate [11]. Pentru evaluarea încărcării concurente și a debitului de procesare este folosit Locust [12], iar pentru documentarea vizuală a arhitecturii și a secvențelor de protocol sunt utilizate diagrame Mermaid [13]. În plus, proiectul include scripturi de benchmark și fișiere CSV generate automat, folosite în capitolul experimental.

### I.3. Arhitectura aplicației

Aplicația urmează o structură pe trei niveluri, cu separarea clară între nivelul de prezentare, nivelul de aplicație și nivelul de date. Această organizare simplifică atât înțelegerea proiectului, cât și extinderea sa ulterioară.

#### I.3.1. Nivelul de prezentare

Nivelul de prezentare este reprezentat de clientul web din directorul `client_app`. Utilizatorul poate accesa trei pagini principale:

1. `index.html`, care joacă rolul de ecran introductiv.
2. `register.html`, folosită pentru generarea și trimiterea valorii publice Schnorr către server.
3. `login.html`, folosită pentru execuția protocolului complet de autentificare.

În cazul paginilor de înregistrare și login, interfața include și un monitor de rețea în timp real. Acest element este important deoarece proiectul nu este doar o demonstrație funcțională, ci și un instrument de analiză a traficului. Utilizatorul poate observa exact ce câmpuri traversează rețeaua și poate constata diferența dintre un flux în care parola este transmisă și unul în care apare doar transcrisul unei dovezi ZKP.

#### I.3.2. Nivelul de aplicație

Nivelul de aplicație este implementat în `server_app/server.py`, `server_app/server_oauth.py` și `server_app/server_authlib.py`. Acesta conține:

1. Rutele de bază ale serverului ZKP: `/health`, `/parameters`, `/register`, `/login/commit`, `/login/verify`, `/data`.
2. Logica de validare a apartenenței valorilor la subgrupul Schnorr.
3. Gestionarea stării temporare între pașii commit și verify printr-un `_SessionStore` in-memory.
4. Emiterea token-urilor JWT după autentificarea reușită.
5. Implementările comparative pentru OAuth2 PKCE, OAuth2 Simple și Authlib PKCE.

O decizie de proiect relevantă este legarea sesiunii de contextul HTTP. Serverul nu păstrează doar valorile t și c, ci și o amprentă derivată din adresa de rețea, antetul User-Agent, identificatorul de sesiune și identitatea clientului. Astfel, transcrisul protocolului devine legat nu doar de secret, ci și de canalul logic în care a fost creat.

#### I.3.3. Nivelul de date

Nivelul de date folosește SQLite și conține trei entități principale:

| Entitate | Rol | Câmpuri esențiale |
|---|---|---|
| `User` | păstrează identitatea publică a utilizatorului | `client_id`, `secret_y`, `created_at` |
| `AuthToken` | memorează ultimul token emis pentru utilizator | `user_id`, `token`, `created_at` |
| `PersoData` | stochează mesajul protejat asociat utilizatorului | `user_id`, `message` |

Este important de observat că serverul nu stochează parola și nici scalarul privat x. Singura informație criptografică persistentă folosită pentru verificarea Schnorr este cheia publică y. Acesta este unul dintre principalele avantaje de design ale sistemului.

Diagrama de ansamblu a arhitecturii este deja disponibilă în fișierul `diagrams/diagram_architecture.mmd`, iar diagramele de înregistrare, login și mașină de stări sunt incluse în celelalte fișiere Mermaid din directorul `diagrams`.

## Capitolul II. Funcționalitate, protocol și implementare

În acest capitol sunt descrise cerințele funcționale ale sistemului, modelul matematic al schemei Schnorr, structura mesajelor HTTP și detaliile efective de implementare. Accentul este pus pe comportamentul concret al aplicației și pe modul în care fiecare componentă cooperează cu celelalte.

### II.1. Cerințe funcționale

#### II.1.1. Actorii sistemului

Sistemul poate fi descris prin trei roluri logice, chiar dacă în prototip două dintre ele sunt găzduite de aceeași aplicație:

1. Clientul, în rol de doveditor, reprezentat de browserul utilizatorului, care deține local parola și execută pașii de calcul ai dovezii Schnorr.
2. Serverul de autentificare, în rol de verificator, care păstrează cheia publică a utilizatorului, generează contextul sesiunii și verifică dovada matematică.
3. Serverul de resurse, care în prototip coincide cu serverul Flask, dar joacă logic rolul de componentă ce expune date protejate pe baza token-ului emis.

În plus, pentru partea comparativă, apare și rolul de server de autorizare OAuth2, implementat în două variante custom și una bazată pe Authlib.

#### II.1.2. Cerințe funcționale principale

Sistemul trebuie să îndeplinească următoarele cerințe funcționale:

1. Să permită clientului să obțină parametrii publici ai grupului criptografic printr-un endpoint dedicat.
2. Să permită înregistrarea unui utilizator prin transmiterea exclusivă a valorii publice `secret_y = G^x mod P` și a identificatorului `client_id`.
3. Să permită inițierea unei autentificări prin trimiterea unui angajament efemer `commitment_t = G^r mod P`.
4. Să returneze o provocare criptografică asociată unei sesiuni unice și unui context de rețea determinat.
5. Să permită verificarea dovezii matematice prin valoarea `solution_s` transmisă de client.
6. Să emită un JWT valabil limitat în timp după autentificarea cu succes.
7. Să permită consumul token-ului pentru accesul la o resursă protejată fără reluarea protocolului ZKP.
8. Să ofere și fluxuri OAuth2 alternative, utile pentru comparație experimentală.

#### II.1.3. Cerințe nefuncționale și de securitate

Pe lângă funcționalitatea de bază, sistemul urmărește următoarele proprietăți:

1. Parola sau cheia privată să nu fie transmise prin rețea.
2. Transcrisul unei autentificări să nu poată fi reutilizat într-o altă sesiune.
3. Valorile publice primite de la client să fie validate ca membri ai subgrupului corect.
4. Cererile invalide, datele malformate și încercările de fraudă să fie tratate fără a genera erori de server.
5. Sistemul să fie suficient de transparent pentru a permite auditarea traficului și evaluarea comparativă.

Este important de precizat că implementarea curentă nu urmărește anonimizarea identității. `client_id` este transmis în clar în faza de înregistrare și în cea de commit. Protocolul protejează secretul de autentificare, nu și metadatele de identitate.

### II.2. Formalizarea protocolului

#### II.2.1. Parametri și model matematic

Implementarea curentă utilizează un prim sigur P de 512 biți, pentru care `Q = (P - 1) / 2` este de asemenea prim. Verificarea experimentală a parametrilor arată că perechea `(P, Q)` este validă din punct de vedere al proprietății de safe prime. Generatorul folosit în cod este `G = 4`, membru al subgrupului de ordin Q.

Astfel, se lucrează în subgrupul de ordin prim Q al lui `Z_P*`, cu următoarele definiții:

1. Cheia privată: `x`.
2. Cheia publică: `y = G^x mod P`.
3. Nonce efemer: `r`.
4. Angajament: `t = G^r mod P`.
5. Provocare: `c`.
6. Răspuns: `s = (r + c * x) mod Q`.

Verificarea finală este:

`G^s mod P = t * y^c mod P`

Din punct de vedere conceptual, acest model este identic cu schema Schnorr clasică. Diferența de implementare apare în modul de alegere a provocării. În loc să genereze pur și simplu un număr aleator, serverul calculează mai întâi o valoare de legare a sesiunii:

`binding = SHA-256(remote_addr | user_agent | session_id | client_id | t)`

apoi derivă:

`c = int(binding) mod Q`

Această decizie introduce o legare explicită între transcrisul criptografic și contextul de transport observat de server.

#### II.2.2. Faza de înregistrare

Faza de înregistrare are rolul de a asocia `client_id` cu valoarea publică `secret_y`. Fluxul este următorul:

1. Clientul apelează `GET /parameters` și obține P și G.
2. Clientul derivă local scalarul x pornind de la parolă.
3. Clientul calculează `secret_y = G^x mod P`.
4. Clientul transmite `POST /register` cu câmpurile `client_id` și `secret_y`.
5. Serverul verifică dacă `secret_y` aparține subgrupului Schnorr și dacă `client_id` nu există deja.
6. Dacă validarea reușește, serverul persistă perechea `client_id -> secret_y`.

Un element esențial este că înregistrarea nu implică transmiterea parolei către server. Serverul memorează doar cheia publică. În baza de date nu apare nici parola în clar, nici un hash al parolei folosit direct pentru autentificarea clasică.

#### II.2.3. Faza de autentificare

Faza de autentificare este împărțită în două cereri HTTP.

Pasul 1, commit:

1. Clientul alege `r` printr-un generator criptografic de numere pseudoaleatoare.
2. Calculează `t = G^r mod P`.
3. Trimite `POST /login/commit` cu `client_id` și `commitment_t`.
4. Serverul verifică faptul că utilizatorul există, că t aparține subgrupului și că nu există o sesiune activă incompatibilă pentru același utilizator.
5. Serverul generează `session_id`, calculează valoarea de legare a sesiunii și derivă provocarea `challenge_c`.
6. Serverul răspunde cu provocarea `challenge_c` și `session_id`.

Pasul 2, verify:

1. Clientul calculează `s = (r + c * x) mod Q`.
2. Trimite `POST /login/verify`, incluzând `solution_s` în corpul JSON și `X-Auth-Session: session_id` în antet.
3. Serverul verifică existența sesiunii, expirarea ei, intervalul valid pentru s și coerența valorii de legare a sesiunii.
4. Serverul citește cheia publică y a utilizatorului din baza de date.
5. Verifică egalitatea Schnorr.
6. Dacă dovada este validă, emite JWT-ul și șterge imediat sesiunea temporară.

În implementarea curentă, sesiunea de autentificare are un TTL de 5 secunde, iar o a doua încercare de commit pentru același utilizator, apărută după o fereastră de 50 ms, este tratată ca potențială tentativă de preluare abuzivă a sesiunii și duce la invalidarea sesiunii existente. Acest comportament este util experimental și este acoperit de testele automate, însă reprezintă și un compromis de ergonomie care va fi discutat în capitolul de limitări.

#### II.2.4. Emiterea și consumul token-ului

După verificarea cu succes, serverul emite un JWT semnat cu HS256 și valabil 3600 de secunde. Token-ul include cel puțin `client_id`, momentul emiterii și momentul expirării. Pentru accesul la resursa protejată `/data`, clientul transmite token-ul în antetul `Authorization`.

Prototipul acceptă mai multe scheme de compatibilitate (`Bearer`, `Token`, `JWT`, `DPoP` sau token brut), însă forma recomandată este cea standardizată prin RFC 6750:

`Authorization: Bearer <token>`

Această separare între autentificarea inițială și consumul token-ului este intenționată. Protocolul Schnorr nu este reluat pentru fiecare operație asupra resursei, ceea ce ar crește inutil costul operațional. În schimb, acesta servește la inițializarea unei sesiuni autorizate.

### II.3. Structura mesajelor HTTP

#### II.3.1. Antete și convenții REST

Serverul expune o interfață REST JSON și folosește antete suplimentare pentru trasabilitate și securitate. Pe lângă `Content-Type` și `Authorization`, implementarea emite antete precum `Request-ID`, `API-Version`, `X-Response-Time`, `Server-Timing`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` și `Referrer-Policy`. La răspunsurile `401` este emis și antetul `WWW-Authenticate`.

Endpoint-urile principale sunt prezentate în tabelul următor:

| Endpoint | Metodă | Rol |
|---|---|---|
| `/health` | GET | verificare stare server |
| `/parameters` | GET | publicarea parametrilor P și G |
| `/register` | POST | înregistrarea lui `client_id` și `secret_y` |
| `/login/commit` | POST | inițierea autentificării Schnorr |
| `/login/verify` | POST | verificarea dovezii și emiterea token-ului |
| `/data` | GET, POST, PUT | resursă protejată prin JWT |
| `/oauth/pkce/*` | POST | flux OAuth2 Authorization Code cu PKCE |
| `/oauth/simple/*` | POST | flux OAuth2 Authorization Code simplificat |
| `/authlib/*` | POST | flux OAuth2 bazat pe Authlib |

#### II.3.2. Structura payload-urilor JSON

Valorile mari rezultate din calculele Schnorr sunt serializate ca numere întregi sau, în practica clientului web, ca șiruri de caractere ce reprezintă întregi zecimali. API-ul serverului acceptă ambele variante atât timp cât valoarea poate fi convertită la întreg.

Exemplele principale sunt:

Înregistrare:

```json
{
	"client_id": "alice",
	"secret_y": "12345678901234567890"
}
```

Commit:

```json
{
	"client_id": "alice",
	"commitment_t": "98765432109876543210"
}
```

Răspuns la commit:

```json
{
	"challenge_c": "112233445566778899",
	"session_id": "<opaque-session-token>"
}
```

Verify:

```json
{
	"solution_s": "998877665544332211"
}
```

Răspuns la autentificare:

```json
{
	"token": "<jwt>"
}
```

#### II.3.3. Definire ABNF

Pentru o descriere formală a formatului mesajelor, se poate folosi următoarea notație ABNF adaptată specificului aplicației:

```abnf
client-id          = 1*(ALPHA / DIGIT / "-" / "_")
schnorr-value      = 1*DIGIT
session-id         = 1*(ALPHA / DIGIT / "-" / "_")
jwt-token          = 1*(ALPHA / DIGIT / "." / "-" / "_")
q-string           = DQUOTE 1*(VCHAR / SP) DQUOTE

registration-payload = "{" DQUOTE "client_id" DQUOTE ":" q-string ","
												 DQUOTE "secret_y" DQUOTE ":" q-string "}"

commitment-payload   = "{" DQUOTE "client_id" DQUOTE ":" q-string ","
												 DQUOTE "commitment_t" DQUOTE ":" q-string "}"

challenge-response   = "{" DQUOTE "challenge_c" DQUOTE ":" q-string ","
												 DQUOTE "session_id" DQUOTE ":" q-string "}"

verify-payload       = "{" DQUOTE "solution_s" DQUOTE ":" q-string "}"

auth-success-payload = "{" DQUOTE "token" DQUOTE ":" q-string "}"

authorization-header = "Bearer" SP jwt-token
session-header       = "X-Auth-Session:" SP session-id
```

Această descriere este suficientă pentru a evidenția faptul că protocolul schimbă doar identitatea publică, valori numerice Schnorr și token-uri de sesiune, fără a transporta parola sau cheia privată.

### II.4. Detalii de implementare

#### II.4.1. Serverul Flask

Serverul este nucleul logic al aplicației. Acesta definește parametrii criptografici, validează valorile publice, păstrează sesiunile temporare și emite JWT-uri. Câteva aspecte sunt deosebit de importante:

1. Funcția `is_subgroup_member` respinge valorile triviale și verifică relația `value^Q mod P = 1`, reducând riscul atacurilor de tip subgrup mic.
2. `_SessionStore` păstrează atât sesiunea, cât și un index invers `client_id -> session_id`, util pentru a detecta commit-urile concurente pentru același utilizator.
3. `_compute_session_binding` derivează valoarea de legare a sesiunii la contextul de rețea.
4. `_issue_jwt` emite token-ul cu o valabilitate de o oră.
5. `/data` validează semnătura și expirarea JWT-ului și abia apoi permite accesul la resursa protejată.

Din perspectivă de securitate, serverul mai adaugă antete defensive în toate răspunsurile sale și setează `Cache-Control: private, no-store, no-cache, must-revalidate`, evitând stocarea materialului sensibil în cache-urile intermediare.

#### II.4.2. Clientul web

Clientul browser are rol activ în protocol. Acesta nu este doar o interfață de introducere a datelor, ci partea care execută efectiv calculele criptografice. Fluxul de login din `login.js` este foarte explicit:

1. Preia P și G de la server.
2. Derivă x din credențiale.
3. Generează un r aleator cu `window.crypto.getRandomValues`.
4. Calculează t.
5. Trimite commit-ul și primește provocarea `challenge_c` plus `session_id`.
6. Calculează s.
7. Trimite verify-ul și afișează JWT-ul primit.

Acest flux este afișat și textual utilizatorului printr-o casetă de status. În paralel, monitorul de rețea interceptează toate apelurile `fetch` și afișează antetele, payload-urile și răspunsurile. Pentru o lucrare de disertație, acest mecanism este valoros deoarece transformă aplicația într-un instrument de demonstrație și de audit, nu doar într-un prototip funcțional.

#### II.4.3. Implementările OAuth2 comparative

Pe lângă fluxul principal Schnorr, proiectul include trei variante OAuth2:

1. O implementare custom PKCE în `server_oauth.py`.
2. O implementare custom simplificată, fără PKCE, în același modul.
3. O implementare Authlib PKCE în `server_authlib.py`.

Aceste module folosesc parole hash-uite cu SHA-256 pentru verificarea titularului resursei și emit, la rândul lor, token-uri JWT. Scopul lor este comparativ. Ele permit observarea diferenței dintre o autentificare clasică, în care parola apare în fluxul `/authorize`, și o autentificare ZKP, în care rețeaua vede doar valori matematice efemere.

Implementările OAuth2 mai au un rol: arată cum pot fi integrate noțiunile de client public, `code_challenge`, refresh token și authorization code într-un proiect care investighează alternative la parola transmisă direct către serverul de autorizare.

#### II.4.4. Observații privind derivarea secretului și parametrii publici

Această secțiune este importantă deoarece documentația existentă din proiect conține atât opțiuni teoretice, cât și implementări de prototip. Într-o lucrare academică este esențial să se distingă între cele două.

La nivel conceptual, scalarul privat x ar trebui derivat din parolă printr-o funcție de derivare rezistentă la atacuri de dicționar offline, precum scrypt sau Argon2. Fișierul `calculations.py` și utilitarele de test din `qa/qa_utils.py` documentează tocmai această direcție, folosind scrypt și un salt aleator.

În schimb, implementarea efectivă din clientul web (`client_app/js/auth.js`) folosește, pentru simplitate și portabilitate, un hash SHA-256 peste concatenarea `client_id:password`, urmat de o mapare în domeniul numeric. Această alegere este adecvată pentru un prototip demonstrativ, dar nu reprezintă varianta recomandată pentru producție. În plus, clientul conține un fallback local cu parametri foarte mici (`P = 2089`, `G = 4`) atunci când `GET /parameters` eșuează, fapt util doar pentru demonstrații locale și total nerecomandat într-un mediu real.

Prin urmare, lucrarea trebuie interpretată astfel:

1. Modelul criptografic de bază este Schnorr.
2. Implementarea demonstrativă browser-side prioritizează claritatea și ușurința execuției.
3. Varianta întărită de producție ar necesita uniformizarea derivării lui x prin scrypt sau Argon2, stocarea sigură a salt-ului pe client și eliminarea fallback-ului către parametri slabi.

## Capitolul III. Validare, rezultate experimentale și analiză critică

În acest capitol sunt prezentate metodologia de testare, rezultatele obținute în urma rulării suitelor automate și a măsurătorilor de performanță, precum și o analiză critică a avantajelor și limitărilor protocolului propus.

### III.1. Strategia de testare

Strategia de validare a fost concepută multistrat, astfel încât să acopere simultan corectitudinea funcțională, robustețea la intrări anormale, rezistența la scenarii de atac și costul operațional al soluției. În consecință, evaluarea nu s-a limitat la verificarea traseului nominal al aplicației, ci a inclus atât cazuri negative și cazuri-limită, cât și experimente dedicate performanței și simulării unor atacuri relevante pentru modelul de amenințare analizat.

Testarea automată a fost organizată în cinci suite principale:

1. `pos_case.py` pentru cazuri pozitive.
2. `neg_case.py` pentru cazuri negative și eșecuri controlate.
3. `corner_case.py` pentru valori-limită și date malformate.
4. `security_case.py` pentru scenarii de atac specifice protocolului.
5. `oauth_case.py` pentru validarea fluxurilor OAuth2 comparative.

Executarea acestor suite este orchestrată de `qa/test/main_test.py`, care agregă statisticile la nivel de suită și furnizează o imagine sintetică a stării sistemului. Fiecare test utilizează clientul Flask de test, iar starea bazei de date și a sesiunilor în memorie este reinițializată înainte și după execuție. Această alegere metodologică este importantă deoarece elimină dependențele între scenarii și asigură reproductibilitatea rezultatelor.

În afara testelor funcționale propriu-zise, proiectul include și următoarele instrumente de evaluare experimentală:

1. scripturi de benchmark pentru latență și memorie în `qa/measurement/benchmark.py`;
2. teste de încărcare concurentă cu Locust în `qa/measurement/locustfile.py`;
3. audit de trafic și rezultate generate în `qa/measurement/generated`;
4. simulări de atac și scenarii manuale în `qa/attack_simulation`.

Pentru redactarea prezentei secțiuni au fost efectuate, în mediul curent de lucru, trei execuții experimentale principale, menite să acopere validarea funcțională, simularea atacurilor și măsurarea performanței:

1. `python qa/test/main_test.py` pentru suita principală de QA;
2. `python -m pytest qa/attack_simulation/automated.py -v --tb=short` pentru simulările automate de atac;
3. `python qa/measurement/probes.py --run-all 50 30s` pentru fluxul complet de măsurare, incluzând benchmark-ul offline, auditul de trafic, măsurătorile de memorie și testul live cu Locust timp de 30 de secunde, la un nivel de 50 de utilizatori concurenți.

### III.2. Rezultatele testelor funcționale și de securitate

În urma execuției suitei principale de QA, s-a obținut rezultatul sintetic prezentat în tabelul următor:

| Suită | Număr teste | Rezultat |
|---|---:|---|
| Positive Test Cases | 5 | promovată integral |
| Negative Test Cases | 5 | promovată integral |
| Corner Cases | 30 | promovată integral |
| Security Tests | 8 | promovată integral |
| OAuth2 Functional Tests | 8 | promovată integral |
| Total | 56 | 56 teste promovate, 0 eșecuri |

Promovarea integrală a suitei de bază arată că implementarea acoperă corect traseul nominal și gestionează adecvat un număr semnificativ de scenarii de eroare. Totuși, valoarea acestor rezultate nu derivă exclusiv din totalul testelor trecute, ci și din distribuția lor pe categorii funcționale distincte.

#### III.2.1. Cazuri pozitive

Scenariile pozitive validează funcționarea corectă a sistemului în condiții nominale. Acestea confirmă:

1. înregistrarea utilizatorului și persistența exclusivă a valorii publice `secret_y`;
2. absența parolei brute și a unor hash-uri standard ale parolei din baza de date a serverului;
3. fluxul complet `commit -> verify -> token`;
4. accesul la resursa protejată pe baza unui JWT valid;
5. autentificarea paralelă a doi utilizatori diferiți fără interferență între sesiuni.

Prin urmare, aceste rezultate validează obiectivul central al proiectului, și anume realizarea unei autentificări reușite fără transmiterea parolei către server.

#### III.2.2. Cazuri negative

Scenariile negative urmăresc verificarea comportamentului de respingere controlată atunci când protocolul este utilizat incorect sau malițios. În această categorie sunt incluse următoarele situații:

1. parola greșită și dovada incompatibilă cu cheia publică stocată;
2. atacul de tip replay prin reutilizarea aceleiași sesiuni și a aceleiași soluții;
3. expirarea sesiunii dintre commit și verify;
4. commit dublu pentru același utilizator;
5. înregistrare duplicată pentru același `client_id`.

Rezultatele obținute arată că protocolul nu este doar corect din punct de vedere matematic, ci și însoțit de politici de control care împiedică reutilizarea transcrisului și suprascrierea silențioasă a unei sesiuni active.

#### III.2.3. Cazuri limită

Cazurile-limită sunt relevante deoarece numeroase vulnerabilități apar nu în traseul nominal, ci în tratarea necorespunzătoare a valorilor extreme sau a intrărilor neconforme. Suita dedicată, alcătuită din 30 de teste, a verificat, între altele:

1. respingerea valorilor `solution_s` aflate în afara intervalului admis;
2. respingerea valorilor triviale pentru `secret_y` și `commitment_t`;
3. tratarea stabilă a datelor malformate precum string-uri, liste, obiecte sau notație științifică;
4. comportamentul corect în scenarii concurente cu commit-uri simultane;
5. robustețea antetului `X-Auth-Session` la intrări bizare sau absente.

Promovarea integrală a acestei suite indică un nivel bun de validare defensivă la intrare și sugerează că serverul tratează robust o gamă largă de valori anormale fără a genera erori necontrolate.

#### III.2.4. Teste de securitate

Testele de securitate au vizat proprietăți direct asociate schemei Schnorr și modului concret în care aceasta a fost integrată în aplicație. Au fost evaluate următoarele aspecte:

1. eșecul unui transcris simulat atunci când este aplicat unei sesiuni legate de alt angajament;
2. eșecul folosirii nonce-ului brut ca soluție, fără contribuția secretului x;
3. eșecul unei soluții modificate cu `+1` sau `-1`;
4. respingerea lui `s = 0`;
5. imposibilitatea reutilizării unei soluții consumate într-o sesiune nouă;
6. imposibilitatea ghicirii brute-force a `session_id`;
7. izolarea sesiunilor concurente aparținând unor utilizatori diferiți.

Aceste rezultate confirmă faptul că securitatea implementării nu depinde exclusiv de ecuația Schnorr, ci și de corecta gestionare a stării temporare și de legarea sesiunii la contextul de rețea observat de server.

#### III.2.5. Testele OAuth2 comparative

Suita dedicată fluxurilor OAuth2 comparative a validat următoarele proprietăți operaționale:

1. emiterea codului de autorizare în fluxul PKCE;
2. schimbul codului în token și refresh token;
3. respingerea parolei incorecte;
4. respingerea `code_verifier`-ului greșit în PKCE;
5. funcționarea fluxului simplificat fără PKCE;
6. compatibilitatea aliasurilor `/oauth/*` cu implementarea PKCE explicită.

Aceste teste sunt importante deoarece furnizează o bază experimentală solidă pentru comparația ulterioară dintre fluxul ZKP și alternativele OAuth2 clasice.

#### III.2.6. Simulări automate de atac

Separat de suita principală, au fost executate și scenariile din `qa/attack_simulation/automated.py`. În campania experimentală descrisă în această secțiune, toate cele patru scenarii s-au încheiat fără erori. Importanța lor constă în faptul că completează verificarea funcțională cu experimente explicit orientate pe modelul de atac:

1. imposibilitatea autentificării pe baza unei chei publice furate din baza de date;
2. unicitatea valorilor `challenge_c` și `session_id` pe 10.000 de commit-uri consecutive;
3. demonstrarea faptului că un atac MitM devine viabil dacă serverul și clientul operează efectiv pe parametri slabi injectați de atacator;
4. demonstrarea faptului că același atac eșuează atunci când serverul rămâne fixat pe parametrii săi reali și respinge valorile publice din grupul slab.

Rezultatele acestor simulări susțin două concluzii esențiale. În primul rând, stocarea exclusivă a cheii publice `secret_y` nu este suficientă pentru impersonarea utilizatorului. În al doilea rând, distribuția parametrilor publici rămâne o suprafață critică de atac și necesită mecanisme suplimentare de protecție într-o implementare matură.

### III.3. Benchmark-uri și măsurători

#### III.3.1. Auditul conținutului traficului

Una dintre cele mai relevante observații experimentale provine din auditul traficului HTTP generat de aplicație. Fișierul `qa/measurement/generated/audit_traffic_content.md` evidențiază explicit diferența de conținut dintre fluxuri:

1. în ZKP, `POST /login/commit` conține `client_id` și `commitment_t`, iar `POST /login/verify` conține doar `solution_s`;
2. în login-ul clasic și în fluxurile OAuth2 custom, cererea de autorizare conține parola utilizatorului;
3. în PKCE, parola dispare din pasul de schimb al codului, dar este totuși prezentă în pasul inițial de autorizare a titularului resursei.

Această observație are o valoare probatorie ridicată pentru întreaga lucrare. Principalul avantaj al autentificării ZKP nu rămâne, astfel, la nivel teoretic, ci devine observabil direct în transcrisul de trafic: parola nu traversează rețeaua în fluxul principal de autentificare.

#### III.3.2. Latența pe pași ai fluxului ZKP

Măsurătorile regenerate în `zkp_steps_latency.csv` indică următoarele valori pentru principalele etape ale fluxului ZKP:

| Operație | Medie | Minim | Maxim | p95 |
|---|---:|---:|---:|---:|
| `/login/commit` pe server | 1.598 ms | 1.116 ms | 5.494 ms | 2.789 ms |
| `/login/verify` pe server | 2.415 ms | 1.665 ms | 15.519 ms | 4.008 ms |
| Round-trip total client | 4.034 ms | 2.797 ms | 21.039 ms | 6.785 ms |

Se observă că etapa `verify` este mai costisitoare decât etapa `commit`, fapt firesc deoarece în acest punct sunt realizate verificarea completă a ecuației criptografice, validarea sesiunii și emiterea token-ului.

#### III.3.3. Comparația end-to-end între protocoale

Fișierul `e2e_results.csv` oferă o comparație end-to-end între fluxul ZKP și alternativele OAuth2, pe baza execuției curente:

| Flux | Medie full-flow |
|---|---:|
| ZKP full flow (commit + verify) | 4.252 ms |
| OAuth2 PKCE full flow | 2.418 ms |
| OAuth2 Simple full flow | 2.421 ms |
| Authlib PKCE full flow | 0.970 ms |

Rezultatele confirmă ipoteza teoretică potrivit căreia protocolul ZKP este mai costisitor decât fluxurile OAuth2 bazate predominant pe operații hash și pe schimb de token-uri. Costul suplimentar este explicat de exponențierile modulare și de verificările suplimentare asociate apartenenței la subgrup.

#### III.3.4. Debit de procesare sub încărcare

Rezultatele de debit de procesare regenerate pentru benchmark-ul comparativ controlat arată următoarea evoluție la nivelul de 100 utilizatori concurenți:

| Metodă | Requests per second |
|---|---:|
| ZKP | 233.864 |
| OAuth2 PKCE | 408.039 |
| OAuth2 Simple | 468.065 |
| Authlib PKCE | 1008.934 |

ZKP rămâne varianta cu cel mai scăzut debit de procesare dintre cele comparate, însă această diferență trebuie interpretată în raport cu obiectivul protocolului. Scopul său nu este minimizarea absolută a latenței, ci eliminarea transmiterii parolei și reducerea dependenței de un secret partajat între client și server în faza de autentificare.

#### III.3.5. Amprenta de memorie

Măsurătorile din `memory_footprint_results.csv` indică o amprentă redusă a stării temporare gestionate de server. În scenariile regenerate, `tracemalloc_peak_kb` s-a situat între 180 KB și 223 KB, iar numărul de intrări active în `_SessionStore` a rămas între 0 și 1. Acest rezultat sugerează că, pentru un prototip de laborator, costul memoriei nu reprezintă un factor limitativ. Într-un sistem distribuit, însă, starea temporară ar trebui externalizată într-un serviciu dedicat, precum Redis.

În plus, monitorizarea resurselor din `monitor_resources.csv`, realizată în timpul campaniei live de măsurare, a indicat un consum RAM tipic în intervalul 60.79-69.12 MB și vârfuri CPU de până la 4.70%. Pentru configurația de laborator utilizată aici, aceste valori arată că serverul rămâne ușor din perspectiva consumului de resurse, chiar și în condițiile unui test live cu trafic concurent.

#### III.3.6. Benchmark intern al serverului

Fișierul `server_internals_results.csv` oferă o imagine mai granulară asupra costului operațiilor interne. Cele mai relevante valori medii sunt prezentate în tabelul următor:

| Operație internă | Medie |
|---|---:|
| `is_subgroup_member` | 0.529 ms |
| `_compute_session_binding` | 0.0023 ms |
| `_compute_challenge` | 0.0007 ms |
| `_issue_jwt` | 0.0189 ms |
| `GET /parameters` | 0.245 ms |
| `POST /register` | 1.458 ms |
| `GET /data` | 1.008 ms |
| `POST /data` | 1.372 ms |

Aceste rezultate arată că operația dominantă, la nivel criptografic, este validarea apartenenței la subgrup. În schimb, derivarea valorii de legare a sesiunii și calculul provocării au un cost practic neglijabil, iar emiterea JWT-ului rămâne foarte ieftină în raport cu restul fluxului.

#### III.3.7. Load test live cu Locust

Pe lângă benchmark-urile locale realizate cu clientul Flask de test, a fost executat și un test live cu Locust prin comanda `python qa/measurement/probes.py --run-all 50 30s`, care a pornit efectiv serverul și a generat trafic concurent timp de 30 de secunde, la un nivel de 50 de utilizatori. La finalul execuției, raportul agregat Locust a indicat 717 cereri totale, 0 eșecuri și o rată agregată de aproximativ 24.83 cereri pe secundă.

Din aceeași execuție rezultă și următoarele valori medii pentru fluxurile complete simulate în regim live:

| Flux live | Număr execuții | Timp mediu |
|---|---:|---:|
| `full_zkp_login` | 45 | 4101 ms |
| `full_oauth_pkce_login` | 42 | 4100 ms |
| `full_oauth_simple_login` | 41 | 4092 ms |
| `full_authlib_pkce_login` | 36 | 4079 ms |

În acest context, diferențele dintre protocoale apar mai puțin pronunțate decât în benchmark-ul offline. Explicația constă în faptul că testul live include costuri suplimentare de infrastructură, scheduling, traffic shaping și timpi specifici generatorului de sarcină, care atenuează diferențele rezultate strict din costul criptografic. Cu toate acestea, observația importantă este că serverul a susținut întreaga execuție fără erori și fără creșteri semnificative ale consumului de resurse.

### III.4. Avantajele protocolului propus

Protocolul și arhitectura implementate oferă un set de avantaje relevante atât pentru analiza academică, cât și pentru proiectarea unor mecanisme de autentificare mai robuste:

1. Parola nu este transmisă prin rețea în fluxul principal de autentificare, ceea ce reduce impactul interceptării traficului.
2. Serverul nu stochează secretul privat și nici parola utilizatorului, ci doar cheia publică `secret_y`, diminuând severitatea unei breșe în baza de date.
3. Transcrisul este legat de o sesiune temporară și de contextul de rețea, ceea ce îngreunează replay-ul și relay-ul.
4. După emiterea JWT-ului, accesul la resurse devine eficient și compatibil cu modelele uzuale de API moderne.
5. Sistemul este transparent și ușor de observat datorită monitorului de rețea integrat și a scripturilor de audit.
6. Prezența fluxurilor OAuth2 comparative face posibilă evaluarea riguroasă a compromisului dintre securitate și performanță.
7. Endpoint-ul `/parameters` permite, cel puțin conceptual, folosirea unor parametri publici proprii fiecărui server, reducând dependența de constante exclusiv client-side.

Din perspectivă academică, argumentul cel mai puternic în favoarea protocolului este acela că acesta modifică modelul de încredere: serverul nu mai trebuie să fie depozitarul unui secret de autentificare partajat cu utilizatorul, ci doar verificatorul unei relații matematice bazate pe o cheie publică.

### III.5. Limitări și dezavantaje

În același timp, soluția prezintă și limitări importante, care trebuie asumate explicit în evaluarea sa:

1. Fluxul ZKP este mai lent decât fluxurile OAuth2 clasice, iar benchmark-urile confirmă acest cost suplimentar.
2. Protocolul necesită stocarea unei stări temporare între pașii commit și verify, ceea ce complică scalarea pe mai multe instanțe.
3. `client_id` este transmis în clar, deci soluția nu oferă anonimitate sau protecție a identității la nivel de metadate.
4. După emitere, JWT-ul devine noul artefact de acces, ceea ce înseamnă că furtul token-ului rămâne relevant până la expirare.
5. Implementarea browser-side actuală folosește o derivare simplificată a lui x prin SHA-256, nu un KDF memory-hard unificat cu restul documentației experimentale.
6. Clientul conține un fallback către parametri mici, acceptabil doar pentru demo și periculos într-o implementare reală.
7. Endpoint-ul `/parameters` nu este semnat și nu este pin-uit în client; fără TLS și pinning, distribuția parametrilor rămâne un punct sensibil.
8. Secretul JWT este hardcodat, sesiunile sunt păstrate in-memory, CORS este deschis pentru orice origine, iar SQLite nu reprezintă o opțiune adecvată pentru producție.
9. TTL-ul de 5 secunde pentru sesiune este prea agresiv pentru rețele lente sau clienți mobili.
10. Fereastra de 50 ms folosită pentru diferențierea dintre race și hijack este utilă în laborator, dar fragilă operațional într-un sistem real.

Aceste aspecte nu invalidează soluția, dar arată clar că proiectul trebuie interpretat ca un prototip experimental solid, nu ca un produs final pregătit pentru exploatare în medii critice.

### III.6. Direcții de îmbunătățire

Direcțiile naturale pentru maturizarea sistemului sunt următoarele:

1. standardizarea derivării lui x prin scrypt sau Argon2, cu salt persistent stocat sigur pe client;
2. eliminarea fallback-ului către parametri slabi și pinning-ul parametrilor publici sau al amprentei acestora;
3. creșterea dimensiunii grupului la cel puțin 2048 de biți sau migrarea la o schemă Schnorr pe curbe eliptice;
4. externalizarea sesiunilor în Redis și migrarea bazei de date la PostgreSQL sau MySQL;
5. trecerea de la HS256 la RS256 sau ES256 pentru separarea semnării de verificarea token-urilor;
6. introducerea rate limiting-ului, a jurnalizării structurate și a mecanismelor de revocare a token-urilor;
7. obligativitatea HTTPS în infrastructură și configurarea strictă a CORS pentru originile permise;
8. extinderea modelului către token-uri proof-of-possession, pentru a reduce dependența de semantica bearer.

## Concluzii

Lucrarea a urmărit proiectarea, implementarea și evaluarea unui sistem de autentificare care combină schema Schnorr de identificare cu un model de autorizare bazat pe JWT și inspirat conceptual din ecosistemul OAuth 2.0. Rezultatul este un prototip coerent, funcțional și bine instrumentat, care demonstrează că autentificarea web poate fi realizată fără transmiterea parolei către server.

Din punct de vedere tehnic, proiectul oferă un flux complet de înregistrare, autentificare, emitere de token și acces la resurse protejate. În plus, include măsuri experimentale utile de întărire, precum validarea apartenenței la subgrup, legarea sesiunii la contextul HTTP, eliminarea sesiunii după consum, antete de securitate și validarea strictă a intrărilor. Suita principală de testare, alcătuită din 56 de teste, a fost promovată integral, iar simulările automate suplimentare de atac s-au încheiat de asemenea fără erori, ceea ce confirmă consistența funcțională și experimentală a implementării.

Rezultatele experimentale evidențiază clar compromisul fundamental al soluției. Pe de o parte, fluxul ZKP este mai costisitor decât alternativele OAuth2 clasice și necesită o logică operațională mai complexă. Pe de altă parte, el oferă un avantaj semnificativ prin faptul că transcrisul de trafic nu conține parola utilizatorului. Auditul conținutului traficului confirmă direct această diferență, iar acesta constituie argumentul central în favoarea protocolului propus.

În forma actuală, proiectul reprezintă un prototip de disertație solid, cu valoare demonstrativă și experimentală ridicată. El nu trebuie însă confundat cu o implementare finală de producție. Există limitări clare, precum derivarea simplificată a lui x în clientul web, distribuția neautentificată a parametrilor publici, sesiunile in-memory și secretul JWT hardcodat. Tocmai aceste limite îi conferă relevanță academică: ele permit discutarea onestă a diferenței dintre o demonstrație funcțională și o soluție matură.

Prin urmare, concluzia principală a lucrării este că autentificarea bazată pe dovezi de cunoaștere zero poate fi integrată eficient într-o arhitectură web modernă și poate reduce semnificativ expunerea credențialelor la interceptare, cu condiția ca implementarea să fie completată ulterior printr-o întărire riguroasă a distribuției parametrilor, a derivării secretelor și a infrastructurii operaționale.

## Bibliografie

[1] IETF, The OAuth 2.0 Authorization Framework, RFC 6749, 2012.

[2] IETF, Proof Key for Code Exchange by OAuth Public Clients, RFC 7636, 2015.

[3] IETF, JSON Web Token (JWT), RFC 7519, 2015.

[4] IETF, The OAuth 2.0 Authorization Framework: Bearer Token Usage, RFC 6750, 2012.

[5] C. P. Schnorr, Efficient Identification and Signatures for Smart Cards, Advances in Cryptology, CRYPTO '89.

[6] A. J. Menezes, P. C. van Oorschot, S. A. Vanstone, Handbook of Applied Cryptography, CRC Press, 1996.

[7] Flask Documentation, https://flask.palletsprojects.com/.

[8] Flask-SQLAlchemy Documentation, https://flask-sqlalchemy.palletsprojects.com/.

[9] PyJWT Documentation, https://pyjwt.readthedocs.io/.

[10] Authlib Documentation, https://docs.authlib.org/.

[11] pytest Documentation, https://docs.pytest.org/.

[12] Locust Documentation, https://locust.io/.

[13] Mermaid Documentation, https://mermaid.js.org/.

[14] J. Katz, Y. Lindell, Introduction to Modern Cryptography, 2nd Edition, CRC Press, 2014.

[15] OWASP, Password Storage Cheat Sheet, https://cheatsheetseries.owasp.org/.

## Anexe

### Anexa 1. Fișiere de diagramă relevante

1. `diagrams/diagram_architecture.mmd`
2. `diagrams/diagram_registration_flow.mmd`
3. `diagrams/diagram_login_flow.mmd`
4. `diagrams/diagram_auth_state_machine.mmd`
5. `diagrams/done/client_server_sequence_high_level_login.mmd`
6. `diagrams/done/client_server_sequence_high_level_register.mmd`
7. `diagrams/done/client_server_sequence_login_detailed.mmd`
8. `diagrams/done/client_server_sequence_login_verify_detailed.mmd`
9. `diagrams/done/client_server_sequence_oauth_pkce_detailed.mmd`

### Anexa 2. Artefacte experimentale

1. `qa/measurement/generated/audit_traffic_content.md`
2. `qa/measurement/generated/e2e_results.csv`
3. `qa/measurement/generated/zkp_steps_latency.csv`
4. `qa/measurement/generated/throughput_results.csv`
5. `qa/measurement/generated/memory_footprint_results.csv`
6. `qa/measurement/generated/server_internals_results.csv`
7. `qa/measurement/generated/monitor_resources.csv`
8. `qa/measurement/generated/locust_report.html`

### Anexa 3. Suite de testare

1. `qa/test/pos_case.py`
2. `qa/test/neg_case.py`
3. `qa/test/corner_case.py`
4. `qa/test/security_case.py`
5. `qa/test/oauth_case.py`
6. `qa/attack_simulation/automated.py`
