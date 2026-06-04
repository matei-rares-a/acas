
titlu
-------------------
cuprins
-------------------



-----------------------
II.5. Analiza proprietăților de securitate ale protocolului
In acest subcapitol este prezentată o evaluare critică a proprietăților de securitate oferite de protocolul implementat, prin raportare la clasele de amenințări relevante pentru sistemele de autentificare la distanță. Fiecare proprietate este analizată din perspectiva fundamentului matematic al schemei Schnorr și a deciziilor arhitecturale adoptate in cadrul prezentei lucrări.

II.5.1. Rezistența la interceptare și la decriptare ulterioară
Securitatea arhitecturii propuse nu este condiționată de confidențialitatea stratului de transport (Transport Layer Security), ci rezidă in dificultatea computațională a rezolvării problemei logaritmului discret intr-un grup de ordin prim [45], [50]. In sistemele convenționale de autentificare, compromiterea canalului de comunicare prin strategii de stocare și decriptare ulterioară (store now, decrypt later) conduce la expunerea credențialelor in clar, oferind atacatorului acces direct la materialul secret al utilizatorului.

In schema Schnorr, un adversar care interceptează traficul de rețea vizualizează exclusiv transcrisul efemer al protocolului, compus din valorile angajamentului (t), provocării (c) și soluției (s). Extragerea cheii private din aceste valori presupune rezolvarea ecuației liniare cu două necunoscute:

s = (r + c · x) mod Q (1)

unde s reprezintă soluția matematică transmisă de solicitant, r constituie nonce-ul efemer aleatoriu necunoscut atacatorului, c reprezintă provocarea unică generată de server, iar x constituie cheia privată protejată a utilizatorului. Deoarece valoarea r nu este niciodată transmisă prin rețea și este generată cu proprietăți criptografice de aleatorism, ecuația nu poate fi rezolvată de un adversar care dispune exclusiv de valorile publice ale transcrisului. Prin urmare, protocolul asigură proprietatea de secret perfect (perfect secrecy) și oferă imunitate in fața compromiterii integrale a stratului de transport [46], [47], [48], [49].

II.5.2. Eliminarea secretului partajat și reziliența la scurgeri de date
Spre deosebire de modelele clasice de autentificare bazate pe parole, arhitectura propusă elimină in totalitate necesitatea transmiterii sau persistării unui secret partajat (shared secret) pe server [11]. In cadrul protocolului implementat, serverul stochează exclusiv cheia publică y = G^x mod P, asociată identității utilizatorului. Această decizie arhitecturală neutralizează in mod direct impactul compromiterii bazei de date, fie prin injecție SQL, fie prin scurgeri de date (data leaks), deoarece valorile publice extrase sunt inutile din punct de vedere criptografic in absența cheii private corespunzătoare.

Implicația fundamentală a acestei proprietăți constă in faptul că, in eventualitatea compromiterii integrale a serverului, atacatorul nu dispune de informații suficiente pentru a impersona utilizatorii legitimi. Cheia privată nu părăsește niciodată mediul local al aplicației client, iar derivarea acesteia din cheia publică este echivalentă computațional cu rezolvarea problemei logaritmului discret, problemă considerată intractabilă pentru dimensiunile parametrilor utilizați in prezenta implementare.

II.5.3. Atenuarea atacurilor de reluare și a deturnării de sesiune
Prevenirea atacurilor de reluare (replay attacks) este asigurată prin natura interactivă a protocolului, serverul generand o provocare unică (challenge) pentru fiecare tentativă de autentificare [51]. Soluția matematică transmisă de client este validă strict in corelație cu provocarea și angajamentul asociate sesiunii curente. Reutilizarea unui transcript capturat anterior intr-o sesiune nouă eșuează in mod determinist, deoarece provocarea diferă, iar soluția calculată anterior nu satisface egalitatea de verificare G^s = t · y^c (mod P) pentru noua valoare a provocării.

Complementar, riscul de deturnare a sesiunii (session hijacking) este atenuat prin mecanismul de legare de canal (session binding) implementat la nivelul emiterii jetonului JWT. Structura jetonului include un parametru de expirare cu valabilitate limitată in timp, restrangand fereastra de oportunitate disponibilă vectorilor de atac. De asemenea, ancorarea jetonului emis de contextul HTTP unic al sesiunii ZKP impiedică transferul malițios al jetonului intre contexte de rețea diferite.

II.5.4. Descentralizarea validării și paradigma identității auto-suverane
Arhitectura implementată validează identitatea utilizatorului intr-o manieră descentralizată, inscriindu-se in paradigma identității auto-suverane (self-sovereign identity) [52]. Prin eliminarea dependenței de furnizori terți de identitate sau de intermediari de incredere, serverul de autentificare acționează ca o entitate de verificare autonomă. Atestarea identității se realizează prin rigoare matematică directă intre cele două noduri participante la protocol (clientul și serverul), fără a necesita validarea din partea unei autorități externe.

Această proprietate conferă protocolului un grad sporit de reziliență in fața compromiterii lanțului de incredere (chain of trust), deoarece securitatea autentificării nu depinde de integritatea unui furnizor de identitate terț, ci exclusiv de corectitudinea matematică a demonstrației Schnorr și de securitatea parametrilor criptografici ai grupului.

Modificări principale față de versiunea anterioară:

Structură academică cu subsecțiuni numerotate (II.5.1, II.5.2, II.5.3, II.5.4) in locul listei numerotate informale (1, 2, 3, 4)
Paragraf introductiv al secțiunii care contextualizează și anunță conținutul, conform stilului template-ului
Titluri complete și descriptive ale subsecțiunilor in locul titlurilor telegrafice
Dezvoltarea argumentației cu paragrafe narative continue in loc de enunțuri laconice
Explicarea implicațiilor fiecărei proprietăți de securitate, nu doar constatarea lor
Eliminarea liniilor de pauză și utilizarea consecventă a diacriticelor românești
Toate informațiile factuale și referințele din versiunea originală au fost păstrate integral

III.5. 	Discutii finale

În urma evaluărilor efectuate în suita de testare, s-a demonstrat faptul că implementarea protocolului Schnorr îndeplinește cu strictețe rigorile funcționale, de securitate și de performanță predefinite. În primul rând, s-a validat corectitudinea matematică a sistemului, ecuația de verificare G^s ≡ t · y^c (mod P) fiind satisfăcută în toate scenariile ce implică utilizarea unor credențiale valide și respinsă sistematic în cazul tentativelor de falsificare a dovezilor (forgery) sau al utilizării unor credențiale eronate. În al doilea rând, auditul de trafic a confirmat menținerea proprietății zero-knowledge la nivelul stratului de transport. Astfel, s-a observat că niciun mesaj HTTP transmis pe parcursul procesului de autentificare nu conține parola brută sau derivate directe ale acesteia.

De asemenea, s-a demonstrat rezistența arhitecturii la vectori de atac consacrați, sistemul respingând cu succes tentativele de tip replay, session hijacking, compromitere a datelor (data breach), precum și injectările de angajamente simulate (simulator attacks). Din perspectiva performanței, evaluările au indicat o latență a verificării criptografice de aproximativ 1,12 ms per operație și un debit susținut de circa 170 de cereri pe secundă (RPS). În consecință, protocolul se încadrează în parametrii optimi pentru autentificarea interactivă, compromisul temporal față de schemele clasice bazate exclusiv pe funcții de rezumare (hash) fiind justificat de garanțiile criptografice superioare obținute. Totuși, s-a constatat că parametrii utilizați în prezenta iterație, precum generatorul G = 4 și funcția de derivare a cheilor scrypt cu un factor de cost n = 2^11, sunt adecvați exclusiv unui prototip de cercetare. Pentru o viitoare tranziție către un mediu de producție, se impune adoptarea unui generator standardizat (conform specificației RFC 3526) [53], [54] și utilizarea unor parametri scrypt aliniați la recomandările curente de securitate OWASP (n ≥ 2^14).

### Avantajele arhitecturii propuse

Arhitectura implementată prezintă avantaje structurale majore, atât din perspectiva analizei academice, cât și în vederea proiectării unor mecanisme de autentificare cu un grad ridicat de reziliență. Un beneficiu fundamental constă în eliminarea transmiterii parolei prin rețea în cadrul fluxului principal de autentificare, aspect care atenuează drastic impactul interceptării pachetelor de date. Suplimentar, prin faptul că la nivelul serverului se stochează exclusiv cheia publică a utilizatorului (secret_y), lipsind cu desăvârșire secretul privat, vulnerabilitățile asociate potențialelor breșe de securitate la nivelul bazei de date sunt minimizate considerabil.

O altă proprietate esențială a sistemului este ancorarea transcrisului criptografic de o sesiune temporară și de contextul specific rețelei, decizie de proiectare ce neutralizează atacurile de tip replay și relay. Pe de altă parte, integrarea jetoanelor de tip JWT (JSON Web Tokens) post-autentificare facilitează un acces la resurse eficient și compatibil cu standardele arhitecturale ale interfețelor API moderne. Transparența procesului este garantată prin intermediul instrumentelor de observabilitate integrate, iar prezența fluxurilor comparative bazate pe standardul OAuth 2.0 permite o evaluare riguroasă a compromisului inerent dintre securitate și performanță. Mai mult, disponibilitatea unui punct terminal dedicat parametrilor globali (*/parameters*) fundamentează conceptual posibilitatea utilizării unor parametri criptografici specifici fiecărui server, reducând dependența de constante definite exclusiv la nivelul aplicației client. În concluzie, din perspectivă academică, validarea acestui protocol modifică paradigma modelului de încredere: serverul este degrevat de responsabilitatea protejării unui secret partajat, asumându-și strict rolul de verificator al unor relații matematice asimetrice.

### Limitări și constrângeri de proiectare

În ciuda beneficiilor enumerate, sistemul actual prezintă anumite limitări structurale care necesită o analiză riguroasă. În primul rând, s-a observat că fluxul bazat pe demonstrații cu cunoștințe zero (ZKP) introduce o latență de execuție superioară în comparație cu schemele clasice OAuth 2.0, aspect validat de măsurătorile de performanță. În al doilea rând, cerința menținerii unei stări temporare între etapele de angajament (commit) și verificare (verify) adaugă un nivel de complexitate în scenariile de scalare orizontală. O altă limitare conceptuală o reprezintă transmiterea identificatorului de client (client_id) în clar, fapt ce invalidează asigurarea anonimității la nivel de metadate. Totodată, post-verificare, token-ul JWT devine unicul artefact de acces; prin urmare, compromiterea acestuia conferă unui atacator autorizări nelegitime până la momentul expirării jetonului.

La nivelul implementării clientului, s-a utilizat o derivare simplificată a secretului prin intermediul funcției SHA-256, nefiind integrată o funcție de derivare a cheilor (KDF) cu consum ridicat de memorie. S-a implementat, de asemenea, un mecanism de rezervă (fallback) către parametri criptografici de dimensiuni reduse, compromis acceptabil într-un mediu controlat, dar critic într-o implementare de producție. Mai mult, distribuția parametrilor publici nu este protejată prin mecanisme de semnare digitală sau fixare a certificatelor (pinning), devenind un vector de vulnerabilitate în absența securizării prin protocolul TLS [64]. La nivelul infrastructurii serverului, stocarea în memorie a sesiunilor, politicile CORS permisive, utilizarea sistemului de gestiune SQLite și definirea statică a cheilor secrete subliniază caracterul pur experimental al aplicației. Nu în ultimul rând, s-a identificat faptul că un timp de viață (TTL) al sesiunii fixat la 5 secunde este restrictiv pentru clienții mobili sau rețelele cu latență ridicată, în timp ce fereastra de 50 de milisecunde utilizată pentru diferențierea competiției pentru resurse (race conditions) de atacurile de preluare a sesiunii (hijacking) prezintă instabilitate operațională în afara mediului de laborator.

### Direcții de dezvoltare și îmbunătățire

Pentru a asigura maturizarea sistemului și alinierea acestuia la standardele industriale de securitate, se propun mai multe direcții strategice de optimizare. Se impune, cu prioritate, standardizarea procesului de derivare a secretului prin implementarea unor algoritmi robuști (ex. scrypt sau Argon2), proces dependent de un salt criptografic generat și stocat în mod securizat pe dispozitivul clientului. Este imperativă eliminarea procedurilor de rezervă (fallback) destinate parametrilor slabi și implementarea unui sistem de validare a parametrilor publici prin fixarea amprentelor criptografice. Referitor la fundamentul matematic, se recomandă creșterea dimensiunii grupului ciclic la minimum 2048 de biți sau, preferabil, tranziția către o schemă Schnorr aplicată pe curbe eliptice (ECC) [62], [63], pentru o eficientizare a costurilor computaționale. Sistemele de autentificare ZKP pot fi îmbunătățite prin utilizarea unor protocoale alternative de tip SRP [55], PAKE [56], J-PAKE [57], [58] sau prin adoptarea celor mai recente protocoale documentate în literatura de specialitate [59], [60].

Pentru a remedia limitările de scalabilitate și persistență, infrastructura necesită externalizarea stocării sesiunilor către soluții de tip in-memory data structure store (precum Redis) și migrarea stratului de date relațional către platforme robuste, precum PostgreSQL sau MySQL. Din perspectiva gestionării jetoanelor, se preconizează trecerea de la semnături simetrice (HS256) către algoritmi asimetrici (RS256 sau ES256), decuplând astfel procesele de emitere de cele de verificare a token-urilor. Consolidarea perimetrului de securitate va presupune integrarea unor mecanisme de limitare a ratei de acces (rate limiting), implementarea jurnalizării structurate a evenimentelor de securitate și a unor liste de revocare a jetoanelor. În mod obligatoriu, comunicarea trebuie restricționată exclusiv prin protocolul HTTPS [61], cu aplicarea unor politici CORS riguroase. Pe termen lung, extinderea arhitecturii prin încorporarea jetoanelor de tip proof-of-possession va elimina riscurile inerente modelului de acces bazat exclusiv pe transmiterea unui bearer token, ridicând substanțial nivelul global de securitate al protocolului.

----------------------

***, Nostr Community Group: HTTP Schnorr Authentication Draft, https://nostrcg.github.io/http-schnorr-auth, ultima accesare: 30/05/2026. -
----------------------
 + diagrame de comparatie intre protocoale ZKP si OAuth 2.0

II.1.4. 	Comparatie intre protocoale ZKP si OAuth 2.0 todo
Diagramă care să arate unde se încadrează Schnorr în fluxul OAuth 2.0 (înlocuind client_secret cu ZKP Proof). 
 Etapa 	  Metoda HTTP 	Parametri Cheie 	Rol în OAuth 
Commitment 	POST /login/commit 	client_id, t = g^r 	Inițiere Grant 
Challenge 	Response 	c (random challenge) 	Nonce de sesiune 
Proof 	POST /login/verify 	s = r + cx 	Client Authentication 
Token Issue 	Response 	access_token (JWT) 	Access Grant 

----------------------
rezultate și concluzii

------------------------
va multumesc