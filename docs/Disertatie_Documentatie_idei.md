

 ??? 
# clientul are un client id pe care il trimite cand trimite prima data secret_y?  da

Diferenta intre draftul gasit si implementarea curenta 
●	Draft: ar trebui ca secretul/cheia publica sa fie salvata la server si sa valideze semnatura din payload cu schnorr 
●	Implementarea curenta: autentificarea se face cu schnorr, si tokenul e validat la cererile de resurse cu orice altceva 
●	 
●	 
 
Ar trebui acele ABNSF pentru payloads ?  -> DA
 
Authorization header: bearer 
Event Structure pentru fiecare payload - Nu
 

 
Todo: adaugat un pre-exchange/handshake the parametrii globali, astfel fiecare server ar avea parametrii sai (P, G)   -Da
Utilitatea: Apărarea împotriva atacurilor de tip "Logjam" 
Dacă toate serverele din lume ar folosi același grup de parametri (de exemplu, un standard NIST vechi sau parametrii din client.py), un atacator cu resurse imense (ex: un stat-națiune) ar putea face un singur pre-calcul masiv (folosind Number Field Sieve) pentru acel număr prim specific. 
 
 
??? 
#######  
#downsides: serverul ar trebui sa stocheze id -> secret_y 
#upside: serverul nu mai are incredere in alt server 
#idee: protocolul OAuth, dar se adauga pasii aditionali pentru Schnorr proof 
 ####### 
 
 
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
Binding între Identitate și Token: Sistemul trebuie să garanteze că un Access Token emis este legat de sesiunea ZKP care l-a generat.  
Separarea Resurselor: Serverului de Autorizare.   trebuie să poată valida token-ul fără a re-executa protocolul Schnorr, dar folosind cheia publică a  
3.4. Reziliență la Interceptare (Anti-Sniffing): Sistemul trebuie să permită autentificarea chiar și pe canale nesigure sau compromise (Perfect Forward Secrecy la nivel de aplicație).  (https adauga un nivel de securitate, dar nu e necesar)
 
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
 
 
   https://mermaid.js.org/ 
4.4. Diagrama Procesului   
Diagrama 1: Fluxul de inregistrare 
 
 
  Diagrama 2: Fluxul de Autentificare (Sequence Diagram)   
 
 
  Diagrama 3: Consumul Tokenului (Post-Autentificare)   
 
 
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


























bibliografie


Protocol de autentificare OAuth cu Schnorr ZKP: Securitate fără partajare de secrete

oauth 
https://oauth.net/2/ 
https://datatracker.ietf.org/doc/html/rfc6749 oauth rfc
https://ieeexplore.ieee.org/abstract/document/6625487 shows how token leakage, traffic sniffing, and replay attacks can compromise OAuth systems
https://ieeexplore.ieee.org/abstract/document/6123701  - more on what oauth is used for
https://oauth.net/ - official site
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1 - last draft for v2.1

Schnorr
https://link.springer.com/article/10.1007/bf00196725 - first publication about schnorr signature algorithm
https://github.com/zk-Call/zkp-hmac-communication-js?tab=readme-ov-file - JavaScript implementation of a Schnorr-style zero-knowledge proof protocol combined with HMAC communication that lets a prover demonstrate knowledge of a secret (without revealing it) and authenticate messages securely between a client and server.

Books that consider schnorr for zkp authentication and comparison with other algorithms
https://theswissbay.ch/pdf/Gentoomen%20Library/Cryptography/Handbook%20of%20Applied%20Cryptography%20-%20Alfred%20J.%20Menezes.pdf 
https://eclass.uniwa.gr/modules/document/file.php/CSCYB105/Reading%20Material/%5BJonathan_Katz%2C_Yehuda_Lindell%5D_Introduction_to_Mo%282nd%29.pdf 

Miscellaneous about schnorr
https://en.wikipedia.org/wiki/Schnorr_signature 
https://www.geeksforgeeks.org/computer-networks/schnorr-digital-signature/ 
https://www.geeksforgeeks.org/software-engineering/schnorr-identification-scheme/ 
https://www.rfc-editor.org/rfc/rfc8235.html - Schnorr Non‑interactive Zero‑Knowledge (NIZK) Proof, describing how to prove knowledge of a discrete logarithm (e.g., a secret key) without revealing it
https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/ - diagram and explanations of a identification way using schnorr (continued here also https://crypto.stanford.edu/cs355/19sp/lec5.pdf )

Zkp
https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Proof%20Systems/The_Knowledge_Complexity_Of_Interactive_Proof_Systems.pdf definitions of zkp
https://www.academia.edu/43094897/Overview_and_Applications_of_Zero_Knowledge_Proof_ZKP -applications of zkp
https://eprint.iacr.org/2018/46  first practical implementation of transparent, post‑quantum secure zero‑knowledge proofs (ZK‑STARKs) that can be verified extremely efficiently (sublinear in data size) without relying on trusted setup
https://eprint.iacr.org/2025/921 - introduces zkAt, zero-knowledge authentication primitive that enables users to prove they satisfy authentication policies (such as signing requirements) without revealing those policies or sensitive details
https://www.mdpi.com/2079-9292/13/14/2730 - blockchain authentication scheme using zk-SNARK zero-knowledge proofs that enables privacy-preserving, anonymous user authentication while also allowing proactive revocation of credentials
https://www.e3s-conferences.org/articles/e3sconf/abs/2023/106/e3sconf_icegc2023_00085/e3sconf_icegc2023_00085.html  investigates how Zero-Knowledge Proofs (ZKP) can be integrated with OAuth 2.0 to improve anonymity and security in multi-agent distributed systems, exploring ways to verify claims without exposing sensitive data(schnorr is not included)

https://scholar.dsu.edu/theses/425/ token‑based authentication and authorization method using zero‑knowledge proofs to enhance web API security and privacy, demonstrating improved performance and resilience compared to traditional API authentication techniques

TLS 
https://www.rfc-editor.org/rfc/rfc8446 - latest rfc on TLS (former SSL), talks about the standard, improvements on the protocol and notes the known attacks (like 0‑RTT replay attacks, side channels, and traffic analysis )
https://www.mdpi.com/2410-387X/9/4/73 - discusses a future threat to TLS posed by quantum computers. It emphasizes that if post‑quantum cryptography (PQC) is not implemented, the current key exchange mechanisms would become insecure, leaving all previously and future transmitted data vulnerable to compromise
https://www.mdpi.com/2079-9292/13/20/4000 - TLS 1.3 strengthens privacy so much that analyzing traffic becomes technically challenging, and current methods are often insufficient.
https://www.techradar.com/pro/what-the-post-quantum-shift-means-for-your-security-strategy 
https://engineering.fb.com/2024/05/22/security/post-quantum-readiness-tls-pqr-meta/ - meta tries to add PQC

https://www.sciencedirect.com/science/article/abs/pii/S1574013725000140 - notes real-world implementation weaknesses and potential attack risks (misuses that could bring side‑channel, network attacks, zero‑day exploits), and emphasizes the need for future countermeasures and improved security practices.
https://www.diva-portal.org/smash/get/diva2%3A1742628/FULLTEXT01.pdf - studies the side‑channel vulnerabilities of post‑quantum cryptographic algorithms (Saber, CRYSTALS‑Kyber) and shows that even quantum‑safe schemes can be compromised in practice if implementations leak information through physical channels, highlighting the need for stronger resistance in future PQC designs


Other similar projects/researches
https://nostrcg.github.io/http-schnorr-auth - draft implementation of auth through schnorr
https://medium.com/%40prathyusha756/efficacy-of-schnorr-signature-for-stateless-authentication-5ae5d65ec5d3 - discussing efficiency of a authentication system with schnorr


Quantum 
https://eprint.iacr.org/2015/1075.pdf - analyzes the impending threat that large‑scale quantum computers pose to current public‑key cryptography

Algorithm similar to Schnorr
https://datatracker.ietf.org/doc/html/rfc5054 

ZKP Authentication Protocols
https://asecuritysite.com/pake 
https://en.wikipedia.org/wiki/Password_Authenticated_Key_Exchange_by_Juggling 
https://medium.com/@mainnetready/srp-a-zero-knowledge-protocol-for-password-authentication-1e19582aab29 
https://arxiv.org/abs/2401.11735 
https://sedicii.com/news/zero-knowledge-authentication/ 



—-------------------------------------------------------------------


https://blog.cloudflare.com/lattice-crypto-primer/ - protejarea unui secret impotriva quantum computing 

Protectie extra: folosirea unui canal cu PQC (lattice based criptography) 
Hybrid Auth: Folosirea Schnorr peste un canal deja securizat cu un algoritm post-cuantic pentru schimbul de chei.

