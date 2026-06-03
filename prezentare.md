
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