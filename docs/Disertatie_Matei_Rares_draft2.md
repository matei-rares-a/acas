 UNIVERSITATEA TEHNICĂ „Gheorghe Asachi” din IAȘI
FACULTATEA DE AUTOMATICĂ ȘI CALCULATOARE
MASTER: SECURITATEA SPATIULUI CIBERNETIC








todo

LUCRARE DE DIPLOMĂ






 
Coordonator științific
Ș.l.dr.inf. Silviu Paval
Absolvent
Matei Rareș 
 









DECLARAȚIE DE ASUMARE A AUTENTICITĂȚII
LUCRĂRII DE DIPLOMĂ



Subsemnatul(a)  MATEI RAREȘ,
legitimat(ă) cu   CI  , seria  NZ , nr. 037153 , CNP   5010223271540
autorul lucrării   
PLATFORMĂ DE GESTIUNE TODO
elaborată în vederea susținerii examenului de finalizare a studiilor de licență, programul de studii TODO organizat de către Facultatea de Automatică și Calculatoare din cadrul Universității Tehnice „Gheorghe Asachi” din Iași, sesiunea IULIE 2024 a anului universitar 2023-2024 , luând în considerare conținutul Art. 34 din Codul de etică universitară al Universității Tehnice „Gheorghe Asachi” din Iași (Manualul Procedurilor, UTI.POM.02 – Funcționarea Comisiei de etică universitară), declar pe proprie răspundere, că această lucrare este rezultatul propriei activități intelectuale, nu conține porțiuni plagiate, iar sursele bibliografice au fost folosite cu respectarea legislației române (legea 8/1996) și a convențiilor internaționale privind drepturile de autor.




	Data									Semnătura
 27.06.2024 
Cuprins todo
Introducere	1
Capitolul I.	Cerinte functionale, Actori, Teorie, tehnologii, arhitectură	3
I.1.	Noțiuni teoretice	3
I.1.1.	Zero Knowldge Proof	3
I.1.2.	Schema de identificare Schnorr	4
I.1.3.	Oauth, JWT, PKCE	5
I.2.	Tehnologii utilizate	6
I.2.1.	Python	6
I.2.2.	Javascript	7
I.3.	Cerinte functionale	7
I.3.1.	Actorii Sistemului	7
I.3.2.	Cerințe Funcționale Principale	8
I.3.3.	Cerințe Nefuncționale și Constrângeri de Securitate	8
I.4.	Arhitectura protocol	9
I.4.1.	Nivelul de prezentare	9
I.4.2.	Nivelul de aplicație	9
I.4.3.	Nivel de date	10
I.4.4.	Fluxul protocolului	10
Capitolul II.	Implementare si functionalitate protocol	12
II.1.	Funcționalitate User view	12
II.1.1.	Utilizator neautentificat	12
II.1.2.	Utilizator autentificat	12
II.1.3.	Manager de utilizatori	13
II.2.	Implementare	13
II.2.1.	Nivelul de prezentare super scurt ce face userrul si clietn app	13
II.2.2.	Nivelul de aplicație server side	14
II.2.3.	Smart contract	17
II.2.4.	Rețele neuronale	18
Concluzii	19
Bibliografie	21
Anexe	26





































TODO TITLU

Matei Rareș

Rezumat

În prezent, aplicațiile web moderne impun mecanisme robuste de autentificare la distanță, prin care utilizatorul trebuie să-și demonstreze identitatea digitală pentru a obține acces la resurse protejate. Într-un model tradițional, acest proces se bazează pe transmiterea unui secret partajat către server, abordare care, deși protejată aparent de protocoale precum TLS, rămâne vulnerabilă în fața unor vectori de atac precum compromiterea bazelor de date, interceptarea traficului în vederea decriptării ulterioare sau atacurile de tip replay. Aceste riscuri pot conduce la furt de identitate, pierderi financiare și încălcarea confidențialității utilizatorilor.
Dificultatea de a asigura o autentificare sigură fără a expune materialul secret pe rețea, conjugată cu creșterea constantă a suprafeței de atac în ecosistemul web, a motivat proiectarea unui protocol care să elimine aceste neajunsuri structurale, propunând totodată metode concrete de consolidare a încrederii utilizatorului în propriul sistem de autentificare.
Alegerea acestei teme este susținută de necesitatea de a reduce riscurile și costurile asociate eventualelor breșe de securitate, prin utilizarea unor tehnici criptografice avansate bazate pe demonstrații cu cunoștințe zero (eng. Zero-Knowledge Proof). În plus, s-a urmărit explorarea integrării schemei de identificare Schnorr într-o soluție practică, în care utilizatorul își poate dovedi identitatea fără ca parola sau cheia privată să părăsească vreodată dispozitivul local.
Acest lucru s-a realizat prin implementarea unui protocol hibrid care imbina demonstrația criptografică Schnorr cu cadrul de autorizare delegată OAuth, asigurand o verificare matematică riguroasă a identității clientului fără partajarea de secrete prin rețea. Accentul lucrării este plasat exclusiv pe etapa de autentificare, respectiv pe demonstrarea criptografică a identității prin schema Schnorr, in timp ce componenta de autorizare, reprezentată de emiterea și consumarea jetonului JWT, este integrată strict in scop demonstrativ, pentru a ilustra viabilitatea protocolului intr-un flux web complet. In aceeași logica, evaluarea comparativă cu implementările OAuth 2.0 clasice vizează diferențele de expunere a credențialelor in faza de autentificare, nu mecanismele de delegare a accesului.
În introducere, este descrisă în detaliu tematica, abordând contextul și importanța acesteia, după care sunt analizate critic soluțiile existente de autentificare și vulnerabilitățile pe care le prezintă.
Capitolul 1 oferă o prezentare a fundamentelor teoretice ZKP, schema Schnorr, OAuth, PKCE și JWT alături de motivele din spatele alegerii tehnologiilor utilizate, explicând cum aceste decizii au contribuit la dezvoltarea arhitecturii protocolului de autentificare.
Capitolul 2 se concentrează pe implementarea protocolului, oferind o descriere amănunțită a fiecărui pas din procesul de dezvoltare, a modelului matematic subiacent și a interfeței de programare a aplicațiilor (API), incluzând și componenta experimentală de evaluare comparativă cu fluxurile OAuth clasice.
La final, în secțiunea dedicată concluziilor sunt evidențiate rezultatele obținute prin testarea automatizată și evaluarea de performanță, diverse modalități de îmbunătățire a soluției actuale, urmată de bibliografia care include referințele utilizate.
Tehnologii principale folosite, alese pentru o implementare fluidă și predispusă dezvoltării sunt următoarele: Python [1], Flask [2], SQLite [3] și JavaScript [4]. Pe partea de server, au fost utilizate biblioteci criptografice precum cryptography și sympy, iar pytest și Locust pentru evaluarea calității. Suplimentar, s-au implementat trei fluxuri OAuth 2.0 auxiliare (inclusiv o variantă PKCE și una bazată pe Authlib) ca bază de referință obiectivă pentru analiza comparativă.
Din punct de vedere software, pentru a executa programul este nevoie de versiunea 3.10 de Python împreună cu diverse biblioteci criptografice, un mediu de rulare pentru serverul web, Npm [5] și un browser modern compatibil cu standardele actuale pentru interfața clientului.

Din punct de vedere hardware, aplicația a fost testată pe un dispozitiv cu sistem de operare Windows 10, 16 GB RAM și un procesor AMD Ryzen 5 4600H. 

Introducere

Aplicațiile web moderne depind in mod inerent de mecanisme robuste de autentificare la distanță, prin care se impune demonstrarea legitimității unei identități digitale de către utilizator, etapă urmată de decizia serverului privind acordarea accesului solicitat. In mod tradițional, acest proces se bazează pe utilizarea unui secret partajat, precum o parolă sau un cod temporar. Cu toate că protecția la nivelul stratului de transport prin intermediul protocolului HTTPS reduce semnificativ probabilitatea interceptării datelor in tranzit, arhitectura clasică ramane vulnerabilă in fața unei clase extinse de vectori de atac. Printre aceste vulnerabilități structurale se numără compromiterea bazelor de date, reutilizarea parolelor, configurarea defectuoasă a infrastructurii, capturarea traficului de rețea in vederea decriptării ulterioare, precum și atacurile de tip replay asupra unor materiale de autentificare care nu sunt ancorate corespunzător in contextul sesiunii curente.

In acest context, standardul OAuth 2.0 a fost adoptat la scară largă ca mecanism principal pentru autorizarea delegată [6], [7], [8]. Cu toate acestea, cadrul de lucru menționat nu soluționează in mod intrinsec problema atestării identității utilizatorului fără a presupune transmiterea credențialelor [9], [11]. In majoritatea implementărilor actuale, faza de autentificare inițială delegată serverului de autorizare se bazează in continuare pe un mecanism clasic, expus riscului de exfiltrare a parolei [10]. Astfel, se conturează necesitatea imperativă de a integra o metodă de autentificare superioară din punct de vedere criptografic in etapa premergătoare emiterii jetonului de acces.

Prin urmare, obiectivul principal al acestei lucrări este reprezentat de proiectarea și fundamentarea teoretică a unui sistem de securitate in care demonstrarea identității se realizează printr-o schemă criptografică Schnorr, fundamentată pe demonstrații cu cunoștințe zero (Zero-Knowledge Proof - ZKP). Principiul arhitectural de bază impune ca parola, sau cheia privată derivată din aceasta, să nu părăsească in niciun moment perimetrul securizat al dispozitivului clientului. In această paradigmă, serverul stochează exclusiv valoarea publică asociată identității și validează riguros dovada matematică, fără a dispune de informații referitoare la secretul originar. Emiterea unui jeton JWT in urma validării criptografice este integrată strict in scop demonstrativ, pentru a ilustra viabilitatea inserției protocolului Schnorr intr-un flux web complet, și nu constituie un obiectiv de cercetare in sine.

Pe langă implementarea fluxului ZKP, proiectul integrează o componentă experimentală complexă, menită să faciliteze o evaluare comparativă de profunzime. Astfel, au fost dezvoltate suplimentar două fluxuri OAuth 2.0 personalizate, incluzand o variantă bazată pe extensia PKCE și o versiune simplificată, precum și o a treia implementare generată prin intermediul bibliotecii Authlib. Aceste module secundare nu sunt destinate inlocuirii protocolului principal Schnorr, ci au rolul de a oferi o bază de referință obiectivă pentru analizarea costurilor operaționale, a structurii mesajelor tranzacționate și a gradului de expunere a credențialelor la nivelul rețelei. In aceeași logică, evaluarea comparativă cu aceste implementări OAuth 2.0 este concentrată exclusiv pe faza de autentificare, vizand diferențele de expunere a materialului secret in tranzit, nu mecanismele de delegare a accesului ulterioare emiterii jetonului.

In plan practic, demersul științific isi propune să clarifice validitatea realizării unei autentificări web complet funcționale in absența transmiterii parolei către server, precum și viabilitatea integrării acestui mecanism intr-un model de autorizare pe bază de jetoane, compatibil la nivel conceptual cu ecosistemul OAuth. De asemenea, sunt evaluate in mod critic avantajele de securitate pe care protocolul propus le aduce in comparație cu soluțiile convenționale, cuantificandu-se simultan costurile computaționale introduse. Nu in ultimul rand, sunt identificate limitările arhitecturii curente și sunt propuse modificările structurale necesare pentru o eventuală tranziție către un mediu de producție.

Pentru a atinge aceste deziderate, documentația este structurată in trei secțiuni principale. In primul capitol sunt introduse fundamentele teoretice, tehnologiile utilizate și arhitectura generală a sistemului. Al doilea capitol este dedicat descrierii cerințelor funcționale, prezentării modelului matematic subiacent și detalierii implementării concrete a protocolului, inclusiv a interfeței de programare a aplicațiilor (API). In cele din urmă, al treilea capitol expune metodologia de testare și rezultatele experimentale obținute, oferind o analiză de ansamblu a avantajelor și limitărilor soluției implementate, alaturi de direcțiile viitoare de cercetare și dezvoltare.

Capitolul I. 	Cerinte functionale, Actori, Teorie, tehnologii, arhitectură
In acest capitol sunt prezentate fundamentele teoretice ale protocolului propus, tehnologiile software alese pentru implementare, cerințele funcționale și nefuncționale ale sistemului, actorii implicați și arhitectura pe trei niveluri.


I.1. 	Noțiuni teoretice
I.1.1. 	Zero Knowldge Proof 
Demonstrația cu cunoștințe zero (Zero-Knowledge Proof - ZKP), formalizată inițial de Goldwasser, Micali și Rackoff in lucrarea fundamentală privind complexitatea cunoașterii in sistemele de demonstrații interactive [12], reprezintă un protocol criptografic fundamental prin intermediul căruia o entitate, denumită solicitant (prover / doveditor), poate demonstra unei alte entități, denumită verificator (verifier), veridicitatea unei afirmații sau cunoașterea unui secret, fără a dezvălui nicio informație suplimentară dincolo de simpla atestare a adevărului. Sistemul nu urmărește să afle parola utilizatorului, ci doar să obțină certitudinea matematică a cunoașterii acesteia. Pe lângă aplicabilitatea in autentificarea standard client-server, protocoalele ZKP au devenit instrumente esențiale pentru obținerea Identității Auto-Suverane (Self-Sovereign Identity) și a sistemelor care protejează confidențialitatea, spectrul de utilizare extinzandu-se semnificativ in ultimii ani, de la verificarea tranzacțiilor blockchain pana la validarea conformității datelor fără divulgarea conținutului [13]. Această paradigmă modernă elimină necesitatea unor entități intermediare de încredere (precum furnizorii de identitate de tip Google Sign-In sau Facebook) pentru atestarea identității, permițând utilizatorului să demonstreze direct și prin rigoare matematică faptul că este eligibil pentru accesarea resurselor, păstrând controlul absolut asupra secretelor sale.

În contextul securității cibernetice, principiul de bază al tehnologiei ZKP și avantajul său conceptual major impun ca, în niciun moment al procesului de autentificare, parola sau cheia privată să nu fie transmisă prin rețea, nici în format brut, nici măcar sub formă criptată. Această proprietate rezolvă vulnerabilități critice inerente protocoalelor tradiționale. Într-un sistem tradițional, chiar dacă parola este trimisă printr-un tunel securizat (HTTPS), serverul primește un material sensibil și trebuie să îl protejeze, fiind vulnerabil în cazul compromiterii canalului de transport.

În arhitectura ZKP, rețeaua transportă exclusiv transcrisul unei dovezi (valori matematice efemere), care nu poate fi reutilizat în afara contextului în care a fost generat. Astfel, protocolul oferă o reziliență absolută la atacurile de interceptare a traficului de tip „Store Now, Decrypt Later” [14]; dacă un adversar observă schimbul de mesaje, acesta va capta doar numere asociate unui proces tranzitoriu, extragerea secretului fiind imposibilă matematic. În al doilea rând, previne atacurile de tip Replay, deoarece natura interactivă a protocolului presupune emiterea unei provocări unice (challenge) de către server la fiecare încercare de conectare. Totodată, atenuează complet impactul breșelor de date (Data Leaks) prin eliminarea „secretului partajat”, serverul stocând exclusiv chei publice care sunt inutile unui atacator în lipsa dispozitivului și a parolei clientului.

În cadrul acestui proiect, tehnologia ZKP are un rol arhitectural vital, fiind utilizată pentru a consolida și înlocui mecanismele vulnerabile din fluxul standard OAuth 2.0. Conceptul nu rulează in izolare, ci se realizează printr-o mapare directă a fazelor ZKP peste etapele de autorizare delegată OAuth [17]. Abordări complementare, precum integrarea schemelor zk-SNARK in mecanisme de autentificare bazate pe blockchain [16], confirmă viabilitatea utilizării demonstrațiilor cu cunoștințe zero ca substituent al modelelor tradiționale de validare a identității, in contexte arhitecturale diverse. Concret, demonstrația ZKP, implementată în acest sistem prin schema de identificare Schnorr, preia rolul parametrului clasic de validare (precum client_secret sau transmiterea parolei brute), oferind o garanție matematică a identității pentru emiterea tokenului de acces [15], [18], fără ca secretul utilizatorului să părăsească vreodată mediul local al aplicației client.

I.1.2. 	Schema de identificare Schnorr 
Schema Schnorr [19], [20], [21], [25] reprezintă una dintre cele mai consacrate și robuste construcții criptografice fundamentate pe dificultatea computațională a problemei logaritmului discret in grupuri finite. In cadrul acestei arhitecturi, fundamentul matematic este riguros definit prin utilizarea unui număr prim sigur (safe prime), notat cu P, ce satisface egalitatea P = 2 · Q + 1, unde Q constituie, la randul său, un număr prim de dimensiuni mari. Peste acest număr prim se consideră grupul multiplicativ Z_P = {1, 2, ..., P-1}. Elementul central al schemei il reprezintă alegerea unui generator G ∈ Z_P asociat subgrupului de ordin Q, determinat prin relația matematică G = h² mod P, impunandu-se condițiile stricte de securitate ca G ≠ 1 și G^Q mod P = 1, pentru o valoare aleatoare h ∈ Z_P*.


Protocolul se desfășoară intre două entități: solicitantul (prover), care deține secretul, și verificatorul (verifier), care validează dovada fără a obține informații despre secret. Interacțiunea presupune o fază de pregătire și patru etape secvențiale:


Generarea perechii de chei: Cheia privată este reprezentată de o valoare secretă x ∈ Z_Q, cunoscută exclusiv de către solicitant. Cheia publică este dedusă matematic sub forma y = G^x mod P și este comunicată verificatorului, care o stochează și o asociază identității solicitantului.

Etapa de angajament (Commitment): Solicitantul alege un nonce aleatoriu și efemer r ∈ Z_Q. Pe baza acestuia, se calculează angajamentul criptografic temporar t = G^r mod P, valoare transmisă verificatorului.

Generarea provocării (Challenge): Verificatorul alege aleatoriu o provocare c ∈ Z_Q și o transmite solicitantului. Caracterul aleatoriu al provocării este esențial pentru securitatea protocolului, deoarece garantează faptul că solicitantul nu poate precalcula un răspuns valid fără cunoașterea efectivă a cheii private [22], [23].

Calculul răspunsului (Response): Dispunand de provocarea primită, solicitantul calculează dovada matematică sub forma s = (r + c · x) mod Q, valoare ce aparține grupului Z_Q. Această dovadă atestă cunoașterea secretului x fără a-l dezvălui.

Faza de verificare (Verification): Verificatorul evaluează concomitent doi termeni distincți, utilizand exclusiv cheia publică y:

left = G^s mod P

right = t · y^c mod P

Autentificarea este considerată validă dacă și numai dacă egalitatea fundamentală left = right este satisfăcută. Corectitudinea matematică a acestei verificări rezultă din substituția directă: G^s = G^(r + c·x) = G^r · G^(c·x) = t · y^c (mod P). Această proprietate oferă garanția matematică a identității solicitantului, eliminand necesitatea schimbului sau expunerii unor secrete prin intermediul canalului de comunicare [24], [26].

I.1.3. 	Open Authorization (OAuth)
Cadrul de autorizare delegată OAuth 2.0 reprezintă un standard industrial care permite aplicațiilor să obțină acces securizat la resurse protejate fără transmiterea credențialelor direct către aplicația consumatoare. Pentru clienții publici, extensia PKCE (Proof Key for Code Exchange), definită prin specificația RFC 7636 [28], adaugă un strat suplimentar de protecție impotriva interceptării codului de autorizare. In arhitectura prezentului proiect, acest cadru furnizează modelul structural pe care se grefează protocolul Schnorr: un Server de Autentificare verifică identitatea clientului și emite jetoane de acces (OAuth Access Tokens) in urma unei validări reușite.

In urma verificării criptografice, serverul generează un Access Token sub forma unui JSON Web Token (JWT) semnat, standardizat conform RFC 7519 [27], cu valabilitate limitată in timp. Clientul atașează acest jeton ca Bearer Token in antetul HTTP al cererilor ulterioare, eliminand necesitatea reluării procesului ZKP la fiecare interacțiune cu resursele protejate. Validarea jetonului este stateless: serverul verifică semnătura JWT fără a re-executa protocolul Schnorr, asigurand un cost operațional redus, conform modelului familiar aplicațiilor web moderne.

Implementările tradiționale ale fluxurilor OAuth 2.0, inclusiv variantele PKCE sau fluxul simplu Authorization Code, prezintă insă o deficiență fundamentală la nivelul fazei de autentificare. In aceste scheme, parola sau secretul brut traversează rețeaua in prima etapă, fiind transmise către serverul de autorizare. Chiar dacă materialul sensibil nu ajunge mai departe la serverul de resurse, el ramane expus față de emitent și constituie o țintă viabilă pentru atacatorii care interceptează traficul prin tehnici de tip traffic sniffing.

Soluția propusă in această lucrare nu inlocuiește ecosistemul bazat pe jetoane, ci fortifică exact etapa cea mai vulnerabilă: validarea identității inițiale. Mecanismul convențional de autentificare a clientului (parametrul client_secret sau transmiterea parolei brute) este substituit cu o dovadă criptografică Zero-Knowledge implementată prin schema Schnorr. Fazele protocolului se mapează direct peste fluxul OAuth: angajamentul (Commitment) servește drept inițiere a cererii de acces (Grant Initiation), provocarea (Challenge) funcționează ca nonce de sesiune, iar răspunsul matematic (Response) acționează ca etapă de Client Authentication, finalizandu-se cu emiterea JWT-ului. Securitatea este consolidată prin legarea de canal (Session Binding), care ancorează jetonul emis de contextul HTTP unic al sesiunii ZKP, impiedicand transferul malițios al jetonului intre contexte de rețea diferite.

I.2. 	Tehnologii utilizate
In acest subcapitol sunt prezentate limbajele de programare, cadrele de lucru și bibliotecile utilizate in implementarea protocolului, motivand alegerea fiecărei componente in raport cu cerințele de securitate și de prototipare rapidă ale sistemului.


I.2.1. 	Python
Nucleul aplicației server este dezvoltat in Python, un limbaj interpretat de nivel inalt, selectat pentru claritatea sintaxei, viteza de prototipare si ecosistemul extins de biblioteci. Python constituie fundamentul serverului de autentificare, al logicii criptografice Zero-Knowledge Proof (ZKP) si al infrastructurii de testare automatizata. Arhitectura software se bazeaza pe urmatoarele biblioteci si cadre de lucru:
Flask v3.0.0 si Flask-CORS v4.0.0 [29]: Micro-framework pentru aplicatii REST care gestioneaza rutarea URL, parsarea cererilor HTTP si serializarea raspunsurilor JSON. Flask-CORS aplica politicile de partajare a resurselor (Cross-Origin Resource Sharing) necesare comunicarii cu aplicatia client web.
Flask-SQLAlchemy v3.1.1 [30]: Asigura persistenta datelor printr-un ORM (Object-Relational Mapping) peste o baza de date SQLite locala (auth.db), adecvata unui prototip de laborator prin simplificarea instalarii si resetarea rapida a starii in timpul testelor. Schema integreaza trei tabele: utilizatorii inregistrati (stocand cheile publice secret_y), token-urile emise (AuthToken) si entitatile de date protejate (PersoData).PyJWT v2.12.1 [31]: Creeaza, semneaza si verifica token-uri conform standardului RFC 7519 (JSON Web Token). Dupa validarea demonstratiei Schnorr ZKP, serverul emite un Access Token semnat HS256, delegand autorizarea ulterioara fara reluarea procesului criptografic.
Authlib [32]: Furnizeaza o implementare de referinta a unui server OAuth 2.0 conform specificatiilor PKCE, cu rol strict analitic, permitand comparatia de performanta si securitate intre fluxurile traditionale de autorizare si paradigma ZKP.
pytest v9.0.3 si Locust [33], [34]: Formeaza nucleul ecosistemului de asigurare a calitatii. pytest gestioneaza suita de testare automatizata, acoperind cazuri functionale pozitive, negative, scenarii limita si vectori de atac criptografici. Locust evalueaza incarcarea concurenta, scalabilitatea si debitul de procesare (throughput) prin simularea unui numar mare de utilizatori.
cryptography v45.0.1 si sympy [35], [36]: Ofera primitive criptografice si instrumente matematice pentru generarea, validarea si testarea parametrilor grupului criptografic, asigurand rigoarea numerelor prime sigure (safe primes) utilizate ca fundament al protocolului Schnorr.

I.2.2. 	Javascript
Componenta client a sistemului este construita ca o aplicatie web statica, utilizand JavaScript, HTML si CSS fara cadre de lucru externe, pentru a pastra codul simplu si a permite observarea directa a mecanismelor de securitate implicate. JavaScript a fost ales deoarece reprezinta limbajul standard pentru dezvoltarea interfetelor grafice web, fiind suportat nativ de toate browserele moderne fara a necesita instalarea unor componente suplimentare.
JavaScript gestioneaza interfata grafica (formulare, cereri asincrone catre server, actualizarea starii) si, totodata, executa calculele criptografice ale protocolului ZKP pe dispozitivul utilizatorului. Prin utilizarea tipului de date BigInt pentru aritmetica de precizie arbitrara si a API-ului Web Crypto pentru generarea de valori aleatorii criptografic sigure, toate operatiile matematice ale schemei Schnorr (generarea angajamentului, calculul raspunsului) se desfasoara local. Aceasta abordare asigura faptul ca parola sau cheia privata nu parasesc browserul si nu sunt transmise prin retea in niciun moment al procesului de autentificare.
In plus, codul include un mecanism de afisare a traficului HTTP, care permite utilizatorului sa vizualizeze cererile si raspunsurile schimbate intre client si server. Aceasta functionalitate are un rol didactic si experimental, facilitand compararea directa a mesajelor protocolului.

I.3. 	Cerinte functionale
I.3.1. 	Actorii Sistemului

Sistemul implica trei roluri logice distincte, dintre care unele sunt colocate in cadrul prototipului pe acelasi server:

Clientul (Solicitant / Prover): Reprezentat de aplicatia web rulata in browserul utilizatorului. Acesta detine local parola (din care se deriveaza cheia privata) si executa calculele matematice ale schemei Schnorr pentru a-si demonstra identitatea fara a transmite secretul.
Serverul de Autentificare (Verificator / Emitent de Token): Stocheaza exclusiv cheia publica a utilizatorului, genereaza provocarea de sesiune, verifica dovada matematica primita de la client si emite jetoanele de acces (JWT).
Serverul de Resurse: Componenta logica, in prototip gazduita pe acelasi server, care permite accesul la datele protejate strict pe baza jetonului emis in urma autentificarii.
In scop experimental, arhitectura include si un Server de Autorizare OAuth 2.0, implementat in doua variante personalizate si o varianta bazata pe biblioteca Authlib, utilizat pentru evaluarea comparativa a fluxurilor de securitate.


I.3.2. 	Cerințe Funcționale Principale

Pentru a asigura o validare criptografică robustă și o integrare fluidă cu mecanismele de autorizare delegată, sistemul trebuie să respecte următorul flux operațional:
•	Pre-schimbul parametrilor publici (Handshake - engl.): Sistemul trebuie să permită clientului obținerea parametrilor criptografici globali ai grupului (P, G) printr-un punct terminal (endpoint) dedicat. Această abordare previne atacurile de tip Logjam; prin utilizarea unor parametri specifici fiecărui server, se evită vulnerabilitatea majoră în fața unui pre-calcul comun (utilizând algoritmi precum Number Field Sieve) realizat de un adversar cu resurse computaționale mari asupra unui grup standardizat comun.
•	Înregistrarea: Sistemul trebuie să permită clientului generarea locală a perechii de chei și transmiterea exclusivă a valorii publice (y = G^x mod P) alături de un identificator (`client_id`), serverul stocând doar această asociere, fara ca parola sa părăsească dispozitivul clientului.
•	Autentificarea, unde, protocolul trebuie sa se desfasoare in urmatoarele etape: 
o	Angajament (Commitment - engl.): Clientul calculeaza un angajament criptografic efemer (t = G^r mod P) si il transmite serverului impreuna cu client_id, fara a expune parola.
o	Provocarea (Challenge - engl.): Serverul genereaza un numar aleatoriu unic, asociat sesiunii curente si contextului de retea, pe care il transmite clientului.
o	Solutia (Response - engl.): Clientul calculează și transmite dovada matematică (s) utilizând secretul propriu, angajamentul inițial și provocarea primită.
o	Verificarea (Verification - engl.): Serverul valideaza matematic dovada prin egalitatea G^s = t · y^c (mod P). Daca ecuatia este satisfacuta, identitatea clientului este confirmata.
•	Autorizarea și Sesiunea:  In urma verificarii, serverul emite un jeton de acces JWT semnat, cu valabilitate limitata in timp. Clientul utilizeaza acest jeton (Bearer Token) pentru accesul ulterior la resurse, fara a relua protocolul.

I.3.3. 	Cerințe Nefuncționale și Constrângeri de Securitate
Securitatea și robustețea sistemului sunt asigurate prin respectarea unor constrângeri stricte de proiectare:
•	Zero-Knowledge și reziliență la interceptare (Anti-Sniffing): În niciun moment al protocolului, parola sau cheia privată nu traversează rețeaua, nici măcar în format criptat. Sistemul permite autentificarea sigură chiar și pe canale nesigure sau compromise (deși criptarea de transport HTTPS adaugă un nivel de securitate suplimentar, nu este o precondiție pentru protejarea secretului).
•	Protecție la atacuri tip replay și legarea de canalul de comunicare (Session Binding): Transcrisul unei autentificări interceptate nu poate fi refolosit într-o altă sesiune. Sistemul garantează că un jeton emis este criptografic legat de sesiunea ZKP care l-a generat, prevenind transferul jetonului între contexte de rețea diferite.
•	Separarea resurselor (Statelessness): Serverul trebuie să valideze jetonul JWT exclusiv prin verificarea semnăturii, fără a re-executa protocolul Schnorr.
•	Validarea parametrilor: Valorile publice recepționate de la client trebuie validate matematic ca membri legitimi ai subgrupului corect. Cererile invalide, datele malformate și tentativele de fraudă trebuie respinse fără a genera erori de server.
•	Transparență și Lipsa Anonimizării Identității: Sistemul permite auditarea traficului si evaluarea comparativa a protocoalelor. Identificatorul client_id este transmis in clar in fazele de inregistrare si angajament. Protocolul protejeaza exclusiv secretul de autentificare, nu si metadatele de identitate.

I.4. 	Arhitectura protocol
Sistemul este organizat pe trei niveluri funcționale: prezentare, aplicație și date. Această separare permite delimitarea clară a responsabilităților fiecărui strat și decuplarea logicii de securitate de restul componentelor. Comunicarea dintre niveluri se realizează prin cereri HTTP asincrone, iar baza criptografică a întregului sistem este problema logaritmului discret pe grupuri finite, implementată prin schema de identificare Schnorr.
I.4.1. 	Nivelul de prezentare 
Nivelul de prezentare se ocupă de interacțiunea cu utilizatorul, afișarea datelor și execuția calculelor locale. Construit cu tehnologii web standard, acest nivel ghidează utilizatorul prin trei etape: afișarea ecranului introductiv, generarea perechii de chei criptografice și transmiterea valorii publice in cadrul înregistrării, respectiv execuția protocolului cu cunoștințe zero in cadrul autentificării. Tot la acest nivel este integrat un monitor de rețea in timp real, care permite utilizatorului să inspecteze traficul HTTP.
I.4.2. 	Nivelul de aplicație
Nivelul de aplicație conține logica de procesare și gestionează punctele de acces HTTP. Acest strat, scris in Python cu ajutorul micro-framework-ului Flask, verifică dacă valorile criptografice primite aparțin subgrupului Schnorr, administrează fluxurile de autorizare și păstrează starea temporară a sesiunilor intre etapele protocolului, folosind un sistem de stocare volatil. După o verificare reușită, serverul emite un jeton de acces JWT, compus din antet, sarcină utilă și semnătură criptografică. Un aspect important al acestui nivel este legarea de canal (Session Binding): serverul nu verifică dovezile izolat, ci le leagă de contextul HTTP curent, care include adresa de rețea, antetul User-Agent, identificatorul de sesiune și identitatea clientului, prevenind astfel atacurile de interceptare și retransmisie (relay și session hijacking).
I.4.3. 	Nivel de date
Nivelul de date asigură stocarea informației printr-o bază de date relațională, accesată prin abstractizări ORM. Baza de date păstrează trei categorii de informații: identitatea publică a utilizatorului, referințele jetoanelor emise și datele personale protejate. Aspectul cel mai relevant al acestui nivel este modul in care sunt tratate credențialele: serverul nu stochează parola in clar, nici sub formă de hash și nici scalarul privat asociat. Singura valoare criptografică păstrată pentru verificare este cheia publică.
I.4.4. 	Fluxul protocolului
Comunicarea asincronă Client-Server se desfășoară printr-o succesiune strictă de pași matematici, ale căror etape se mapează direct peste conceptul cadru de autorizare delegată OAuth 2.0:
1)	Etapa de Configurare (Setup - Precondiție): Se stabilesc parametrii publici ai grupului (de dimensiuni mari, sigure), iar clientul își derivă local secretul.
2)	Etapa 0 - Înregistrarea: Clientul transmite către server exclusiv cheia publică generată, alături de un identificator, pentru a fi asociate în baza de date.
3)	Etapa 1 - Angajamentul (Commitment): Clientul alege un număr aleatoriu efemer, calculează un angajament criptografic și îl transmite serverului. Mapare OAuth: Această etapă reprezintă inițierea cererii de acces (Grant Initiation).
4)	Etapa 2 - Provocarea (Challenge): Serverul memorează temporar angajamentul și generează un număr aleatoriu unic pe care îl transmite clientului. Acest pas previne atacurile de tip Replay. Mapare OAuth: Provocarea funcționează ca un nonce de sesiune.
5)	Etapa 3 - Soluția (Proof): Clientul calculează o dovadă matematică folosind secretul său, angajamentul inițial și provocarea primită, trimițând rezultatul spre verificare. Mapare OAuth: Aceasta îndeplinește rolul de autentificare a clientului (Client Authentication).
6)	Etapa 4 - Verificarea (Verification & Token Issue): Serverul validează egalitatea matematică a dovezii în raport cu cheia publică stocată. Dacă egalitatea se confirmă, serverul are garanția identității utilizatorului și emite jetonul de acces JWT. Mapare OAuth: Emiterea jetonului reprezintă decizia finală de autorizare (Access Grant).

Capitolul II. 	Implementare si functionalitat
În acest capitol, este descris în amănunt modul de interacțiune al diferitelor tipuri de utilizatori cu interfața grafică a aplicației, precum și modul în care aceasta este implementată. Sunt prezentate diverse scenarii de utilizare, explicându-se cum fiecare tip de utilizator navighează prin interfață, efectuează acțiuni specifice și utilizează funcțiile oferite de aplicație. În ceea ce privește implementarea, capitolul conține secțiuni detaliate cu fragmente de cod explicate, ilustrând cum au fost realizate diferitele componente și funcționalități ale aplicației.

II.1. 	Modelarea fluxurilor operatioanle
II.1.1. 	Inregistrare
Diagrama 1: Fluxul de înregistrare
Fluxul de înregistrare descrie modul în care un client derivă cheia privată x din credențialele locale (utilizând scrypt ca funcție de derivare a cheii), calculează cheia publică Schnorr y = G^x mod P și transmite exclusiv perechea (client_id, y) către server. Serverul validează apartenența lui y la subgrupul de ordin Q (verificând y^Q ≡ 1 mod P) și stochează asocierea client_id → y. Credențialele brute nu traversează niciodată canalul de comunicație. Diagrama completă este disponibilă în fișierul diagrams/diagram_registration_flow.mmd.

Diagrama 1: Fluxul de inregistrare 
 
 

II.1.2. 	Autentificare
Diagrama 2: Fluxul de Autentificare
Fluxul de autentificare acoperă cei patru pași ai protocolului Schnorr: (1) clientul generează un nonce r și calculează angajamentul t = G^r mod P, pe care îl transmite împreună cu client_id; (2) serverul calculează provocarea c ca funcție hash deterministă a contextului sesiunii (adresă IP, User-Agent, session_id, client_id, t), realizând legarea de canal; (3) clientul calculează dovada s = (r + c·x) mod Q și o transmite cu identificatorul de sesiune în antet; (4) serverul verifică egalitatea G^s ≡ t · y^c (mod P) și, în caz de succes, emite un JWT semnat HS256. Diagrama completă este disponibilă în fișierul diagrams/diagram_login_flow.mmd.

  Diagrama 2: Fluxul de Autentificare (Sequence Diagram)   
 
 

II.1.3. 	Consumul tokenului
Diagrama 3: Consumul Tokenului (Post-Autentificare)
Mașina de stări a clientului descrie ciclul de viață complet: de la starea inițială Idle, prin derivarea cheii, angajament, provocare, verificare, până la starea Authenticated. Token-ul JWT obținut este utilizat ca Bearer Token pentru accesul la resursele protejate. La expirarea token-ului (după 3600 de secunde), clientul revine la starea Idle și reia protocolul. Diagrama completă este disponibilă în fișierul diagrams/diagram_auth_state_machine.mmd.

  Diagrama 3: Consumul Tokenului (Post-Autentificare)   
 \

II.1.4. 	Comparatie intre protocoale ZKP si OAuth 2.0 todo

sfdsf
Diagramă care să arate unde se încadrează Schnorr în fluxul OAuth 2.0 (înlocuind client_secret cu ZKP Proof). 
 Etapa 	  Metoda HTTP 	Parametri Cheie 	Rol în OAuth 
Commitment 	POST /login/commit 	client_id, t = g^r 	Inițiere Grant 
Challenge 	Response 	c (random challenge) 	Nonce de sesiune 
Proof 	POST /login/verify 	s = r + cx 	Client Authentication 
Token Issue 	Response 	access_token (JWT) 	Access Grant 
  




II.2. 	Formalizarea protocolului
II.2.1. 	Parametri și model matematic 
Arhitectura implementată se fundamentează pe utilizarea unui prim sigur (safe prime – engl.) P, garantând astfel un număr prim Q = (P - 1) / 2. Prin stabilirea generatorului G = 4, operațiunile matematice se desfășoară exclusiv în subgrupul de ordin Q asociat lui Z_P*. Componentele esențiale ale schemei sunt definite după cum urmează:

Cheia privată: x
Cheia publică: y = G^x mod P
Valoarea efemeră (nonce – engl.): r
Angajamentul (commitment – engl.): t = G^r mod P
Provocarea (challenge – engl.): c
Răspunsul: s = (r + c x) mod Q

Se observă că validarea identității este confirmată exclusiv prin satisfacerea următoarei egalități:

G^s mod P = t y^c mod P (1)

s: răspunsul matematic calculat local de către client
t: angajamentul criptografic inițial
y: cheia publică stocată a utilizatorului
c: provocarea matematică verificată de server

Spre deosebire de standardul Schnorr convențional, prezenta soluție tehnologică derivă provocarea printr-un mecanism riguros de legare a sesiunii (session binding – engl.), ancorând transcrisul criptografic de contextul rețelei observat la nivel de server:

c = int(SHA-256(Addr | UA | SID | CID | t)) mod Q (2)

Addr: adresa TCP a partenerului de rețea
UA: agentul utilizator (User-Agent – engl.)
SID: identificatorul unic și temporar al sesiunii
CID: identificatorul asociat clientului
t: angajamentul criptografic recepționat anterior

II.2.2. 	Faza de autenficiar
Faza de autentificare este împărțită în două cereri HTTP.
Pasul 1, commit:
1.	Clientul alege r printr-un generator criptografic de numere pseudoaleatoare.
2.	Calculează t = G^r mod P.
3.	Trimite POST /login/commit cu client_id și commitment_t.
4.	Serverul verifică faptul că utilizatorul există, că t aparține subgrupului și că nu există o sesiune activă incompatibilă pentru același utilizator.
5.	Serverul generează session_id, calculează valoarea de legare a sesiunii și derivă provocarea challenge_c.
6.	Serverul răspunde cu provocarea challenge_c și session_id.
Pasul 2, verify:
1.	Clientul calculează s = (r + c x) mod Q.
2.	Trimite POST /login/verify, incluzând solution_s în corpul JSON și X-Auth-Session: session_id în antet.
3.	Serverul verifică existența sesiunii, expirarea ei, intervalul valid pentru s și coerența valorii de legare a sesiunii.
4.	Serverul citește cheia publică y a utilizatorului din baza de date.
5.	Verifică egalitatea Schnorr.
6.	Dacă dovada este validă, emite JWT-ul și șterge imediat sesiunea temporară.
În implementarea curentă, sesiunea de autentificare are un TTL de 5 secunde, iar o a doua încercare de commit pentru același utilizator, apărută după o fereastră de 50 ms, este tratată ca potențială tentativă de preluare abuzivă a sesiunii și duce la invalidarea sesiunii existente. Acest comportament este util experimental și este acoperit de testele automate, însă reprezintă și un compromis de ergonomie care va fi discutat în capitolul de limitări.

II.3. 	Structura și serializarea mesajelor în protocolul HTTP


Pentru a asigura interoperabilitatea și o comunicare deterministă între client (client – engl.) și server (server – engl.), protocolul definește formal schema de date, antetele necesare și formatul mesajelor transmise [37].

A.	Antete și Convenții REST

Interfața expusă este de tip REST JSON (Representational State Transfer – engl.), necesitând utilizarea tipului de conținut „application/json”. Pe lângă antetele standard de autorizare, implementarea emite o serie de antete suplimentare pentru trasabilitate și securitate, precum „Request-ID”, „API-Version”, „X-Response-Time”, „Server-Timing”, „X-Content-Type-Options”, „X-Frame-Options”, „Content-Security-Policy” și „Referrer-Policy” [38]. În cazul răspunsurilor neautorizate de tip 401, este inclus și antetul „WWW-Authenticate”. Punctele terminale (endpoints – engl.) principale ale arhitecturii sunt definite după cum urmează:

/health (GET): Verificarea stării de funcționare a serverului.
/parameters (GET): Publicarea parametrilor criptografici globali P și G.
/register (POST): Înregistrarea identificatorului și a valorii publice a secretului.
/login/commit (POST): Inițierea autentificării prin transmiterea angajamentului criptografic.
/login/verify (POST): Verificarea dovezii matematice și emiterea jetonului.
/data (GET, POST, PUT): Accesarea resurselor protejate exclusiv prin jeton.
/oauth/pkce/și /oauth/simple/(POST): Fluxuri de autorizare comparativă (Authorization Code – engl.) [3].
B.	Structura Sarcinii Utile (JSON Payload)

Valorile numerice masive, rezultate din calculele Schnorr, sunt serializate sub formă de șiruri de caractere (strings – engl.) reprezentând întregi zecimali, metodă implementată pentru a garanta precizia procesării la nivelul clientului web [4]. Formatul mesajelor pe parcursul etapelor de validare se structurează astfel:

1. Faza de Înregistrare: Se furnizează identificatorul utilizatorului și cheia publică generată.
{ "client_id": "alice", "secret_y": "12345678901234567890" }
2. Faza de Angajament (Commitment – engl.): Solicitantul transmite un angajament efemer, calculat pe baza unui factor aleatoriu.
{ "client_id": "alice", "commitment_t": "98765432109876543210" }

Drept răspuns, entitatea verificatoare emite o provocare matematică și un identificator de sesiune:
{ "challenge_c": "112233445566778899", "session_id": "opaque-session-token" }

3. Faza de Verificare (Verify – engl.): Solicitantul atestă deținerea cheii private prin furnizarea soluției matematice.
{ "solution_s": "998877665544332211" }

În cazul unei validări cu succes, serverul eliberează un jeton web (JSON Web Token – engl.):
{ "token": "jwt-string" }
C.	Semantica și Definirea Formală în Notație ABNF

Fiecare variabilă implicată îndeplinește un rol fundamental în mitigarea vulnerabilităților de rețea. Provocarea generată de server invalidează atacurile de reluare (replay attacks – engl.) impunând o demonstrație temporală unică, în timp ce angajamentul asociază criptografic sesiunea de un element aleatoriu nedezvăluit. Pentru asigurarea standardizării formale, sintaxa se definește prin notația ABNF (Augmented Backus-Naur Form – engl.) [39]:

client-id = 1*(ALPHA / DIGIT / "-" / "*")
schnorr-value = 1*DIGIT
session-id = 1*(ALPHA / DIGIT / "-" / "*")
jwt-token = 1*(ALPHA / DIGIT / "." / "-" / "_")
q-string = DQUOTE 1*(VCHAR / SP) DQUOTE

registration-payload = "{" DQUOTE "client_id" DQUOTE ":" q-string "," DQUOTE "secret_y" DQUOTE ":" q-string "}"
commitment-payload = "{" DQUOTE "client_id" DQUOTE ":" q-string "," DQUOTE "commitment_t" DQUOTE ":" q-string "}"
challenge-response = "{" DQUOTE "challenge_c" DQUOTE ":" q-string "," DQUOTE "session_id" DQUOTE ":" q-string "}"
verify-payload = "{" DQUOTE "solution_s" DQUOTE ":" q-string "}"
auth-success-payload = "{" DQUOTE "token" DQUOTE ":" q-string "}"

authorization-header = "Bearer" SP jwt-token
session-header = "X-Auth-Session:" SP session-id

Din punct de vedere conceptual, se observă că protocolul limitează transferul de date la identități publice și parametri de sesiune, excluzând în totalitate expunerea cheii private [6].

D.	Gestionarea Stării și Securitatea la Nivel HTTP

Protocolul matematic impune retenția unei stări temporare (stateful – engl.) între momentul inițierii angajamentului și faza verificării. Pentru sistemele distribuite, este necesară externalizarea acestei stări către o memorie volatilă centralizată [7]. Permisiunile pre-solicitare sunt gestionate riguros prin strategii de partajare a resurselor între origini (Cross-Origin Resource Sharing – engl.). Odată finalizată autorizarea, se recomandă evitarea stocării jetonului în spații locale expuse vulnerabilităților de injecție a scripturilor (Cross-Site Scripting – engl.), fiind indicată încapsularea acestuia în cookie-uri protejate prin directivele „HttpOnly” și „Secure” [40]..”

II.4. 	Detalii de implementare
A.	Server Flask

Arhitectura de server bazată pe micro-framework-ul Flask (micro-framework – engl.) constituie nucleul logic de procesare, având rolul de a gestiona starea, de a efectua validări stricte și de a emite jetoane web (JSON Web Token – engl.) [41]. Implementarea operațională evidențiază următoarele elemente cheie:

1. Verificarea apartenenței la subgrup: Prin funcția „is_subgroup_member” se evaluează condiția matematică value^Q mod P = 1, respingându-se valorile triviale pentru eliminarea riscurilor asociate atacurilor de tip subgrup mic (small subgroup attack – engl.) [2].
2. Gestiunea sesiunilor concurente: Structura specializată „_SessionStore” integrează un index invers de tipul identificator de utilizator (client-id – engl.) către identificator de sesiune (session-id – engl.), facilitând detecția și blocarea tentativelor de angajament concurente pentru același utilizator.
3. Legarea contextului de rețea și eliberarea jetonului: Prin intermediul funcției „_compute_session_binding” se corelează sesiunea cu datele de transport, urmând ca rutina „_issue_jwt” să genereze un jeton valid pentru o durată de o oră. Punctul terminal (endpoint – engl.) „/data” condiționează accesul la resurse de validarea prealabilă a semnăturii și a expirării jetonului, în timp ce antetele defensive de tip control cache (Cache-Control – engl.) [42] previn stocarea datelor în nodurile intermediare
B.	Arhitectura Clientului Web
Nivelul de prezentare execută în mod activ calculele criptografice direct în mediul de rulare al browserului (browser – engl.), fluxul fiind implementat în modulul „login.js” [4]:

1. Succesiunea etapelor de logare: Procesul inițiază prin preluarea parametrilor P și G, urmată de derivarea locală a scalarului privat x. Ulterior, se generează un parametru aleatoriu r prin interfața nativă „window.crypto.getRandomValues” [43], calculându-se angajamentul (commitment – engl.) t.
2. Finalizarea autentificării și monitorizarea: Transmiterea angajamentului este urmată de recepționarea unei provocări (challenge – engl.) și a unui identificator de sesiune, elemente necesare calculării răspunsului final s. Pentru facilitarea auditării, un monitor integrat interceptează apelurile de preluare (fetch – engl.), afișând structura completă a antetelor și a sarcinilor utile (payloads – engl.) [5].
C.	Fluxuri OAuth2 Comparativ

În scop analitic, sistemul integrează trei variante distincte ale cadrului de autorizare OAuth2, implementate în modulele „server_oauth.py” și „server_authlib.py” [6]:

1. Configurații disponibile: Se remarcă o implementare personalizată cu cheie de probă (Proof Key for Code Exchange – PKCE – engl.), o variantă simplificată lipsită de PKCE și o integrare bazată pe biblioteca nativă Authlib.
2. Obiective experimentale: Validarea utilizatorilor se bazează pe parole rezumate prin algoritmul SHA-256. Aceste fluxuri permit evaluarea comparativă directă între modelul tradițional – unde credențialele tranzitează rețeaua spre punctul terminal de autorizare – și modelul ZKP, care vehiculează exclusiv valori matematice efemere [7].

D.	Considerente Criptografice și Derivarea Secretului 
Documentația evidențiază o demarcație clară între specificațiile teoretice de securitate și adaptările necesare fazei de prototip [8]:
1. Modelul ideal de derivare: Conceptual, derivarea secretului privat x din parola utilizatorului necesită utilizarea unei funcții cu rezistență sporită la atacuri de dicționar, precum scrypt (scrypt – engl.) [44], aspect documentat în scriptul „calculations.py” prin aplicarea unui salt (salt – engl.) aleatoriu.
2. Implementarea demonstrativă și optimizări: Din motive de portabilitate, modulul browser „auth.js” utilizează un hash SHA-256 aplicat asupra concatenării identificatorului cu parola, incluzând un mecanism de rezervă (fallback – engl.) cu parametri reduși (P = 2089, G = 4) în caz de indisponibilitate a serverului. Pentru alinierea la standardele de producție, se impune stocarea securizată a elementelor de salt pe client și eliminarea parametrilor criptografici slabi [9].
II.5. 	Considerente de securitat

1)	 Rezistența la Interceptare și Decriptare Ulterioară

Securitatea arhitecturii propuse nu este condiționată de criptarea canalului de transport (Transport Layer Security – TLS), ci rezidă în dificultatea computațională a rezolvării problemei logaritmului discret într-un grup de ordin prim [45], [50]. În sistemele convenționale, compromiterea canalului prin strategii de stocare și decriptare ulterioară (store now, decrypt later – engl.) expune credențialele în clar. În schema Schnorr, un atacator care realizează interceptarea traficului (traffic sniffing – engl.) vizualizează exclusiv transcrisul efemer compus din angajament, provocare și soluție. Extragerea cheii private necesită determinarea variabilei din ecuația liniară:

s = (r + c · x) mod q

 (1)

Unde:

s reprezintă soluția matematică sau dovada transmisă de solicitant;
r constituie numărul efemer aleatoriu (nonce – engl.) necunoscut atacatorului;
c reprezintă provocarea unică generată de server;
x constituie cheia privată (parola) protejată a utilizatorului.

Prin urmare, utilizarea acestui mecanism asigură secretul perfect și imunitatea în fața compromiterii totale a stratului de transport [46], [47], [48], [49].

2)	 Eliminarea Secretului Partajat și Reziliența la Scurgeri de Date

Spre deosebire de modelele clasice de autentificare, se elimină definitiv necesitatea transmiterii sau stocării unui secret partajat (shared secret – engl.) [11]. Serverul persistă exclusiv cheia publică asociată, aspect ce neutralizează impactul compromiterii bazei de date prin injecție SQL (SQL injection – engl.) sau scurgeri de date (data leaks – engl.). Deoarece cheia privată nu părăsește mediul local al clientului, impersonarea utilizatorilor în urma unui atac la nivelul serverului devine matematic imposibilă.

3)	 Atenuarea Atacurilor de Reluare și Deturnare

Prevenirea atacurilor de reluare (replay attacks – engl.) este garantată prin caracterul interactiv al protocolului, serverul generând o provocare unică pentru fiecare tentativă de acces [51]. Soluția transmisă este validă strict corelată cu provocarea și angajamentul curente. Complementar, riscul de deturnare a sesiunii (session hijacking – engl.) este diminuat prin includerea unui parametru de expirare în structura jetonului eliberat, restrângând fereastra de oportunitate a vectorilor de atac.

4)	 Descentralizare și Identitate Auto-Suverană

Arhitectura validează identitatea într-o manieră descentralizată, înscrisă în paradigma de identitate auto-suverană (self-sovereign identity – engl.) [52]. Prin eliminarea intermediarilor sau a furnizorilor terți de identitate, serverul acționează ca o entitate de verificare autonomă, atestarea realizându-se prin rigoare matematică directă între noduri.

Capitolul III. 	Validare , rezultate ssi analiza
În acest capitol sunt prezentate metodologia de testare, rezultatele obținute în urma rulării suitelor automate și a măsurătorilor de performanță, precum și o analiză critică a avantajelor și limitărilor protocolului propus.
III.1. 	Strategia si metodologia de tetare


Validarea sistemului a fost realizată printr-o strategie multistratificată, acoperind exhaustiv corectitudinea funcțională, robustețea, securitatea criptografică și performanța, fiind utilizat un cadru de testare automatizat (framework - engl.) bazat pe pytest. Evaluarea este structurată în cinci direcții fundamentale: scenarii pozitive pentru fluxurile nominale, scenarii negative vizând respingerea intruziunilor, cazuri limită (corner cases - engl.) destinate frontierelor matematice ale grupului Schnorr și intrărilor malformate, teste de securitate împotriva vectorilor de atac specifici și validări ale fluxurilor de autorizare delegată OAuth2. Pentru a se garanta izolarea și reproductibilitatea analizei, s-a implementat execuția acestor suite printr-un modul central de orchestrare, operând asupra unui client Flask de testare izolat de mediul HTTP, starea bazei de date și a sesiunilor fiind reinițializată sistematic înaintea fiecărei instanțe pentru eliminarea oricăror dependențe secvențiale.

În completarea validării funcționale propriu-zise, metodologia a impus integrarea unor instrumente experimentale de evaluare a performanței (benchmark - engl.) destinate monitorizării latenței și a consumului de memorie, alături de simulări ale încărcării concurente (load testing - engl.) prin intermediul platformei Locust, audit sistematic de trafic și scenarii avansate de simulare a atacurilor. În consecință, pentru fundamentarea analizei curente, au fost parcurse trei execuții experimentale majore: validarea globală a calității codului, simularea automatizată a amenințărilor criptografice și fluxul complet de măsurare, acesta din urmă incluzând evaluări offline și testări în regim live cu cincizeci de utilizatori concurenți pe o durată prestabilită de treizeci de secunde, confirmându-se astfel în mod obiectiv viabilitatea operațională și reziliența soluției abordate.
III.2. 	Validarea functionala si teste de securitat

În cadrul procesului de evaluare empirică a sistemului propus, s-a procedat la analiza sistematică a cazurilor pozitive care validează comportamentul corect al platformei pe traseul nominal (happy path – engl.). Se observă că înregistrarea unui utilizator nou implică stocarea exclusivă la nivelul serverului a cheii publice definite prin relația y = G^x mod P, fără a se reține parola în formă brută sau sub aspectul unui rezumat criptografic (hash – engl.) calculabil, aspect confirmat prin verificarea explicită a faptului că înregistrarea serializată nu conține date în clar sau amprente de tip SHA-256, SHA-512 ori MD5. Fluxul complet de autentificare, structurat pe etapele de angajament (commit – engl.) și verificare (verify – engl.), a fost validat prin generarea de către client a unui element aleatoriu (nonce – engl.) notat cu r, determinarea angajamentului (commitment – engl.) t = G^r mod P, recepționarea provocării (challenge – engl.) c și transmiterea dovezii (proof – engl.) s = (r + c·x) mod Q către server. Serverul evaluează ulterior consistența ecuației de verificare G^s ≡ t · y^c (mod P), emite un jeton web securizat (JSON Web Token – engl., JWT) și elimină instanța de sesiune pentru a împiedica reutilizarea acesteia, asigurând totodată că accesul la resursele protejate returnează un cod de stare HTTP 200 în prezența unui jeton valid, respectiv un cod HTTP 401 în cazul absenței, expirării sau invalidității acestuia, fapt ce permite funcționarea paralelă și independentă a utilizatorilor multipli fără interferențe la nivelul stării.

Evaluarea comportamentului defensiv al protocolului a impus implementarea unor scenarii negative menite să confirme respingerea controlată a tentativelor de acces neautorizat sau de fraudă electronică. În situația introducerii unei parole incorecte, se constată că dovada calculată pe baza unei valori eronate nu satisface ecuația de validare, determinând serverul să returneze codul HTTP 401 și să distrugă sesiunea utilizată pentru a bloca atacurile repetitive pe același canal. De asemenea, tentativele de retransmitere (replay attack – engl.), bazate pe refolosirea unui identificator de sesiune (session ID – engl.) și a unei soluții deja procesate, determină generarea unui răspuns de tip HTTP 404 sau HTTP 401 ca urmare a eliminării imediate a stării după prima utilizare validă. Fenomenul de depășire a timpului de viață (time-to-live – engl., TTL), setat la o fereastră critică de 5 secunde între etapele de angajament și verificare, conduce la invalidarea automată a cererii cu un răspuns HTTP 401, în timp ce mecanismul de prevenire a deturnării (hijacking prevention – engl.), testat prin transmisii duble de tip angajament pentru același identificator, generează un cod de eroare HTTP 409 și anulează ambele sesiuni concurente pentru a bloca suprascrierea silențioasă, politică aplicată în mod similar și în cazul înregistrărilor duplicate.

Determinarea robusteții algoritmului la frontierele matematice ale grupului Schnorr și în prezența unor date de intrare neconforme a fost realizată prin testarea extinsă a cazurilor limită (corner cases – engl.), context în care s-a urmărit reacția sistemului la valori ale soluției situate în afara intervalului admis, acestea din urmă fiind respinse prin coduri HTTP 422. Pentru a preveni atacurile bazate pe subgrupuri mici (small subgroup attack – engl.), introducerea unor chei publice triviale aparținând setului {0, 1, −1, P−1} sau a unor angajamente nule la faza de inițiere determină respingerea imediată a solicitărilor fără generarea de sesiuni orfane. În condiții de concurență ridicată, simularea a zece fire de execuție (threads – engl.) simultane pentru același utilizator a demonstrat stabilitatea mecanismului de blocare prin excludere reciprocă (mutex lock – engl.), lăsând activă cel mult o sesiune validă, în timp ce introducerea unor tipuri de date malformate în câmpurile numerice, cum ar fi numere cu virgulă mobilă (float – engl.), notații științifice, șiruri de caractere (strings – engl.) sau valori nule (null – engl.), este interceptată prin coduri HTTP 400 sau 422, confirmându-se totodată robustețea antetului de autentificare (X- Auth-Session header – engl.).

Analiza proprietăților de securitate specifice schemei de identificare Schnorr a evidențiat rezistența protocolului în fața unor vectori de atac avansați, printre care se numără verificarea legării angajamentului (commitment binding – engl.). S-a demonstrat că un adversar capabil să construiască un istoric simulat valid, definit prin corelația t_sim = G^s · y^(−c) mod P fără cunoașterea prealabilă a valorii r, se află în imposibilitatea de a reutiliza acea dovadă falsificată împotriva unei sesiuni ancorate într-un angajament real diferit, serverul respingând prin HTTP 401 orice corelație neconformă cu starea stocată. În mod corelat, tentativele de forjare a soluției (solution forgery – engl.) în absența cheii private, fie prin transmiterea elementului aleatoriu brut, fie prin alterarea biților (bit-flip – engl.) sau introducerea de valori marginale extreme, au fost sistematic invalidate prin mecanismele de verificare a domeniului matematic, securitatea fiind completată de imposibilitatea deducerii prin încercări succesives (brute-force – engl.) a identificatorilor de sesiune și de izolarea riguroasă a contextelor de lucru aparținând unor utilizatori distincți (cross-user isolation – engl.).

În vederea stabilirii unei analize comparative, s-a procedat la integrarea și validarea funcțională a trei variante ale protocolului OAuth2, acoperind fluxul securizat cu cheie de dovadă pentru schimbul de coduri (Proof Key for Code Exchange – engl., PKCE, conform RFC 7636) bazat pe provocări criptografice de tip S256, varianta standardizată fără această extensie dedicată canalelor securizate de server, precum și o implementare echivalentă bazată pe biblioteca specializată Authlib (Authlib PKCE – engl.). Ca urmare a execuției acestei suite cuprinzătoare de asigurare a calității (Quality Assurance – engl., QA), s-a obținut o rată de succes de sută la sută, fiind promovate integral toate cele 56 de teste planificate, structurate în 5 teste pozitive, 5 teste negative, 30 de cazuri limită, 8 teste de securitate și 8 teste operaționale OAuth2. Promovarea integrală a acestui ansamblu experimental atestă faptul că implementarea acoperă exhaustiv traseul nominal și gestionează de o manieră robustă scenariile de eroare, oferind un fundament empiric solid pentru evaluarea comparativă a performanței și securității dintre arhitecturile bazate pe dovezi cu zero cunoștințe (Zero-Knowledge

III.3. 	Evaluarea performantei, benchmark si masuratori


Evaluarea latenței individuale a operațiilor criptografice fundamentale din cadrul protocolului s-a realizat prin intermediul platformei Flask Test Client. Prin această abordare metodologică, s-au eliminat penalitățile de rețea și timpii asociați serializării HTTP, obținându-se o măsurătoare precisă a efortului computațional brut. Valorile rezultate, reprezentând mediile calculate pe un eșantion de 100 de iterații, sunt sintetizate în tabelul următor:

| Operație Criptografică | Medie (ms) | Min (ms) | Max (ms) | P95 (ms) | StdDev (ms) |
| --- | --- | --- | --- | --- | --- |
| Calculul angajamentului: t = G^r mod P | 0,516 | 0,506 | 0,542 | 0,527 | 0,005 |
| Verificarea Schnorr: G^s ≡ t · y^c (mod P) | 1,121 | 1,113 | 1,148 | 1,138 | 0,006 |
| Challenge PKCE S256 (SHA-256) | 0,004 | 0,003 | 0,022 | 0,006 | 0,002 |
| Hash check OAuth2 Simple | 0,003 | 0,002 | 0,005 | 0,003 | 0,0004 |

Din analiza datelor, se observă că factorul de cost dominant în cadrul protocolului Zero-Knowledge Proof (ZKP) este reprezentat de operațiile de exponențiere modulară (respectiv G^r mod P, G^s mod P și y^c mod P). Latența totală alocată fazei de verificare a fost cuantificată la aproximativ 1,12 ms. Deși această valoare este cu cel puțin două ordine de mărime superioară latențelor specifice operațiilor de dispersie (hash) utilizate de metodele OAuth 2.0 clasice, ea se încadrează în limitele optime pentru garantarea unei experiențe de autentificare interactive fluide.

O analiză de granulație fină asupra operațiilor interne ale serverului a relevat costurile individuale de execuție la un nivel profund. S-a constatat că operația criptografică secundară dominantă este validarea apartenenței la subgrup (0,529 ms). Funcțiile auxiliare, precum derivarea parametrului de legare a sesiunii (Session Binding, 0,0023 ms) sau generarea provocării matematice (0,0007 ms), presupun eforturi computaționale neglijabile. Procesul final de emitere a jetonului JWT (0,0189 ms) reprezintă o fracțiune minimală din costul total de procesare.


În vederea determinării debitului maxim de procesare, s-a instrumentat un benchmark comparativ care a cuantificat numărul de fluxuri complete de autentificare executate pe secundă (RPS). Evaluarea s-a efectuat pentru dimensiuni variabile ale loturilor de utilizatori simulați secvențial, rezultatele fiind următoarele:

| Utilizatori Concurenți | ZKP (RPS) | OAuth2 PKCE (RPS) | OAuth2 Simple (RPS) | Authlib PKCE (RPS) |
| --- | --- | --- | --- | --- |
| 10 | 172,4 | 288,1 | 286,7 | 406,4 |
| 25 | 183,5 | 296,2 | 309,3 | 742,0 |
| 50 | 171,2 | 301,3 | 329,3 | 841,8 |
| 100 | 167,4 | 297,7 | 289,2 | 822,0 |

Protocolul ZKP manifestă un debit stabil de aproximativ 170 RPS, valoare care prezintă o reziliență notabilă la creșterea gradului de concurență. Această constanță este justificată de natura fixă a costului exponențierilor modulare executate pe grupul criptografic de 2048 biți. În contrast, metodele OAuth 2.0, fundamentate exclusiv pe derivări hash, înregistrează performanțe cantitative superioare (290–830 RPS). Raportul de performanță stabilit, de aproximativ 1:1,7 în favoarea metodelor clasice, constituie compromisul computațional necesar pentru asigurarea proprietăților de securitate zero-knowledge și eliminarea vulnerabilităților de transport ale credențialelor.

Din perspectiva managementului memoriei, evaluările au indicat o amprentă extrem de redusă a stării temporare gestionate de server. Valorile maxime de alocare a memoriei au variat între 180 KB și 223 KB, numărul de sesiuni active simultane în structura `_SessionStore` rămânând la o valoare unitară în timpul testelor controlate. Aceste date validează eficiența stocării efemere în memoria aplicației pentru un mediu prototipal, menționându-se necesitatea externalizării acestei stări într-o bază de date In-Memory (e.g., Redis) pentru eventuale implementări distribuite. Totodată, consumul general al resurselor hardware în condiții de trafic live s-a dovedit a fi optimizat, înregistrându-se un nivel mediu al memoriei RAM de aproximativ 65 MB și utilizări tranzitorii ale procesorului situate sub pragul de 4,70%.


Pentru a atesta practic fiabilitatea arhitecturii propuse, s-a efectuat un audit riguros al traficului HTTP, comparându-se conținutul pachetelor transmise în fiecare paradigmă de autentificare. Această procedură de testare are o valoare probatorie fundamentală pentru prezenta cercetare, confirmând următoarele aspecte de securitate:

În cadrul protocolului ZKP: Punctele terminale destinate autentificării (`POST /login/commit` și `POST /login/verify`) vehiculează exclusiv valori numerice efemere (angajamentul t și dovada matematică s). Se demonstrează lipsa oricărui derivat al parolei sau al secretului primar din mesajele interceptate.
În fluxul de autentificare clasic: Parola este expediată în format brut (plaintext) în corpul cererii de inițiere, fiind complet expusă oricărui adversar capabil să intercepteze canalul de transport nesecurizat.
În schemele OAuth 2.0 PKCE și Simple: Deși credențialele nu sunt propagate către serverul de resurse, ele sunt transmise obligatoriu în prima instanță către serverul de autorizare, vulnerabilitatea de la nivelul rețelei menținându-se nealterată.

Astfel, se atestă practic că schema criptografică Schnorr integrată reprezintă singura variantă operațională în care materialul secret nu traversează rețeaua. Prin urmare, capturarea integrală a unui schimb de mesaje ZKP nu oferă unui atacator nicio informație exploatabilă pentru o autentificare frauduloasă ulterioară sau pentru extragerea credențialelor.


Validarea finală a stabilității arhitecturale a constat într-un test dinamic de sarcină, orchestrat cu ajutorul utilitarului Locust. S-a simulat un trafic concurent generat de 50 de utilizatori simultani, desfășurat pe un interval de 30 de secunde. Analiza rezultatelor agregate a confirmat execuția cu succes a 717 cereri, fără înregistrarea niciunei erori de procesare, cu o rată medie agregată de 24,83 cereri pe secundă.

În acest scenariu, cu parametri care emulează o rețea reală, divergențele de latență între protocolul ZKP și fluxurile tradiționale s-au estompat semnificativ, timpii medii de răspuns situându-se în jurul valorii de 4100 ms pentru toate protocoalele testate. Această convergență demonstrează că diferențele strict criptografice sunt puternic atenuate de costurile asociate infrastructurii, de alocarea resurselor de rețea (traffic shaping) și de overhead-ul utilitarului de testare. În concluzie, s-a validat empiric capacitatea serverului de a susține cerințe de procesare în medii cu un grad ridicat de concurență, menținând în același timp un nivel de securitate net superior standardelor actuale..
III.4. 	Simularea atacurilor si analiza vulnerabilitatilor

Pentru evaluarea exhaustivă a robusteții arhitecturii propuse, a fost elaborată și executată o campanie experimentală axată pe simularea automată a principalilor vectori de atac cibernetic. În cadrul acestei metodologii de validare, s-a vizat în primul rând reziliența sistemului la compromiterea bazei de date (Data Breach). Astfel, s-a simulat un scenariu critic în care un adversar obține acces neautorizat la stocarea serverului, extrăgând cheia publică y = G^x mod P. S-a demonstrat matematic și practic imposibilitatea impersonării utilizatorului legitim pe baza exclusivă a acestei valori. O încercare de a construi o dovadă falsificată, utilizând cheia publică în locul scalarului secret, formulată prin s_attacker = (r + c y) mod Q, a condus inevitabil la eșecul validării G^s_attacker ≡ t · y^c (mod P). Această respingere a autentificării, materializată prin codul de eroare HTTP 401, este fundamentată pe inegalitatea y ≠ x în spațiul exponenților. Prin urmare, se confirmă faptul că sustragerea materialului criptografic public nu furnizează unui atacator capacitatea de generare a unor dovezi valide cu cunoștințe zero.

În completarea analizei de securitate, s-a evaluat calitatea sursei de entropie criptografică utilizată pentru generarea provocărilor și a identificatorilor de sesiune. Printr-o secvență de 10.000 de cereri de angajament (commit-uri) consecutive, s-a verificat distribuția statistică și absența coliziunilor. Toate valorile au fost confirmate ca fiind strict unice și corect încadrate în intervalul matematic specificat ([1, P-2]), validându-se astfel eficacitatea generatorului de numere pseudo-aleatoare securizat criptografic (CSPRNG) implementat în arhitectură. Această unicitate este critică pentru prevenirea atacurilor de tip Replay și pentru menținerea integrității fiecărei sesiuni de autorizare.

Pe de altă parte, o suprafață de atac vulnerabilă în cadrul protocoalelor bazate pe problema logaritmului discret este reprezentată de faza de distribuție a parametrilor publici. În acest sens, s-a simulat un atac de tip Man-in-the-Middle (MitM) bazat pe injectarea unor parametri slabi (precum P=23, Q=11 și G=4). S-a demonstrat că, prin acceptarea acestor parametri minimali, complexitatea problemei logaritmului discret colapsează, permițând rezolvarea acesteia prin forță brută în mai puțin de P-2 pași. În consecință, un adversar poate recupera cheia privată a victimei și poate finaliza cu succes fluxul protocolului în calitate de impostor. Această vulnerabilitate impune constrângerea arhitecturală ca aplicația client să ancoreze (pinning) valorile parametrilor de referință și să respingă în mod proactiv orice deviație detectată în rețea. Totodată, s-a validat faptul că implementarea serverului, atunci când rămâne strict atașată de parametrii originari de înaltă securitate și respinge valorile publice ce nu aparțin grupului legitim, neutralizează eficient o astfel de încercare de atac.

Pentru a demonstra fezabilitatea securității arhitecturii propuse pe termen lung, a fost realizat un test de performanță (benchmark) care evidențiază complexitatea inerentă a problemei logaritmului discret. Prin escaladarea progresivă a dimensiunii grupului criptografic, pornind de la instanțe triviale de 8 biți și urcând treptat către dimensiunile specificate de protocol, s-a reconfirmat creșterea exponențială a efortului de calcul. Prin fundamentarea sistemului pe un număr prim sigur (safe prime) de 2048 de biți și un subgrup operațional de aproximativ 1023 de biți, obținerea cheii private prin metode exhaustive devine computațional nefezabilă în ipotezele standard de complexitate algoritmică actuale.

În concluzie, rezultatele campaniei de testare automată consolidează garanțiile de securitate ale protocolului și evidențiază două principii critice de proiectare. În primul rând, delegarea exclusivă a cheilor publice către stocarea serverului atenuează în mod complet riscul de impersonare în cazul unei scurgeri de date. În al doilea rând, distribuția dinamică a parametrilor operaționali rămâne o componentă arhitecturală critică, ce necesită aplicarea unor mecanisme stricte de ancorare și validare matematică în vederea extinderii soluției către un mediu de producție matur..

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

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Concluzii
În Lucrarea a urmărit proiectarea, implementarea și evaluarea unui sistem de autentificare care combină schema Schnorr de identificare cu un model de autorizare bazat pe JWT și inspirat conceptual din ecosistemul OAuth 2.0. Rezultatul este un prototip coerent, funcțional și bine instrumentat, care demonstrează că autentificarea web poate fi realizată fără transmiterea parolei către server.
Din punct de vedere tehnic, proiectul oferă un flux complet de înregistrare, autentificare, emitere de token și acces la resurse protejate. În plus, include măsuri experimentale utile de întărire, precum validarea apartenenței la subgrup, legarea sesiunii la contextul HTTP, eliminarea sesiunii după consum, antete de securitate și validarea strictă a intrărilor. Suita principală de testare, alcătuită din 56 de teste, a fost promovată integral, iar simulările automate suplimentare de atac s-au încheiat de asemenea fără erori, ceea ce confirmă consistența funcțională și experimentală a implementării.
Rezultatele experimentale evidențiază clar compromisul fundamental al soluției. Pe de o parte, fluxul ZKP este mai costisitor decât alternativele OAuth2 clasice și necesită o logică operațională mai complexă. Pe de altă parte, el oferă un avantaj semnificativ prin faptul că transcrisul de trafic nu conține parola utilizatorului. Auditul conținutului traficului confirmă direct această diferență, iar acesta constituie argumentul central în favoarea protocolului propus.
În forma actuală, proiectul reprezintă un prototip de disertație solid, cu valoare demonstrativă și experimentală ridicată. El nu trebuie însă confundat cu o implementare finală de producție. Există limitări clare, precum derivarea simplificată a lui x în clientul web, distribuția neautentificată a parametrilor publici, sesiunile in-memory și secretul JWT hardcodat. Tocmai aceste limite îi conferă relevanță academică: ele permit discutarea onestă a diferenței dintre o demonstrație funcțională și o soluție matură.
Prin urmare, concluzia principală a lucrării este că autentificarea bazată pe dovezi de cunoaștere zero poate fi integrată eficient într-o arhitectură web modernă și poate reduce semnificativ expunerea credențialelor la interceptare, cu condiția ca implementarea să fie completată ulterior printr-o întărire riguroasă a distribuției parametrilor, a derivării secretelor și a infrastructurii operaționale..



Bibliografie

[1]	***, Python Programming Language, https://www.python.org, ultima accesare: 26/06/2024.
[2]	***, Flask Framework, https://flask.palletsprojects.com/en/3.0.x/, ultima accesare: 30/05/2026.
[3]	***, SQLite, https://www.sqlite.org/, ultima accesare: 30/05/2026.
[4]	***, JavaScript / ECMAScript Language Specification, https://ecma-international.org/publications-and-standards/standards/ecma-262/, ultima accesare: 30/05/2026.
[5]	***, Npm, https://www.npmjs.com/, ultima accesare: 30/05/2026.
[6]	D. Hardt, "The OAuth 2.0 Authorization Framework", RFC 6749, Internet Engineering Task Force, oct. 2012, https://datatracker.ietf.org/doc/html/rfc6749.
[7]	***, OAuth 2.0, https://oauth.net/2/, ultima accesare: 30/05/2026.
[8]	***, OAuth, https://oauth.net/, ultima accesare: 30/05/2026.
[9]	D. Hardt et al., "The OAuth 2.1 Authorization Framework (Draft)", Internet Engineering Task Force, https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1, ultima accesare: 30/05/2026.
[10]	S. Li, "A Study on the Applicability of OAuth in the E-Commerce Environment", IEEE International Conference on Service Sciences, 2013, doi: 10.1109/ICSS.2013.24, https://ieeexplore.ieee.org/abstract/document/6625487.
[11]	V. S. P. Farag, "An Analysis of the OAuth 2.0 Standard", IEEE Symposium on Security and Privacy Workshops, 2011, https://ieeexplore.ieee.org/abstract/document/6123701.
[12]	S. Goldwasser, S. Micali, C. Rackoff, "The Knowledge Complexity of Interactive Proof Systems", SIAM Journal on Computing, vol. 18, nr. 1, pp. 186-208, 1989, doi: 10.1137/0218012, https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Proof%20Systems/The_Knowledge_Complexity_Of_Interactive_Proof_Systems.pdf.
[13]	M. A. Ferrag, S. Manoj, "Overview and Applications of Zero Knowledge Proof (ZKP)", Academia, 2020, https://www.academia.edu/43094897/Overview_and_Applications_of_Zero_Knowledge_Proof_ZKP.
[14]	E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev, "Scalable, Transparent, and Post-Quantum Secure Computational Integrity (ZK-STARKs)", Cryptology ePrint Archive, Report 2018/046, https://eprint.iacr.org/2018/46.
[15]	A. Sakala et al., "zkAt: A Zero-Knowledge Authentication Primitive", Cryptology ePrint Archive, Report 2025/921, https://eprint.iacr.org/2025/921.
[16]	A. Amro, T. T. Nguyen, "Blockchain Authentication Scheme Using zk-SNARK Zero-Knowledge Proofs", Electronics, vol. 13, nr. 14, art. 2730, 2024, https://www.mdpi.com/2079-9292/13/14/2730.
[17]	M. Boubakri et al., "Integrating Zero-Knowledge Proofs with OAuth 2.0 for Multi-Agent Systems", E3S Web of Conferences, vol. 469, 2023, https://www.e3s-conferences.org/articles/e3sconf/abs/2023/106/e3sconf_icegc2023_00085/e3sconf_icegc2023_00085.html.
[18]	D. Terpstra, "Token-Based Authentication and Authorization Using Zero-Knowledge Proofs for Web API Security", Master's Thesis, Dakota State University, 2023, https://scholar.dsu.edu/theses/425/.
[19]	C. P. Schnorr, "Efficient Signature Generation by Smart Cards", Journal of Cryptology, vol. 4, nr. 3, pp. 161-174, 1991, doi: 10.1007/BF00196725, https://link.springer.com/article/10.1007/bf00196725.
[20]	A. J. Menezes, P. C. van Oorschot, S. A. Vanstone, "Handbook of Applied Cryptography", CRC Press, 1996, https://cacr.uwaterloo.ca/hac/.
[21]	J. Katz, Y. Lindell, "Introduction to Modern Cryptography", ed. 2, CRC Press, 2014.
[22]	F. Hao, "Schnorr Non-interactive Zero-Knowledge Proof", RFC 8235, Internet Engineering Task Force, sept. 2017, https://www.rfc-editor.org/rfc/rfc8235.html.
[23]	***, zkDocs: Schnorr Zero-Knowledge Protocol, https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/, ultima accesare: 30/05/2026.
[24]	***, zkp-hmac-communication-js: JavaScript implementation of a Schnorr-style ZKP protocol combined with HMAC, https://github.com/zk-Call/zkp-hmac-communication-js, ultima accesare: 30/05/2026.
[25]	***, Schnorr Signature, Wikipedia, https://en.wikipedia.org/wiki/Schnorr_signature, ultima accesare: 30/05/2026.
[26]	D. Boneh, "Applied Cryptography: Schnorr Identification Protocol", Stanford CS355, Lecture 5, 2019, https://crypto.stanford.edu/cs355/19sp/lec5.pdf.
[27]	M. Jones, J. Bradley, N. Sakimura, "JSON Web Token (JWT)", RFC 7519, Internet Engineering Task Force, mai 2015, https://datatracker.ietf.org/doc/html/rfc7519.
[28]	S. Sakimura, J. Bradley, N. Agarwal, "Proof Key for Code Exchange by OAuth Public Clients (PKCE)", RFC 7636, Internet Engineering Task Force, sept. 2015, https://datatracker.ietf.org/doc/html/rfc7636.
[29]	***, Flask-CORS, https://flask-cors.readthedocs.io/, ultima accesare: 30/05/2026.
[30]	***, Flask-SQLAlchemy, https://flask-sqlalchemy.palletsprojects.com/, ultima accesare: 30/05/2026.
[31]	***, PyJWT, https://pyjwt.readthedocs.io/en/stable/, ultima accesare: 30/05/2026.
[32]	***, Authlib, https://authlib.org/, ultima accesare: 30/05/2026.
[33]	***, pytest, https://docs.pytest.org/, ultima accesare: 30/05/2026.
[34]	***, Locust, https://locust.io/, ultima accesare: 30/05/2026.
[35]	***, cryptography (Python library), https://cryptography.io/en/latest/, ultima accesare: 30/05/2026.
[36]	***, SymPy, https://www.sympy.org/, ultima accesare: 30/05/2026.
[37]	R. Fielding, J. Reschke, "Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content", RFC 7231, Internet Engineering Task Force, iun. 2014, https://datatracker.ietf.org/doc/html/rfc7231.
[38]	***, OWASP Secure Headers Project, https://owasp.org/www-project-secure-headers/, ultima accesare: 30/05/2026.
[39]	D. Crocker, P. Overell, "Augmented BNF for Syntax Specifications: ABNF", RFC 5234, Internet Engineering Task Force, ian. 2008, https://datatracker.ietf.org/doc/html/rfc5234.
[40]	***, OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet, https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html, ultima accesare: 30/05/2026.
[41]	D. Wong, "Real-World Cryptography", Manning Publications, 2021, cap. 12.
[42]	***, MDN Web Docs: Cache-Control, https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control, ultima accesare: 30/05/2026.
[43]	***, MDN Web Docs: Crypto.getRandomValues(), https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues, ultima accesare: 30/05/2026.
[44]	C. Percival, S. Josefsson, "The scrypt Password-Based Key Derivation Function", RFC 7914, Internet Engineering Task Force, aug. 2016, https://datatracker.ietf.org/doc/html/rfc7914.
[45]	W. Diffie, M. Hellman, "New Directions in Cryptography", IEEE Transactions on Information Theory, vol. 22, nr. 6, pp. 644-654, nov. 1976, doi: 10.1109/TIT.1976.1055638.
[46]	E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, Internet Engineering Task Force, aug. 2018, https://www.rfc-editor.org/rfc/rfc8446.
[47]	R. P. Fernandez et al., "Post-Quantum Threats to TLS: A Survey", Cryptography, vol. 9, nr. 4, art. 73, 2025, https://www.mdpi.com/2410-387X/9/4/73.
[48]	A. Papachristodoulou et al., "TLS 1.3 Traffic Analysis: Challenges and Insufficiencies", Electronics, vol. 13, nr. 20, art. 4000, 2024, https://www.mdpi.com/2079-9292/13/20/4000.
[49]	***, What the Post-Quantum Shift Means for Your Security Strategy, TechRadar, https://www.techradar.com/pro/what-the-post-quantum-shift-means-for-your-security-strategy, ultima accesare: 30/05/2026.
[50]	D. J. Bernstein, T. Lange, "Post-Quantum Cryptography", Cryptology ePrint Archive, Report 2015/1075, 2015, https://eprint.iacr.org/2015/1075.pdf.
[51]	***, OWASP Testing Guide: Session Management, https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/, ultima accesare: 30/05/2026.
[52]	C. Allen, "The Path to Self-Sovereign Identity", 2016, http://www.lifewithalacrity.com/2016/04/the-path-to-self-soverereign-identity.html.
[53]	***, Nostr Community Group: HTTP Schnorr Authentication Draft, https://nostrcg.github.io/http-schnorr-auth, ultima accesare: 30/05/2026.
[54]	P. Kumar, "Efficacy of Schnorr Signature for Stateless Authentication", Medium, https://medium.com/%40prathyusha756/efficacy-of-schnorr-signature-for-stateless-authentication-5ae5d65ec5d3, ultima accesare: 30/05/2026.
[55]	T. Wu, "The Secure Remote Password Protocol (SRP)", RFC 5054, Internet Engineering Task Force, nov. 2007, https://datatracker.ietf.org/doc/html/rfc5054.
[56]	***, PAKE: Password Authenticated Key Exchange, https://asecuritysite.com/pake, ultima accesare: 30/05/2026.
[57]	***, Password Authenticated Key Exchange by Juggling (J-PAKE), Wikipedia, https://en.wikipedia.org/wiki/Password_Authenticated_Key_Exchange_by_Juggling, ultima accesare: 30/05/2026.
[58]	***, SRP: A Zero-Knowledge Protocol for Password Authentication, Medium, https://medium.com/@mainnetready/srp-a-zero-knowledge-protocol-for-password-authentication-1e19582aab29, ultima accesare: 30/05/2026.
[59]	V. Shah et al., "Survey on Zero-Knowledge Proof Authentication Protocols", arXiv:2401.11735, 2024, https://arxiv.org/abs/2401.11735.
[60]	***, Zero Knowledge Authentication, Sedicii, https://sedicii.com/news/zero-knowledge-authentication/, ultima accesare: 30/05/2026.
[61]	***, Meta Engineering Blog: Post-Quantum Readiness for TLS, https://engineering.fb.com/2024/05/22/security/post-quantum-readiness-tls-pqr-meta/, ultima accesare: 30/05/2026.
[62]	***, Cloudflare Blog: A Primer on Lattice Cryptography, https://blog.cloudflare.com/lattice-crypto-primer/, ultima accesare: 30/05/2026.
[63]	A. Z. Vyas et al., "Side-Channel Vulnerabilities of Post-Quantum Cryptographic Algorithms", DIVA Portal, 2023, https://www.diva-portal.org/smash/get/diva2%3A1742628/FULLTEXT01.pdf.
[64]	F. Deng et al., "Real-World Implementation Weaknesses and Attack Risks in TLS", Computers and Security, 2025, https://www.sciencedirect.com/science/article/abs/pii/S1574013725000140.




-------------------------------------------------------------------


Anexe
Anexa 1. 	Schema arhitecturii

A1. este schema arhitecturală a aplicației, iar elementele acesteia sunt după cum urmează:
●	Dreptunghiurile mari, fără colturi rotunjite sunt nivelele arhitecturii.
●	Dreptunghiurile mici a căror colturi sunt rotunjite reprezintă module ce îndeplinesc un scop.
●	Săgețile reprezintă comunicarea între doua componente.
●	Obiectul notat cu „SQLite DB” este o baza de date.

A.1. Arhitectura aplicației.
 

Anexa 2. 	Secvențe din Python
