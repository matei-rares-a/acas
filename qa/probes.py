'''
Pentru a transforma recomandările de livrabile în rezultate concrete pentru lucrarea de disertație, poți folosi următoarele prompturi pentru agentul tău AI. Acestea sunt concepute să genereze scripturi care colectează datele, extrag codul relevant și pregătesc materialul vizual.

Iată prompturile structurate pe cele trei categorii:

1. Tabele de Latență (Automatizarea colectării datelor)
Acest prompt va genera un script care rulează testele și produce direct tabelul Markdown pentru lucrare.
"Acționează ca un Data Analyst. Scrie un script Python de benchmarking (generate_latency_table.py) care să:
Ruleze 100 de iterații ale fluxului complet de autentificare ZKP (Commitment -> Challenge -> Proof).
Folosească time.perf_counter_ns() pentru a măsura cu precizie de nanosecunde:
Timpul de execuție pe server pentru /login/commit (generare challenge).
Timpul de execuție pe server pentru /login/verify (verificare matematică).
Timpul total de 'Round Trip' de la client.
Calculeze pentru fiecare etapă: Media (Mean), Minimul, Maximul și Deviația Standard.
Output-ul scriptului trebuie să fie un tabel formatat în Markdown gata de pus în disertație, cu valorile convertite în milisecunde (ms)."

2. Capturi de Trafic (Demonstrarea absenței parolei)
Deoarece agentul nu poate rula Wireshark, el poate genera un script care "simulează" ce ar vedea un atacator (sniffing la nivel de aplicație) pentru a pune în oglindă datele.
"Scrie un script de test (audit_traffic_content.py) care să intercepteze și să logheze conținutul brut (raw) al pachetelor JSON trimise între client și server în timpul procesului de login.
Scriptul trebuie să simuleze un 'Man-in-the-Middle' care citește corpul request-urilor către /login/commit și /login/verify.
Output-ul trebuie să fie un fișier text care arată exact ce date circulă (ex: client_id, commitment_t, solution_s).
Adaugă o funcție de scanare care să caute cuvinte cheie precum 'password', 'parola', 'x' (cheia privată) în payload-uri și să confirme (print) că acestea lipsesc.
Generează un fișier audit_report.md care să compare un request clasic (unde parola e vizibilă) cu request-ul ZKP Schnorr, evidențiind avantajul de securitate."

3. Fragmente de Cod Logice (Extragerea automată a mecanismelor de apărare)
Acest prompt ajută la documentarea tehnică prin extragerea automată a "inimii" securității din codul tău.
"Scrie un script de documentare care să scaneze fișierul server.py și să extragă următoarele 'Security Snippets' într-un format pregătit pentru LaTeX sau Markdown:
Mecanismul de validare a subgrupului: Funcția is_subgroup_member și locul unde este apelată în rute.
Mecanismul de unicitate a sesiunii: Logica de ștergere a sesiunii (del sessions[session_id]) imediat după utilizare sau la eroare.
Mecanismul de rezistență la Replay: Generarea challenge_c folosind secrets.randbelow.
Pentru fiecare fragment extras, adaugă automat un comentariu explicativ (în limba română) care să descrie ce atac specific previne acel cod (ex: prevenirea atacurilor de tip small subgroup, prevenirea replay attacks)."

4. Generarea de Grafice Profesionale (Vizualizarea rezultatelor)
Pentru a aduce valoare vizuală, cere-i agentului să scrie scriptul de vizualizare a datelor colectate la punctul 1.
"Folosind datele de latență generate anterior, scrie un script Python cu matplotlib sau seaborn care să genereze două grafice pentru capitolul 6:
Box Plot: Pentru a arăta distribuția latenței la /login/verify. Trebuie să evidențieze că majoritatea timpului este consumat de exponențierea modulară, dar că valorile sunt stabile.
Histogramă: Care să compare timpul de răspuns al fluxului ZKP cu timpul de răspuns al fluxului OAuth clasic (bazat pe datele colectate anterior).
Configurează graficele să aibă titluri, legende și axe explicate în limba română, cu un stil vizual 'academic' (grilă discretă, fonturi lizibile)."
'''