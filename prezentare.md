
titlu
cuprins



 + diagrame de comparatie intre protocoale ZKP si OAuth 2.0

II.1.4. 	Comparatie intre protocoale ZKP si OAuth 2.0 todo
Diagramă care să arate unde se încadrează Schnorr în fluxul OAuth 2.0 (înlocuind client_secret cu ZKP Proof). 
 Etapa 	  Metoda HTTP 	Parametri Cheie 	Rol în OAuth 
Commitment 	POST /login/commit 	client_id, t = g^r 	Inițiere Grant 
Challenge 	Response 	c (random challenge) 	Nonce de sesiune 
Proof 	POST /login/verify 	s = r + cx 	Client Authentication 
Token Issue 	Response 	access_token (JWT) 	Access Grant 


rezultate și concluzii


va multumesc