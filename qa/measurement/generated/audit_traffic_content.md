# Audit Trafic: ZKP vs OAuth2 PKCE vs OAuth2 Simple vs Authlib PKCE

## POST /login/commit (ZKP Step 1)
```json
{'client_id': 'audit_traffic_user', 'commitment_t': '973326440169834481015295460957432679024327201642072458256116...'}
```

## POST /login/verify (ZKP Step 2)
```json
{'solution_s': '413986039251808339438229491184684649399893527342186947745704...'}
```

## POST /classic/login (Autentificare Clasica)
```json
{'client_id': 'audit_traffic_user', 'password': 'audit-secret'}
```
Nota: parola este trimisa in clar catre server.

## POST /oauth/pkce/authorize (OAuth2 PKCE Step 1)
```json
{'response_type': 'code', 'client_id': 'acas-pkce-client', 'username': 'audit_traffic_user', 'password': 'audit-secret', 'code_challenge': '9us7W2TQdKRITRqdzOcq4ytNqo8MJjefUzW-CQhhHXM', 'code_challenge_method': 'S256'}
```
Nota: parola este trimisa catre authorization server (acelasi domeniu), nu catre client.

## POST /oauth/pkce/token (OAuth2 PKCE Step 2 – code exchange)
```json
{'grant_type': 'authorization_code', 'client_id': 'acas-pkce-client', 'code': '<opaque-auth-code>', 'code_verifier': 'QIFNVlrjNBMyoTiU-519qzbRprdFOayETbTEXMqvf262TkV8jx7PQotgrVZA...'}
```
Nota: code_verifier este un secret de scurta durata, parola nu mai apare in aceasta cerere.

## POST /oauth/simple/authorize (OAuth2 Simple Step 1)
```json
{'response_type': 'code', 'client_id': 'acas-simple-client', 'username': 'audit_traffic_user', 'password': 'audit-secret'}
```
Nota: parola este trimisa catre authorization server, fara PKCE.

## POST /oauth/simple/token (OAuth2 Simple Step 2)
```json
{'grant_type': 'authorization_code', 'client_id': 'acas-simple-client', 'code': '<opaque-auth-code>'}
```

## POST /authlib/oauth/authorize (Authlib PKCE Step 1 – form-encoded)
```
{'response_type': 'code', 'client_id': 'acas-authlib-client', 'username': 'audit_traffic_user', 'password': 'audit-secret', 'code_challenge': '9us7W2TQdKRITRqdzOcq4ytNqo8MJjefUzW-CQhhHXM', 'code_challenge_method': 'S256'}
```
Nota: echivalent cu OAuth2 PKCE dar folosind biblioteca Authlib, parametri form-encoded.

## POST /authlib/oauth/token (Authlib PKCE Step 2 – form-encoded)
```
{'grant_type': 'authorization_code', 'client_id': 'acas-authlib-client', 'code': '<opaque-auth-code>', 'code_verifier': 'QIFNVlrjNBMyoTiU-519qzbRprdFOayETbTEXMqvf262TkV8jx7PQotgrVZA...'}
```
