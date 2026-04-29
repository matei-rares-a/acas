# Audit Trafic: ZKP vs OAuth2 PKCE vs OAuth2 Simple vs Authlib PKCE

## POST /login/commit (ZKP Step 1)
```json
{'client_id': 'audit_traffic_user', 'commitment_t': '160855915213375910180590180588964462351793079122868697616157...'}
```

## POST /login/verify (ZKP Step 2)
```json
{'solution_s': '175575443075392262733766681167841216802903907734336980098705...'}
```

## POST /classic/login (Autentificare Clasica)
```json
{'client_id': 'audit_traffic_user', 'password': 'audit-secret'}
```
Nota: parola este trimisa in clar catre server.

## POST /oauth/pkce/authorize (OAuth2 PKCE Step 1)
```json
{'response_type': 'code', 'client_id': 'acas-pkce-client', 'username': 'audit_traffic_user', 'password': 'audit-secret', 'code_challenge': '3gCYhbjFnuH0Mq9RFhOQwTgzVGaqOrpxERTrrs__HMc', 'code_challenge_method': 'S256'}
```
Nota: parola este trimisa catre authorization server (acelasi domeniu), nu catre client.

## POST /oauth/pkce/token (OAuth2 PKCE Step 2 – code exchange)
```json
{'grant_type': 'authorization_code', 'client_id': 'acas-pkce-client', 'code': '<opaque-auth-code>', 'code_verifier': 'v7nKdRARBEHvGBJWFzL5tCf-ld2uUPZG63EREKV7pmKmwolk5TzctEdw435I...'}
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
{'response_type': 'code', 'client_id': 'acas-authlib-client', 'username': 'audit_traffic_user', 'password': 'audit-secret', 'code_challenge': '3gCYhbjFnuH0Mq9RFhOQwTgzVGaqOrpxERTrrs__HMc', 'code_challenge_method': 'S256'}
```
Nota: echivalent cu OAuth2 PKCE dar folosind biblioteca Authlib, parametri form-encoded.

## POST /authlib/oauth/token (Authlib PKCE Step 2 – form-encoded)
```
{'grant_type': 'authorization_code', 'client_id': 'acas-authlib-client', 'code': '<opaque-auth-code>', 'code_verifier': 'v7nKdRARBEHvGBJWFzL5tCf-ld2uUPZG63EREKV7pmKmwolk5TzctEdw435I...'}
```
