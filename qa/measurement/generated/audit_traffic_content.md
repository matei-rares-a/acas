# Audit Trafic: ZKP vs OAuth2 PKCE vs OAuth2 Simple vs Authlib PKCE

## POST /login/commit (ZKP Step 1)
```json
{'client_id': 'audit_traffic_user', 'commitment_t': '117032539225729478656309239777159986493783239881194295205901...'}
```

## POST /login/verify (ZKP Step 2)
```json
{'solution_s': '237859736564415088408754490843798305709313740397176971056399...'}
```

## POST /classic/login (Autentificare Clasica)
```json
{'client_id': 'audit_traffic_user', 'password': 'audit-secret'}
```
Nota: parola este trimisa in clar catre server.

## GET /oauth/pkce/authorize (OAuth2 PKCE Step 1a - browser initiates)
```
{'response_type': 'code', 'client_id': 'acas-pkce-client', 'redirect_uri': '<redirect_uri>', 'scope': 'openid profile', 'code_challenge': 'P35lGrIQd9a2Iu62wl635N2siOI-4k2WpHxYCyS6RTk', 'code_challenge_method': 'S256'}
```
Nota: browser-ul (client app) trimite parametrii OAuth in query string; parola nu apare.

## POST /oauth/pkce/authorize (OAuth2 PKCE Step 1b - user submits credentials)
```
{'auth_request_id': '<opaque-one-time-token>', 'username': 'audit_traffic_user', 'password': '<hidden-by-browser-form>'}
```
Nota: parola este trimisa direct catre Authorization Server (nu trece prin client app).

## POST /oauth/pkce/token (OAuth2 PKCE Step 2 - code exchange)
```json
{'grant_type': 'authorization_code', 'client_id': 'acas-pkce-client', 'code': '<opaque-auth-code>', 'code_verifier': 'wO1JXWe-Ci5Sf2nXHzJ41dnUIybtQNF-Ue08GpjjDOMmqT0uvy7VJA93dAjH...'}
```
Nota: code_verifier este un secret de scurta durata, parola nu mai apare in aceasta cerere.

## GET /oauth/simple/authorize (OAuth2 Simple Step 1a - browser initiates)
```
{'response_type': 'code', 'client_id': 'acas-simple-client', 'redirect_uri': '<redirect_uri>', 'scope': 'openid profile'}
```
Nota: browser-ul trimite parametrii OAuth in query string, fara PKCE.

## POST /oauth/simple/authorize (OAuth2 Simple Step 1b - user submits credentials)
```
{'auth_request_id': '<opaque-one-time-token>', 'username': 'audit_traffic_user', 'password': '<hidden-by-browser-form>'}
```
Nota: parola este trimisa direct catre Authorization Server.

## POST /oauth/simple/token (OAuth2 Simple Step 2)
```json
{'grant_type': 'authorization_code', 'client_id': 'acas-simple-client', 'code': '<opaque-auth-code>'}
```

## POST /authlib/oauth/authorize (Authlib PKCE Step 1 - form-encoded)
```
{'response_type': 'code', 'client_id': 'acas-authlib-client', 'username': 'audit_traffic_user', 'password': 'audit-secret', 'code_challenge': 'P35lGrIQd9a2Iu62wl635N2siOI-4k2WpHxYCyS6RTk', 'code_challenge_method': 'S256'}
```
Nota: echivalent cu OAuth2 PKCE dar folosind biblioteca Authlib, parametri form-encoded.

## POST /authlib/oauth/token (Authlib PKCE Step 2 - form-encoded)
```
{'grant_type': 'authorization_code', 'client_id': 'acas-authlib-client', 'code': '<opaque-auth-code>', 'code_verifier': 'wO1JXWe-Ci5Sf2nXHzJ41dnUIybtQNF-Ue08GpjjDOMmqT0uvy7VJA93dAjH...'}
```
