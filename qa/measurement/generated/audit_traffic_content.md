# Audit Trafic: ZKP vs OAuth2 PKCE vs OAuth2 Simple vs Authlib PKCE

## POST /login/commit (ZKP Step 1)
```json
{'client_id': 'audit_traffic_user', 'commitment_t': '603173959978855029429248483780620869489581253628514797162897...'}
```

## POST /login/verify (ZKP Step 2)
```json
{'solution_s': '335686855401156123561564023328522861013871348623468771917174...'}
```

## POST /classic/login (Autentificare Clasica)
```json
{'client_id': 'audit_traffic_user', 'password': 'audit-secret'}
```
Nota: parola este trimisa in clar catre server.

## GET /oauth/pkce/authorize (OAuth2 PKCE Step 1a - browser initiates)
```
{'response_type': 'code', 'client_id': 'acas-pkce-client', 'redirect_uri': '<redirect_uri>', 'scope': 'openid profile', 'code_challenge': 'gT3Lklugel098P7G15xjqRBQRYQKtZHi_JUu7krAUEc', 'code_challenge_method': 'S256'}
```
Nota: browser-ul (client app) trimite parametrii OAuth in query string; parola nu apare.

## POST /oauth/pkce/authorize (OAuth2 PKCE Step 1b - user submits credentials)
```
{'auth_request_id': '<opaque-one-time-token>', 'username': 'audit_traffic_user', 'password': '<hidden-by-browser-form>'}
```
Nota: parola este trimisa direct catre Authorization Server (nu trece prin client app).

## POST /oauth/pkce/token (OAuth2 PKCE Step 2 - code exchange)
```json
{'grant_type': 'authorization_code', 'client_id': 'acas-pkce-client', 'code': '<opaque-auth-code>', 'code_verifier': 'n_S9OqrZQqtfFKzBSSqFOCcQkGoSer10poOfhYWA36zL1dOCAwHVTHKjD0da...'}
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
{'response_type': 'code', 'client_id': 'acas-authlib-client', 'username': 'audit_traffic_user', 'password': 'audit-secret', 'code_challenge': 'gT3Lklugel098P7G15xjqRBQRYQKtZHi_JUu7krAUEc', 'code_challenge_method': 'S256'}
```
Nota: echivalent cu OAuth2 PKCE dar folosind biblioteca Authlib, parametri form-encoded.

## POST /authlib/oauth/token (Authlib PKCE Step 2 - form-encoded)
```
{'grant_type': 'authorization_code', 'client_id': 'acas-authlib-client', 'code': '<opaque-auth-code>', 'code_verifier': 'n_S9OqrZQqtfFKzBSSqFOCcQkGoSer10poOfhYWA36zL1dOCAwHVTHKjD0da...'}
```
