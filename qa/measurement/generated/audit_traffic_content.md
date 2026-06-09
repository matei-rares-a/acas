# Audit Trafic: ZKP vs OAuth2 PKCE vs OAuth2 Simple vs Authlib PKCE

## POST /login/commit (ZKP Step 1)
```json
{'client_id': 'audit_traffic_user', 'commitment_t_x': '784983363160419062494799289566665217528500908380955596904354...', 'commitment_t_y': '905972828960625440980669028196117825665445716191406656752003...'}
```

## POST /login/verify (ZKP Step 2)
```json
{'solution_s': '302844247777853772114904094366709777327093731105142459314937...'}
```

## POST /classic/login (Autentificare Clasica)
```json
{'client_id': 'audit_traffic_user', 'password': 'audit-secret'}
```
Nota: parola este trimisa in clar catre server.

## GET /oauth/pkce/authorize (OAuth2 PKCE Step 1a - browser initiates)
```
{'response_type': 'code', 'client_id': 'acas-pkce-client', 'redirect_uri': '<redirect_uri>', 'scope': 'openid profile', 'code_challenge': 'gtIMQafw0Z8vEuVyTgFipT4uKqJNisv0Qs3j7GjNpg0', 'code_challenge_method': 'S256'}
```
Nota: browser-ul (client app) trimite parametrii OAuth in query string; parola nu apare.

## POST /oauth/pkce/authorize (OAuth2 PKCE Step 1b - user submits credentials)
```
{'auth_request_id': '<opaque-one-time-token>', 'username': 'audit_traffic_user', 'password': '<hidden-by-browser-form>'}
```
Nota: parola este trimisa direct catre Authorization Server (nu trece prin client app).

## POST /oauth/pkce/token (OAuth2 PKCE Step 2 - code exchange)
```json
{'grant_type': 'authorization_code', 'client_id': 'acas-pkce-client', 'code': '<opaque-auth-code>', 'code_verifier': 'XbA8co8yYpKl_9DX8_BHcBK0zm1oATh9MUtO7syjZzZusiDlaa4CjaBm_oSp...'}
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
{'response_type': 'code', 'client_id': 'acas-authlib-client', 'username': 'audit_traffic_user', 'password': 'audit-secret', 'code_challenge': 'gtIMQafw0Z8vEuVyTgFipT4uKqJNisv0Qs3j7GjNpg0', 'code_challenge_method': 'S256'}
```
Nota: echivalent cu OAuth2 PKCE dar folosind biblioteca Authlib, parametri form-encoded.

## POST /authlib/oauth/token (Authlib PKCE Step 2 - form-encoded)
```
{'grant_type': 'authorization_code', 'client_id': 'acas-authlib-client', 'code': '<opaque-auth-code>', 'code_verifier': 'XbA8co8yYpKl_9DX8_BHcBK0zm1oATh9MUtO7syjZzZusiDlaa4CjaBm_oSp...'}
```
