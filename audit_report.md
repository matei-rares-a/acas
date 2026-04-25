# Audit trafic - ZKP vs OAuth2

## /login/commit payload (ZKP)
`{'client_id': 'audit_user', 'commitment_t': '10449306645378618835785301172286428436868814191817595942003005793818407936827233912041922512508542004494322946404594866297346873899796651667541900449896505'}`
Hits interzise: niciunul (PASS)

## /login/verify payload (ZKP)
`{'solution_s': '1340397421761622612945843717390560500074401185998866907430969957030747238062767530400685496799373172716155529018948032062623337823255721300664296095429812'}`
Hits interzise: niciunul (PASS)

## /oauth/pkce/authorize payload (OAuth2 PKCE - comparatie)
`{'response_type': 'code', 'client_id': 'acas-pkce-client', 'redirect_uri': 'https://client.example/callback', 'username': 'audit_user', 'password': 'audit-password', 'scope': 'openid profile', 'code_challenge': 'UbCmBcRIZzTKd5cI1zKwko9c8bTbkV-6BHCyaWQYLlw', 'code_challenge_method': 'S256'}`
Hits interzise: ['password']
Nota: parola este trimisa catre authorization server (acelasi domeniu), nu catre client.
Securitatea depinde de confidentialitatea canalului HTTPS, nu de zero-knowledge.

## /oauth/pkce/token payload (OAuth2 PKCE - code exchange)
`{'grant_type': 'authorization_code', 'client_id': 'acas-pkce-client', 'redirect_uri': 'https://client.example/callback', 'code': '<opaque-auth-code>', 'code_verifier': 'Nzb7qdXUdokPPaTE242ajlSoeDp5B_PuQAN71Vu8doos9EKu5U9sKTEzaLP1i926'}`
Hits interzise: niciunul (PASS)
Nota: code_verifier este un secret de scurta durata, parola nu mai apare in aceasta cerere.