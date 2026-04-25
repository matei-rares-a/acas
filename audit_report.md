# Audit trafic - ZKP vs OAuth2

## /login/commit payload (ZKP)
`{'client_id': 'audit_user', 'commitment_t': '8670324857199079353167008875200985277924896686008719238442870109743238203302188241586767425823690822851848930787508777336192842805379889471286837919873951'}`
Hits interzise: niciunul (PASS)

## /login/verify payload (ZKP)
`{'solution_s': '2305108284010460813143021626249812624878476605184775099321879366965900852080180314966493291768252422917671759974950832462330149129340881263947787636886355'}`
Hits interzise: niciunul (PASS)

## /oauth/pkce/authorize payload (OAuth2 PKCE - comparatie)
`{'response_type': 'code', 'client_id': 'acas-pkce-client', 'redirect_uri': 'https://client.example/callback', 'username': 'audit_user', 'password': 'audit-password', 'scope': 'openid profile', 'code_challenge': 'pRtMje1NCooBqP7o1E5Ok_MvSTwO2lvbKttDa9y4auo', 'code_challenge_method': 'S256'}`
Hits interzise: ['password']
Nota: parola este trimisa catre authorization server (acelasi domeniu), nu catre client.
Securitatea depinde de confidentialitatea canalului HTTPS, nu de zero-knowledge.

## /oauth/pkce/token payload (OAuth2 PKCE - code exchange)
`{'grant_type': 'authorization_code', 'client_id': 'acas-pkce-client', 'redirect_uri': 'https://client.example/callback', 'code': '<opaque-auth-code>', 'code_verifier': 'i9nBjNTLGhZhE3KjSdwWjRPN37wTqO_JtExtN__n95yyLp4I_WzeU3IO_3u9vRiE'}`
Hits interzise: niciunul (PASS)
Nota: code_verifier este un secret de scurta durata, parola nu mai apare in aceasta cerere.