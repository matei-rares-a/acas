# acas

OAuth-style API key authentication using the ZKP (zero-knowledge proof) protocol.


## Project Structure

- `server_app/` — Flask authentication server: routes, models, OAuth2 handlers, SQLite database.
- `client_app/` — HTML/JavaScript browser client: registration, login, shared ZKP helpers, and a real-time network monitor panel.
- `qa/` — All QA work: functional tests, benchmarks, load tests, measurement probes, and manual security audits. See [`qa/QA.md`](qa/QA.md).
- `diagrams/` — Architecture and protocol diagrams (Mermaid source files).
- `calculations.py` — Reference parameter-generation notes and calculations.
- `requirements.txt` — Python dependencies.

## Run the System

### 1. Install dependencies
```powershell
pip install -r requirements.txt
```

### 2. Start the authentication server
```powershell
python server_app/server.py
```
Server runs on `http://localhost:5000` by default. HTTPS can be enabled by setting `https = True` in `server_app/server.py` and placing `cert.pem` / `key.pem` in the workspace root.

### 3. Start a static server for the client
```powershell
cd client_app
python -m http.server 8000
```

### 4. Open in browser
Navigate to `http://localhost:8000` and use Register/Login.

## Protocol Notes

### Registration
1. Client derives `x` from username+password.
2. Client computes `y = G^x mod P`.
3. Client sends `client_id` and `secret_y` to `/register`.

### Authentication
1. Client computes commitment `t = G^r mod P` and sends it with `client_id` to `/login/commit`.
2. Server derives a deterministic challenge `c = SHA-256(remote_addr | user-agent | session_id | client_id | t) mod Q` bound to the current network connection, and returns `challenge_c` + `session_id`.
3. Client computes `s = (r + c*x) mod Q` and sends it to `/login/verify` with `X-Auth-Session: <session_id>`.
4. Server re-derives the binding, confirms it matches (relay/MitM protection), then verifies `G^s ≡ t · y^c (mod P)` and returns a signed JWT on success.

## Current Security/Implementation Details
- 2048-bit safe-prime group parameters (`P`, `Q=(P-1)/2`, `G=4`).
- `Q` is computed on the client as `(P - 1) / 2` and is not exchanged.
- Server validates subgroup membership (`pow(v, Q, P) == 1`) for all public values (`secret_y`, `commitment_t`). Rejects with `422` on failure.
- Password secret `x` remains client-side only; only `y = G^x mod P` is transmitted at registration.
- CSPRNG is used for all protocol randomness (`secrets.token_urlsafe`, `secrets.randbelow`).
- Challenge `c` is deterministic: derived via SHA-256 over the session binding (TCP peer address, User-Agent, session ID, client ID, and commitment `t`). No random nonce is generated server-side.
- Session binding enforced at `/login/verify`: if remote address or User-Agent differs from the commit request, the session is invalidated and `401` is returned.
- Commit → verify window: **SESSION_TTL = 5 seconds**. Expired sessions are rejected with `401`.
- Concurrent-commit detection: a second commit for the same `client_id` within **50 ms** is treated as a benign race (first writer wins); after 50 ms the old session is invalidated as a hijack attempt. Both paths return `409`.
- JWT access tokens are **HS256-signed**, valid for **1 hour** (`exp = iat + 3600s`).
- **KDF note**: the browser client derives `x` via `SHA-256(client_id:password)`; `qa_utils.py` uses `scrypt` (n=2048, r=8, p=1). These are intentionally different—the client-side approach is documented as a simplification.
- HTTP is used by default (development); HTTPS should be enforced in production.
- Request/response activity can be observed in the in-app network monitor.

