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
Server runs on `https://localhost:5000` (self-signed cert is generated/used if available).

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
1. Client computes commitment `t = G^r mod P` and sends it to `/login/commit`.
2. Server returns challenge `c`.
3. Client computes `s = (r + c*x) mod Q` and sends it to `/login/verify`.
4. Server verifies `G^s ≡ t * y^c (mod P)` and returns a JWT on success.

## Current Security/Implementation Details
- 2048-bit safe-prime group parameters (`P`, `Q=(P-1)/2`, `G=4`).
- `Q` is computed on the client as `(P - 1) / 2` and is not exchanged.
- Server validates subgroup membership for public values.
- Password secret `x` remains client-side only.
- CSPRNG is used for all protocol randomness.
- Request/response activity can be observed in the in-app network monitor.

