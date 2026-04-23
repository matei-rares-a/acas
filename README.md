# acas

OAuth-style API key authentication using the Schnorr zero-knowledge protocol.


####
#TODO Pentru fiecare dintre aceste teste, adaugă în documentație log-urile din consola serverului Flask (unde se vede generarea request-urilor) alături de explicația pe care am conturat-o mai sus. Acest lucru arată comisiei că sistemul chiar a rulat și nu este doar o teorie.
#TODO Pentru testele de performanță, adaugă în documentație și graficele generate (ex: din benchmark.py sau raportul HTML din Locust) pentru a susține afirmațiile din disertație legate de performanță.
###


## Project Structure
- `calculations.py`: Reference calculations and parameter generation notes.
- `flask_server/server.py`: Flask authentication server (SQLite + JWT).
- `flask_server/db/`: SQLite database folder (`auth.db`).
- `client_app/`: HTML/JavaScript client app.
- `client_app/index.html`: Landing page.
- `client_app/register.html`: Registration page.
- `client_app/login.html`: Login page.
- `client_app/css/style.css`: Shared styles.
- `client_app/js/auth.js`: Shared Schnorr helpers and parameter fetch.
- `client_app/js/register.js`: Registration protocol flow.
- `client_app/js/login.js`: Login protocol flow.
- `client_app/js/network-monitor.js`: Real-time request/response monitor panel.
- `requirements.txt`: Python dependencies for the Flask server.

## Run the System

### 1. Install dependencies
```powershell
pip install -r requirements.txt
```

### 2. Start the authentication server
```powershell
python flask_server/server.py
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
2. Client computes `y = g^x mod p`.
3. Client sends `client_id` and `secret_y` to `/register`.

### Authentication
1. Client computes commitment `t = g^r mod p` and sends it to `/login/commit`.
2. Server returns challenge `c`.
3. Client computes `s = (r + c*x) mod q` and sends it to `/login/verify`.
4. Server verifies `g^s ≡ t * y^c (mod p)` and returns JWT on success.

## Current Security/Implementation Details
- Large safe-prime group parameters are used.
- `Q` is computed on the client as `(P - 1) / 2` and is not exchanged.
- Server validates subgroup membership for public values.
- Password secret `x` remains client-side.
- CSPRNG is used for protocol randomness.
- Request/response activity can be observed in the in-app network monitor.

