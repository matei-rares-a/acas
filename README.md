# acas
Oauth Protocol for Api Key Authentication using Schnorr

This project implements an OAuth-style API key authentication using the Schnorr zero-knowledge proof.

### Project Structure
- `calculations.py` - Core Schnorr protocol implementation and parameter generation
- `flask_server/app.py` - Flask authentication server with SQLite database
- `client_app/` - Pure HTML/JavaScript client application
  - `index.html` - Main landing page (links to register/login)
  - `register.html` - Registration view with external CSS/JS
  - `login.html` - Login view with external CSS/JS
  - `css/style.css` - Shared stylesheet
  - `js/auth.js` - Shared authentication utilities
  - `js/register.js` - Registration logic
  - `js/login.js` - Login/authentication logic
- `requirements.txt` - Python dependencies

### Running the System

#### 1. Start the Authentication Server
```powershell
cd flask_server
pip install -r ../requirements.txt
python app.py
```
The server will run on `https://localhost:5000` (with self-signed certificate).

#### 2. Start the Client Application Server
```powershell
python serve_client.py
```
This will serve the HTML/JavaScript client on `http://localhost:8000`.

#### 3. Open in Browser
Navigate to `http://localhost:8000` in your web browser and choose Register or Login.

### How It Works

1. **Registration**: User creates account with username/password. Password is hashed client-side and public key `y = g^x mod p` is sent to server.

2. **Authentication**: 
   - Client generates random `r` and computes commitment `t = g^r mod p`
   - Server sends challenge `c`
   - Client computes response `s = r + c*x mod (p-1)`
   - Server verifies: `g^s ≡ t * y^c mod p`

3. **Zero-Knowledge**: Password `x` never leaves the client. Only cryptographic proofs are transmitted.

### Security Features
- Zero-knowledge proof authentication
- Password never transmitted or stored
- Secure random number generation
- GDPR-compliant account deletion
- HTTPS with self-signed certificates for development

