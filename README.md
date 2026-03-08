# acas
Oauth Protocol for Api Key Authentication using Schnorr

This project implements an OAuth-style API key authentication using the Schnorr zero-knowledge proof.

Previously a Django backend was used; it has been replaced with a lightweight Flask server located in `flask_server/app.py`.

### Running the Flask server
```powershell
cd flask_server
pip install -r ../requirements.txt
python app.py
```

### Client GUI
The client is a Flask application (`client.py`) that serves a web GUI on `https://localhost:5001`. It communicates with the authentication server at `https://localhost:5000`.

### Notes
- The Flask server uses SQLite (`auth.db`) for storage.
- Endpoints: `/register`, `/commit`, `/verify`, `/forgetme`, `/health`
- CORS is enabled to allow the GUI to interact with the API.

