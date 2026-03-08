"""
Schnorr Authentication Client - Flask Web Server
Serves a web GUI for user registration and authentication using Schnorr protocol.
"""

from flask import Flask, render_template_string, request, jsonify
from flask_cors import CORS
import requests
import random
import os
import ssl

# Global public parameters - must match server
param_p = 2089
param_g = 2

app = Flask(__name__)
CORS(app)

# Read the HTML template
html_template = open('client_gui.html', 'r').read()


@app.route('/')
def index():
    """Serve the main GUI"""
    return render_template_string(html_template)


@app.route('/api/register', methods=['POST'])
def register():
    """Handle registration requests"""
    try:
        data = request.json
        client_id = data.get('client_id')
        password = data.get('password')
        server_url = data.get('server_url', 'https://localhost:5000')

        if not client_id or not password:
            return jsonify({'error': 'Missing parameters'}), 400

        # Derive password_x from password (same as server does)
        password_x = hash_password(password)
        
        # Compute secret_y = g^x mod p
        secret_y = pow(param_g, password_x, param_p)

        # Send registration request to server
        response = requests.post(
            f'{server_url}/register',
            json={'client_id': client_id, 'secret': secret_y},
            verify=False
        )

        return response.json()
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    """Handle authentication requests"""
    try:
        data = request.json
        client_id = data.get('client_id')
        password = data.get('password')
        server_url = data.get('server_url', 'https://localhost:5000')

        if not client_id or not password:
            return jsonify({'error': 'Missing parameters'}), 400

        # Derive password_x
        password_x = hash_password(password)

        # Step 1: Generate random r
        r = random.randint(1, param_p - 2)

        # Step 2: Compute commitment t = g^r mod p
        commitment_t = pow(param_g, r, param_p)

        # Step 3: Send commitment to server
        commit_response = requests.post(
            f'{server_url}/commit',
            json={'client_id': client_id, 't': commitment_t},
            verify=False
        )

        if commit_response.status_code != 200:
            return jsonify({'error': 'Commit failed'}), 500

        commit_data = commit_response.json()
        challenge_c = commit_data.get('c')

        if not challenge_c:
            return jsonify({'error': 'No challenge received'}), 500

        # Step 4: Compute response s = r + c*x mod (p-1)
        solution_s = (r + challenge_c * password_x) % (param_p - 1)

        # Step 5: Send response to server for verification
        verify_response = requests.post(
            f'{server_url}/verify',
            json={'client_id': client_id, 's': solution_s, 'c': challenge_c},
            verify=False
        )

        return verify_response.json()
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/delete', methods=['POST'])
def delete_account():
    """Handle account deletion requests"""
    try:
        data = request.json
        client_id = data.get('client_id')
        server_url = data.get('server_url', 'https://localhost:5000')

        if not client_id:
            return jsonify({'error': 'Missing client_id'}), 400

        # Send deletion request to server
        response = requests.post(
            f'{server_url}/forgetme',
            json={'client_id': client_id, 'token': 'yes'},
            verify=False
        )

        return response.json()
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def hash_password(password):
    """
    Simple password hashing function for demo purposes.
    In production, use proper key derivation function (scrypt, argon2, pbkdf2).
    """
    hash_value = 0
    for char in password:
        hash_value = ((hash_value << 5) - hash_value) + ord(char)
        hash_value = hash_value & 0xFFFFFFFF  # Keep it 32-bit
    return abs(hash_value) % (param_p - 1) + 1


def create_self_signed_cert():
    """Create a self-signed certificate for HTTPS"""
    try:
        if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
            import subprocess
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                '-keyout', 'key.pem', '-out', 'cert.pem',
                '-days', '365', '-nodes',
                '-subj', '/CN=localhost'
            ], check=True)
            print('Created self-signed certificate')
    except Exception as e:
        print(f'Warning: Could not create certificate: {e}')
        print('Run without HTTPS or generate certificates manually:')
        print('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"')


if __name__ == '__main__':
    # Suppress SSL warnings for self-signed certificates
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print('Schnorr Authentication Client')
    print('=' * 50)
    print('Starting Flask server on https://localhost:5001')
    print('Open your browser and go to: https://localhost:5001')
    print('=' * 50)

    # Try to create self-signed certificate
    create_self_signed_cert()

    # Run with HTTPS if certificates exist
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        app.run(
            host='0.0.0.0',
            port=5001,
            ssl_context=('cert.pem', 'key.pem'),
            debug=True
        )
    else:
        # Fall back to HTTP
        print('WARNING: Running without HTTPS. Certificates not found.')
        app.run(
            host='0.0.0.0',
            port=5001,
            debug=True
        )


