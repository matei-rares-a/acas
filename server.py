from flask import Flask, request, jsonify
import random

app = Flask(__name__)

# Public parameters
p = 2089
g = 2

# Client public key (registered)
y = pow(g, 1008, p)  # client password = 1008

# Temporary storage for commitments
commitments = {}

@app.route("/commit", methods=["POST"])
def commit():
    data = request.json
    client_id = data["client_id"]
    t = data["t"]
    
    # Save commitment
    commitments[client_id] = t
    
    # Generate random challenge
    c = random.randint(1, p-2)
    
    return jsonify({"c": c})

@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    client_id = data["client_id"]
    s = data["s"]
    
    t = commitments.get(client_id)
    if not t:
        return jsonify({"status": "failed", "reason": "no commitment"}), 400
    
    # Verify Schnorr proof
    left = pow(g, s, p)
    right = (t * pow(y, data["c"], p)) % p
    
    if left == right:
        return jsonify({"status": "authenticated"})
    else:
        return jsonify({"status": "failed"})

if __name__ == "__main__":
    # For testing: self-signed HTTPS
    app.run(ssl_context='adhoc', port=5000)
