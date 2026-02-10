from flask import Flask, request, jsonify
import random

app = Flask(__name__)

# Global public parameters
#todo unique per server instance, and should be generated securely or standardized
param_p = 2089
param_g = 2

# Client public key (registered)
secret_y = pow(param_g, 1008, param_p)  # client password = 1008

registrations = {"bob": pow(param_g, 1008, param_p)}
commitments = {}

def proof_schnorr(client_id, t, c, s):
#todo impl
    return None


@app.route("/commit", methods=["POST"])
def commit():
    data = request.json
    client_id = data["client_id"]
    commitment_t = data["t"]
    
    # Save commitment
    commitments[client_id] = commitment_t
    
    # Generate random challenge
    challenge_c = random.randint(1, param_p-2)
    
    return jsonify({"c": challenge_c})

@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    client_id = data["client_id"]
    solution_s = data["s"]
    challenge_c = data["c"]
    
    commitment_t = commitments.get(client_id)
    if not commitment_t:
        return jsonify({"status": "failed", "reason": "no commitment"}), 400
    
    # Verify Schnorr proof
    left = pow(param_g, solution_s, param_p)
    right = (commitment_t * pow(registrations[client_id], challenge_c, param_p)) % param_p
    proof = left == right
    
    if proof:
        return jsonify({"status": "authenticated"})
    else:
        return jsonify({"status": "failed"})
    
@app.route("/register", methods=["POST"])
def register():
    client_id = request.json["client_id"]
    secret = request.json["secret"]

    if client_id in registrations:
        return jsonify({"status": "failed", "reason": "client already registered"}), 400
    registrations[client_id] = secret
  
    return jsonify({"status": "authenticated"})

@app.route("/forgetme", methods=["POST"])
def forgetme():
    client_id = request.json["client_id"]
    token = request.json["token"]
    
    if token != "yes":
        return jsonify({"status": "failed", "reason": "invalid token"}), 400

    if client_id not in registrations:
        return jsonify({"status": "failed", "reason": "client not registered"}), 400
    del registrations[client_id]
    if client_id in commitments:
        del commitments[client_id]
  
    return jsonify({"status": "forgotten"})

if __name__ == "__main__":
    # For testing: self-signed HTTPS
    app.run(ssl_context='adhoc', port=5000)
