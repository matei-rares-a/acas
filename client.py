import requests
import random

# Global public parameters
param_p = 2089
param_g = 2

password = 1008
password_x = 1008

client_id = "alice"


# Step 1: compute secret
secret_y = pow(param_g, password, param_p)
# Send registeration request
resp = requests.post("https://localhost:5000/register", json={"client_id": client_id, "secret": secret_y}, verify=False)
print(resp.json())


# Step 2: compute commitment
r = random.randint(1, param_p-2)
commitment_t = pow(param_g, r, param_p)

# Send commitment
resp = requests.post("https://localhost:5000/commit", json={"client_id": client_id, "t": commitment_t}, verify=False)
challenge_c = resp.json()["c"]

# Step 3: compute response
solution_s = (r + challenge_c * password_x) % (param_p - 1)

# Step 4: send response
resp = requests.post("https://localhost:5000/verify", json={"client_id": client_id, "s": solution_s, "c": challenge_c}, verify=False)
print(resp.json())


# Step 5: forget me
resp = requests.post("https://localhost:5000/forgetme", json={"client_id": client_id, "token": "yes"}, verify=False)
print(resp.json())

