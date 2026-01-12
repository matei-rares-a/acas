import requests
import random

# Public parameters
p = 2089
g = 2

password = 1008
x = password

client_id = "alice"

# Step 1: choose random r and compute commitment
r = random.randint(1, p-2)
t = pow(g, r, p)

# Send commitment
resp = requests.post("https://localhost:5000/commit", json={"client_id": client_id, "t": t}, verify=False)
c = resp.json()["c"]

# Step 2: compute response
s = (r + c * x) % (p - 1)

# Step 3: send response
resp = requests.post("https://localhost:5000/verify", json={"client_id": client_id, "s": s, "c": c}, verify=False)
print(resp.json())
