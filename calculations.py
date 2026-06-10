import random as random
import secrets as secrets
import hashlib 

# Zp* = {1, 2, ..., p-1}
# Zp e de ordin p-1 
global_p = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579 # 1024-bit safe prime (standalone demo; server uses RFC 3526 2048-bit group)
# p-1 = 2q
# daca p este un safe prime, atunci q = (p-1)//2
q= (global_p-1) // 2
# Alegem un h random în [2, p-2]
h= secrets.randbelow(global_p-3) + 2 # CSPRNG random in [2, p-2]
# g = h^2 mod p
global_g = pow(h, 2, global_p)
# Verificam ca: g != 1 si g^q mod p == 1
while global_g == 1 or pow(global_g, q, global_p) != 1:
    h = secrets.randbelow(global_p-3) + 2
    global_g = pow(h, 2, global_p)
    print("Trying h:", h, "g:", global_g)

password_string = "my_secure_password"
salt = secrets.token_bytes(16)  #random 128-bit salt # todo: save salt on local at sign up
password_hashed = hashlib.scrypt(password_string.encode(),salt=salt,n=2**11,r=8,p=1) #key derivation function, more secure than simple hashing, but can be slow
password_x = int.from_bytes(password_hashed, 'big') % q
print("Password x:", password_x)
#NOTE: good thing, if salt is used, if the password_x is compromised, then a new generation of salt will prevent the user from changing the password

#0.create secret_y and register
secret_y = pow(global_g, password_x, global_p) #y = g^x mod p, x in [0, q-1], y in subgroup of order q
#1.create commitment and send to server
rand_r = secrets.randbelow(q - 1) + 1 # r = random in Zq* = [1, 2, ..., q-1]
commitment_t = pow(global_g, rand_r, global_p)  # t = g^r mod p
#2.receive challenge c from server, compute solution s and send to server
challenge_c = secrets.randbelow(q - 1) + 1 # c = random in Zq* = [1, 2, ..., q-1]
solution_s = (rand_r + challenge_c * password_x) % q # s = r + c*x mod q, s in Zq* = [1, 2, ..., q-1]
#3.server final verifies, returns true
left = pow(global_g, solution_s, global_p) # left = g^s mod p
right = (commitment_t * pow(secret_y, challenge_c, global_p)) % global_p # right = t * y^c mod p
proof = left == right
print("Proof valid?", proof)

#y,t,left,right sunt in Zp* = {1, 2, ..., p-1}, iar x,r,c,s sunt in Zq* = {1, 2, ..., q-1}
