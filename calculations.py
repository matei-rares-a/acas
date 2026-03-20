import random as random
import secrets as secrets
import hashlib 

# Safe RSA-1024
# Time taken: 12.8760548s
# e=65537
# p=10799018309446006153560036749353158705056175647823285790796460092303813861749126441429930429447845710239509637563345854809963263047423360051128404343310267
# q=11265765632342335036551537872091696586110198505542913553263679179110264391849698228905037174797514739946379181292256825064149485720441384418176141323787543

# Zp* = {1, 2, ..., p-1}
# Zp e de ordin p-1 
global_p = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579 #  todo safe prime
# p-1 = 2q
# daca p este un safe prime, atunci q = (p-1)//2
q= (global_p-1) // 2
# Alegem un h random în [2, p-2]
    ##h =  random.randint(1, global_p-2)  # random but its a bit predictable
h= secrets.randbelow(global_p-3) + 2 # more secure random, uses CSPRNG (Cryptographically Secure Pseudo-Random Number Generator), can be slow
# g = h^2 mod p
global_g = pow(h, 2, global_p)
# Verificam ca: g != 1 si g^q mod p == 1
while global_g == 1 or pow(global_g, q, global_p) != 1:
    h = secrets.randbelow(global_p-3) + 2
    global_g = pow(h, 2, global_p)
    print("Trying h:", h, "g:", global_g)

#global_g = generator of the group of order q, where q is a large prime factor of p-1 (ex: 3028308269127051525405167975747507995374541585604199432310250948811736671713875601275397800353963824392719681574489456366623847832198213548206623290136535)

password_string = "my_secure_password"
salt = secrets.token_bytes(16)  #random 128-bit salt # todo: save salt on local at sign up
password_hashed = hashlib.scrypt(password_string.encode(),salt=salt,n=2**11,r=8,p=1) #key derivation function, more secure than simple hashing, but can be slow
password_x = int.from_bytes(password_hashed, 'big') % q
print("Password x:", password_x)

#0.create secret_y and register
secret_y = pow(global_g, password_x, global_p) #y = g^x mod p
#1.create commitment and send to server
rand_r = secrets.randbelow(global_p-2) + 1 # r = random in [1, p-2]
commitment_t = pow(global_g, rand_r, global_p)  # t = g^r mod p
#2.receive challenge c from server, compute solution s and send to server
challenge_c = secrets.randbelow(global_p-2) + 1 # c = random in [1, p-2]
solution_s = (rand_r + challenge_c * password_x) % (global_p-1) # s = r + c*x mod p
#3.server final verifies, returns true
left = pow(global_g, solution_s, global_p) # left = g^s mod p
right = (commitment_t * pow(secret_y, challenge_c, global_p)) % global_p # right = t * y^c mod p
proof = left == right
print("Proof valid?", proof)



