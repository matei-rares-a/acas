

global_p = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579 #  todo safe prime
global_g = 334633613383181769818411823534665303121 # todo generator of the group of order q, where q is a large prime factor of p-1



password_x = 1008 # todo hash + super salt
password_string = "my_secure_password"

password_x = int.from_bytes(password_string.encode(encoding='utf-32'), 'big') % global_p
print("Password x:", password_x)


secret_y = pow(global_g, password_x, global_p) #y = g^x mod p

rand_r = 1234 # random.randint(1, global_p-2) # todo more secure random
commitment_t = pow(global_g, rand_r, global_p)  # t = g^r mod p

challenge_c = 5679 # random.randint(1, global_p-2) # todo more secure random

solution_s = (rand_r + challenge_c * password_x) % (global_p - 1)


left = pow(global_g, solution_s, global_p)
right = (commitment_t * pow(secret_y, challenge_c, global_p)) % global_p
proof = left == right
print("Proof valid?", proof)

