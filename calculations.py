

global_p = 2089 #  todo safe prime
global_g = 2 # todo generator of the group of order q, where q is a large prime factor of p-1



password_x = 1008 # todo hash + super salt
secret_y = pow(global_g, password_x, global_p)

r = 1234 # random.randint(1, global_p-2) # todo more secure random
commitment_t = pow(global_g, 1234, global_p)  # random r = 1234

challenge_c = 5679 # random.randint(1, global_p-2) # todo more secure random

solution_s = (r + challenge_c * password_x) % (global_p - 1)


left = pow(global_g, solution_s, global_p)
right = (commitment_t * pow(secret_y, challenge_c, global_p)) % global_p
proof = left == right
print("Proof valid?", proof)

