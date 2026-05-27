"""
Global ZKP parameter generation and validation.

Run: python qa/measurement/generates.py --params
"""

import secrets
import sys
import time

from cryptography.hazmat.primitives.asymmetric import dh


P, Q, G = None, None, None


def generate_global_parameters(generate_new=False, use_library=False, generator=2, key_size=2048):
    global P, Q, G
    mode = "library" if use_library else "custom"
    print(f"Generating global parameters with {mode} for: {generator}, {key_size}")
    start_time = time.time_ns()
    if not generate_new:
        P = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
        Q = (P - 1) // 2
        G = 4
    else:
        parameters = dh.generate_parameters(generator=generator, key_size=key_size)
        P = parameters.parameter_numbers().p
        if use_library:
            G = parameters.parameter_numbers().g
        else:
            Q = (P - 1) // 2
            temp_h = secrets.randbelow(P - 3) + 2
            G = pow(temp_h, 2, P)
            while G == 1 or pow(G, Q, P) != 1:
                temp_h = secrets.randbelow(P - 3) + 2
                G = pow(temp_h, 2, P)
        Q = (P - 1) // 2

    elapsed_ms = (time.time_ns() - start_time) / 1000000
    print(f"Global parameters generated in {elapsed_ms:.6f} ms")
    print(f"P = {P}")
    print(f"G = {G}")
    print(f"Q = {Q}")
    print(f"P este prim sigur (p = 2q + 1)? -> {P == 2 * Q + 1}")
    return {"P": P, "Q": Q, "G": G, "elapsed_ms": elapsed_ms}


if __name__ == "__main__":
    generate_global_parameters(generate_new=True, use_library=False)




