import hashlib
import os

def generate_2048bit_number() -> int:
    seed = os.urandom(64)  # 512-bit entropy seed
    digest = hashlib.shake_256(seed).digest(256)  # 256 bytes = 2048 bits
    return int.from_bytes(digest, byteorder="big")


if __name__ == "__main__":
    n = generate_2048bit_number()
    print(f"Decimal ({n.bit_length()} bits):\n{n}\n")
    print(f"Hex:\n{n:#0{2 + 512}x}")
