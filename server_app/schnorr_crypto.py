"""
Schnorr ZKP cryptographic primitives.

Covers requirements §1 (Fiat–Shamir challenge), §7 (parameter validation),
§8 (subgroup enforcement), §11 (constant-time comparison).
"""

import hashlib
import hmac
import ipaddress
import struct

# ---------------------------------------------------------------------------
# Group parameters — safe-prime Schnorr group
# P = 2Q + 1  (safe prime, 512 bits)
# G = 4 generates the unique subgroup of prime order Q
# ---------------------------------------------------------------------------
P = 11731722534755988379582498904317031585514431212880510373180315650809605302410493595610739947214327053090791642864835392206070266585210162380812213540641579
Q = (P - 1) // 2
G = 4


def validate_params() -> None:
    """Verify at process start that (P, Q, G) form a valid safe-prime Schnorr group.

    §7.3 — server must refuse to start with invalid parameters.
    """
    assert (P - 1) // 2 == Q,      "Q must equal (P-1)/2"
    assert pow(G, Q, P) == 1,      "G must generate subgroup of order Q"
    assert pow(G, 2, P) != 1,      "G must not be of order 2 (generator check)"
    assert 1 < G < P - 1,          "G must be in (1, P-1)"


# Run once at import time — raises AssertionError if parameters are wrong.
validate_params()


def is_subgroup_member(value: int) -> bool:
    """Return True iff value is a valid non-trivial element of the Schnorr subgroup.

    §8/§9 — prevents Small Subgroup attacks.
    Rejects value == 1 (trivial), value == P-1 (order-2 element), and anything
    outside the subgroup (pow(v, Q, P) != 1).
    """
    return 1 < value < P and pow(value, Q, P) == 1


def compute_challenge(
    session_id: str,
    client_id: str,
    t: int,
    server_nonce: bytes,
    client_ip: str,
    user_agent: str,
) -> int:
    """Fiat–Shamir hash-based challenge (non-interactive transform).  §1

    c = SHA-512( LP(session_id) || LP(client_id) || LP(t_bytes)
               || LP(client_ip) || LP(user_agent) || server_nonce )

    LP  = 4-byte big-endian length prefix followed by the field bytes.
          Length-prefixing prevents any two distinct field combinations from
          producing the same byte sequence (no concatenation collisions).
    server_nonce is always 32 bytes — fixed width, no length prefix needed.

    The challenge is fully determined by the session context:
    - session_id  : unique per session (CSPRNG)
    - server_nonce: unique per session (CSPRNG, 32 bytes)
    - client_ip   : network context — relay to a different IP changes c
    - user_agent  : additional context binding

    Result ∈ [1, Q-1].
    """
    h = hashlib.sha512()
    for field in (
        session_id.encode("utf-8"),
        client_id.encode("utf-8"),
        (t.to_bytes((t.bit_length() + 7) // 8, "big") if t > 0 else b"\x00"),
        client_ip.encode("utf-8"),
        user_agent.encode("utf-8"),
    ):
        h.update(struct.pack(">I", len(field)))
        h.update(field)
    h.update(server_nonce)  # fixed 32 bytes
    return (int.from_bytes(h.digest(), "big") % (Q - 1)) + 1


def verify_proof(s: int, t: int, y: int, c: int) -> bool:
    """Constant-time ZKP verification: g^s ≡ t · y^c (mod P).  §11

    Both sides are serialised to fixed-length byte arrays of (P.bit_length()+7)//8
    bytes so hmac.compare_digest operates on equal-length inputs.
    """
    p_bytes = (P.bit_length() + 7) // 8
    left  = pow(G, s, P).to_bytes(p_bytes, "big")
    right = ((t * pow(y, c, P)) % P).to_bytes(p_bytes, "big")
    return hmac.compare_digest(left, right)


def ips_match(stored_ip: str, current_ip: str) -> bool:
    """Context-binding IP comparison with /24 subnet tolerance for mobile clients.  §6.2

    - Exact match → True (both IPv4 and IPv6)
    - Same IPv4 /24 subnet → True (allows NAT renegotiation, LTE handoff)
    - Otherwise → False
    """
    if stored_ip == current_ip:
        return True
    try:
        s = ipaddress.ip_address(stored_ip)
        c = ipaddress.ip_address(current_ip)
        if isinstance(s, ipaddress.IPv4Address) and isinstance(c, ipaddress.IPv4Address):
            net_s = ipaddress.ip_network(f"{s}/24", strict=False)
            net_c = ipaddress.ip_network(f"{c}/24", strict=False)
            return net_s == net_c
    except ValueError:
        pass
    return False
