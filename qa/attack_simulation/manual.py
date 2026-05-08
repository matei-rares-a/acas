# TODO (Manual Intervention Required)


def manual_test_traffic_sniffing():
    """
    TODO: Manual Intervention Required

    Test:    Traffic Sniffing / Store-Now-Decrypt-Later
    Goal:    Prove that the ZKP Schnorr protocol never transmits the password
             or private key x over the network.

    Setup:
      1. Start the Flask server WITHOUT TLS (HTTP only):
             python server_app/server.py
         Confirm output: "WARNING: Running without HTTPS."

      2. Start Wireshark (or tshark) on the loopback interface:
         - Windows: capture on "Loopback Pseudo-Interface 1" or "\\Device\\NPF_Loopback"

      3. Open a browser, navigate to http://localhost:5000 and perform a
         complete ZKP login:
           a) Enter client_id and password on the login page.
           b) The browser executes auth.js which calls:
              - POST /login/commit  with {client_id, commitment_t}
              - POST /login/verify  with {solution_s}  (header: X-Auth-Session)

    Theoretical conclusion:
      Even if an adversary captures the full network exchange {t, c, s} they
      cannot invert the discrete logarithm relationship y = g^x mod p for a
      2048-bit safe prime.  The zero-knowledge property guarantees that the
      proof {t, c, s} reveals no information about x beyond the fact that
      the prover knows it.
"""
    pass


def mitm():
    '''
    if the client is compromised entirely, then the attacker can pretend to be the client entirely
    so the protocol cannot protect against that.
    '''