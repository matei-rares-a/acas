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


def manual_test_mitm_weak_parameters():
    """
    TODO: Manual Intervention Required

    Test:    Man-in-the-Middle on /parameters (Weak Parameter Injection)
    Goal:    Show that substituting a small prime P breaks the DLP hardness
             assumption and allows an attacker to recover x trivially.
             That means, the protocol would still need to be over https/tls to prevent this attack.

    Setup:
      1. Start the Flask server:
             python server_app/server.py

      2. Install and start Burp Suite (Community Edition is sufficient):
         - Configure your browser to proxy through 127.0.0.1:8080.
         - Enable "Intercept" in the Proxy tab.

    Attack steps:
      3. Open the browser and navigate to the login page.
         auth.js will call:  GET /parameters

      4. In Burp Suite, intercept the RESPONSE to GET /parameters.
         Modify the JSON body, replacing the safe prime with a small prime:
           Original:  { "P": "<2048-bit number>", "G": "4" }
           Modified:  { "P": "23",                "G": "4" }
         Forward the modified response to the browser.

      5. The browser now performs the ZKP protocol over the weak group Z_23.
         The attacker can solve the discrete logarithm trivially:
           For P=23, enumerate g^1, g^2, ..., g^22 mod 23 to find x from y.

    Consequences:
      - Once x is known, the attacker can compute a valid solution_s for any
        challenge c:  s = r + c*x mod Q_small.
      - This completely breaks authentication.

    Mitigation:
      - /parameters MUST be served over HTTPS with a valid TLS certificate.
      - Consider Certificate Pinning in auth.js to prevent proxy interception.
      - Alternatively, hard-code the known-safe parameters in the client JS
        and never fetch them from the network.

    Expected result: PASS if the server uses HTTPS / certificate pinning in prod.
    Document: Screenshot of Burp Suite showing the intercepted response
              and the trivial DLP solution for P=23.
    """
    # TODO: Execute the steps above and document findings for Chapter 6.
    pass
