/**
 * OAuth 2.0 PKCE (Proof Key for Code Exchange) - RFC 7636
 * Full authorization code flow with PKCE extension.
 *
 * Flow:
 *  1. Client generates code_verifier (random secret)
 *  2. Client computes code_challenge = BASE64URL(SHA-256(code_verifier))
 *  3. GET /oauth/pkce/authorize?...&code_challenge=...  → server stores request, returns HTML form
 *  4. POST /oauth/pkce/authorize (form: auth_request_id + credentials) → 302 to redirect_uri?code=...
 *  5. Extract authorization code from redirect URL
 *  6. POST /oauth/pkce/token with code + code_verifier → access_token
 */

const PKCE_CLIENT_ID = 'acas-pkce-client';
const PKCE_SCOPE     = 'openid profile';

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random code_verifier (43-128 chars, URL-safe Base64).
 * RFC 7636 §4.1
 */
function generateCodeVerifier() {
    const array = new Uint8Array(48); // 48 bytes → 64 base64url chars
    window.crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

/**
 * Compute code_challenge = BASE64URL(SHA-256(verifier)).
 * RFC 7636 §4.2 (S256 method)
 * @param {string} verifier
 * @returns {Promise<string>}
 */
async function computeCodeChallenge(verifier) {
    const encoded = new TextEncoder().encode(verifier);
    const digest  = await window.crypto.subtle.digest('SHA-256', encoded);
    return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Base64URL encode a byte array (no padding).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function base64UrlEncode(bytes) {
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generate a random state parameter (CSRF protection).
 * @returns {string}
 */
function generateState() {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

// ---------------------------------------------------------------------------
// Shared UI helpers (mirrors auth.js pattern for alert / status)
// ---------------------------------------------------------------------------

function showStatus(message) {
    const statusDiv     = document.getElementById('auth-status');
    const statusContent = document.getElementById('auth-status-content');
    if (!statusDiv || !statusContent) return;
    statusDiv.style.display = 'block';
    statusContent.innerHTML += `<div class="status-item">${message}</div>`;
    statusContent.scrollTop = statusContent.scrollHeight;
}

function resetForm() {
    document.getElementById('login-form').style.display        = 'block';
    document.getElementById('auth-success').style.display      = 'none';
    document.getElementById('auth-status').style.display       = 'none';
    hideAlert();
    document.getElementById('auth-status-content').innerHTML   = '';
    document.getElementById('username').value                   = '';
    document.getElementById('password').value                   = '';
}

// ---------------------------------------------------------------------------
// Registration  (POST /oauth/pkce/register)
// ---------------------------------------------------------------------------

async function oauthRegister() {
    const client_id = document.getElementById('username').value.trim();
    const password  = document.getElementById('password').value;
    const serverUrl = document.getElementById('server-url').value.trim();

    if (!client_id || !password) {
        showAlert('Please enter client ID and password', 'error');
        return;
    }

    try {
        const btn = document.getElementById('register-btn');
        btn.disabled  = true;
        btn.innerHTML = '<span class="spinner"></span>Registering...';

        const requestId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;

        const response = await fetch(`${serverUrl}/oauth/pkce/register`, {
            method: 'POST',
            headers: {
                'Content-Type':  'application/json; charset=utf-8',
                'Accept':        'application/json',
                'Accept-Language': navigator.language || 'en-US',
                'API-Version':   'S1.0',
                'Request-ID':    requestId,
                'Idempotency-Key': requestId,
            },
            body: JSON.stringify({ client_id, password }),
            mode: 'cors',
        });

        const result = await response.json();

        if (response.ok) {
            showAlert(`${result.status || 'Registered successfully'}!`, 'success');
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
        } else {
            showAlert(`Registration failed: ${result.error_description || result.error}`, 'error');
        }

        btn.disabled  = false;
        btn.innerHTML = 'Register';
    } catch (error) {
        showAlert(`Error: ${error.message}`, 'error');
        const btn = document.getElementById('register-btn');
        btn.disabled  = false;
        btn.innerHTML = 'Register';
    }
}

// ---------------------------------------------------------------------------
// Login - full PKCE authorization code flow
// ---------------------------------------------------------------------------

async function oauthLogin() {
    const username    = document.getElementById('username').value.trim();
    const password    = document.getElementById('password').value;
    const serverUrl   = document.getElementById('server-url').value.trim();
    const redirectUri = document.getElementById('redirect-uri').value.trim();

    if (!username || !password) {
        showAlert('Please enter username and password', 'error');
        return;
    }
    if (!redirectUri) {
        showAlert('Please enter a redirect URI', 'error');
        return;
    }

    try {
        const btn = document.getElementById('login-btn');
        btn.disabled  = true;
        btn.innerHTML = '<span class="spinner"></span>Authenticating...';

        document.getElementById('auth-status-content').innerHTML = '';
        document.getElementById('auth-status').style.display = 'block';

        // ------------------------------------------------------------------
        // Step 1: Generate PKCE parameters
        // ------------------------------------------------------------------
        showStatus('Step 1: Generating PKCE parameters...');
        const codeVerifier  = generateCodeVerifier();
        const codeChallenge = await computeCodeChallenge(codeVerifier);
        const state         = generateState();
        showStatus(`&nbsp;&nbsp;code_verifier  = ${codeVerifier.substring(0, 20)}... (${codeVerifier.length} chars)`);
        showStatus(`&nbsp;&nbsp;code_challenge = ${codeChallenge.substring(0, 20)}... (SHA-256 / S256)`);
        showStatus(`&nbsp;&nbsp;state          = ${state}`);

        // ------------------------------------------------------------------
        // Step 2: GET /authorize - server validates params, returns login form
        // ------------------------------------------------------------------
        showStatus('Step 2: GET /oauth/pkce/authorize — fetching auth_request_id...');
        const authorizeUrl = new URL(`${serverUrl}/oauth/pkce/authorize`);
        authorizeUrl.searchParams.set('response_type',         'code');
        authorizeUrl.searchParams.set('client_id',             PKCE_CLIENT_ID);
        authorizeUrl.searchParams.set('redirect_uri',          redirectUri);
        authorizeUrl.searchParams.set('state',                 state);
        authorizeUrl.searchParams.set('code_challenge',        codeChallenge);
        authorizeUrl.searchParams.set('code_challenge_method', 'S256');
        authorizeUrl.searchParams.set('scope',                 PKCE_SCOPE);

        const getResp = await fetch(authorizeUrl.toString(), {
            method: 'GET',
            headers: { 'Accept': 'text/html,application/json' },
            mode: 'cors',
        });

        if (!getResp.ok) {
            let errBody = {};
            try { errBody = await getResp.json(); } catch (_) { /* ignore */ }
            throw new Error(errBody.error_description || `Authorize GET failed: ${getResp.status}`);
        }

        const html = await getResp.text();

        // Parse auth_request_id from hidden input in server-rendered form
        const match = html.match(/name="auth_request_id"\s+value="([^"]+)"/);
        if (!match) {
            throw new Error('Could not parse auth_request_id from server response');
        }
        const authRequestId = match[1];
        showStatus(`&nbsp;&nbsp;auth_request_id = ${authRequestId.substring(0, 12)}...`);

        // ------------------------------------------------------------------
        // Step 3: POST /authorize with credentials — server validates and
        //         returns JSON with the authorization code (API mode).
        //         Standard browser flow would return 302 redirect instead.
        // ------------------------------------------------------------------
        showStatus('Step 3: POST /oauth/pkce/authorize — submitting credentials...');

        const formBody = new URLSearchParams({
            auth_request_id: authRequestId,
            username,
            password,
        });

        const postResp = await fetch(`${serverUrl}/oauth/pkce/authorize`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
            },
            body: formBody.toString(),
            mode: 'cors',
        });

        const postResult = await postResp.json();

        if (!postResp.ok) {
            throw new Error(postResult.error_description || postResult.error || `Authorization failed: ${postResp.status}`);
        }

        const code          = postResult.code;
        const returnedState = postResult.state;

        if (!code) {
            throw new Error('No authorization code in response');
        }

        showStatus(`&nbsp;&nbsp;authorization_code = ${code.substring(0, 12)}...`);

        // ------------------------------------------------------------------
        // Step 4: Validate state (CSRF protection)
        // ------------------------------------------------------------------
        showStatus('Step 4: Validating state parameter (CSRF check)...');
        if (returnedState !== state) {
            throw new Error(`State mismatch! Expected "${state}" but got "${returnedState}" — possible CSRF attack`);
        }
        showStatus('&nbsp;&nbsp;State valid.');

        // ------------------------------------------------------------------
        // Step 5: Exchange code + code_verifier for access_token
        // ------------------------------------------------------------------
        showStatus('Step 5: POST /oauth/pkce/token — exchanging code for token...');
        showStatus(`&nbsp;&nbsp;Sending code_verifier = ${codeVerifier.substring(0, 20)}...`);
        showStatus('&nbsp;&nbsp;Server recomputes SHA-256(code_verifier) and matches code_challenge');

        const tokenResp = await fetch(`${serverUrl}/oauth/pkce/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Accept':       'application/json',
            },
            body: JSON.stringify({
                grant_type:    'authorization_code',
                code,
                client_id:     PKCE_CLIENT_ID,
                redirect_uri:  redirectUri,
                code_verifier: codeVerifier,
            }),
            mode: 'cors',
        });

        const tokenResult = await tokenResp.json();

        if (!tokenResp.ok) {
            throw new Error(tokenResult.error_description || tokenResult.error || 'Token exchange failed');
        }

        showStatus('Authentication successful!');

        document.getElementById('login-form').style.display   = 'none';
        document.getElementById('auth-success').style.display = 'block';
        document.getElementById('token-display').textContent  = tokenResult.access_token;
        showAlert('Authentication successful!', 'success');

        btn.disabled  = false;
        btn.innerHTML = 'Login';
    } catch (error) {
        showAlert(`Error: ${error.message}`, 'error');
        const btn = document.getElementById('login-btn');
        btn.disabled  = false;
        btn.innerHTML = 'Login';
    }
}

handleEnterKey(oauthLogin);
