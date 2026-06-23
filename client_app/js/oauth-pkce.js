/**
 * OAuth 2.0 PKCE (Proof Key for Code Exchange) - RFC 7636
 * Full authorization code flow with PKCE extension.
 *
 * Flow:
 *  1. Client generates code_verifier + code_challenge, saves to sessionStorage
 *  2. Browser redirects to GET /oauth/pkce/authorize?...&code_challenge=...
 *  3. Server shows its own login form (user enters credentials there)
 *  4. Server validates credentials → 302 to redirect_uri?code=...&state=...
 *  5. oauth-callback.html reads code from URL, gets code_verifier from sessionStorage
 *  6. POST /oauth/pkce/token {code, code_verifier} → access_token
 */

const PKCE_CLIENT_ID = 'acas-pkce-client';
const PKCE_SCOPE     = 'openid profile';

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random code_verifier (43–128 chars, URL-safe Base64).
 * RFC 7636 §4.1
 */
function generateCodeVerifier() {
    const array = new Uint8Array(48); // 48 bytes → 64 base64url chars
    window.crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

/**
 * Compute code_challenge = BASE64URL(SHA-256(verifier)).
 * RFC 7636 S4.2, S256 method.
 * @param {string} verifier
 * @returns {Promise<string>}
 */
async function computeCodeChallenge(verifier) {
    const encoded = new TextEncoder().encode(verifier);
    const digest  = await window.crypto.subtle.digest('SHA-256', encoded);
    return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Base64URL-encode a byte array (no padding).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function base64UrlEncode(bytes) {
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Generate a random state value for CSRF protection.
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
    const statusDiv     = document.getElementById('auth-status');
    const statusContent = document.getElementById('auth-status-content');
    if (statusDiv)     statusDiv.style.display   = 'none';
    if (statusContent) statusContent.innerHTML   = '';
    hideAlert();
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
// Login - full PKCE authorization code flow (real browser redirect)
// ---------------------------------------------------------------------------

async function oauthLogin() {
    const serverUrl   = document.getElementById('server-url').value.trim();
    const redirectUri = document.getElementById('redirect-uri').value.trim();

    if (!serverUrl) {
        showAlert('Please enter the server URL', 'error');
        return;
    }
    if (!redirectUri) {
        showAlert('Please enter a redirect URI', 'error');
        return;
    }

    try {
        const btn = document.getElementById('login-btn');
        btn.disabled  = true;
        btn.innerHTML = '<span class="spinner"></span>Preparing...';

        const _sc = document.getElementById('auth-status-content');
        const _sd = document.getElementById('auth-status');
        if (_sc) _sc.innerHTML = '';
        if (_sd) _sd.style.display = 'block';

        // ------------------------------------------------------------------
        // Step 1: Generate PKCE parameters client-side
        // ------------------------------------------------------------------
        showStatus('Step 1: Generating PKCE parameters...');
        const codeVerifier  = generateCodeVerifier();
        const codeChallenge = await computeCodeChallenge(codeVerifier);
        const state         = generateState();
        showStatus(`&nbsp;&nbsp;code_verifier  = ${codeVerifier.substring(0, 20)}... (${codeVerifier.length} chars)`);
        showStatus(`&nbsp;&nbsp;code_challenge = ${codeChallenge.substring(0, 20)}... (SHA-256 / S256)`);
        showStatus(`&nbsp;&nbsp;state          = ${state}`);

        // ------------------------------------------------------------------
        // Step 2: Encode code_verifier INSIDE the state payload.
        // The server passes state back unchanged in the 302 redirect;
        // the callback decodes it to recover both the CSRF nonce and cv.
        // ------------------------------------------------------------------
        const statePayload = base64UrlEncode(
            new TextEncoder().encode(JSON.stringify({ n: state, cv: codeVerifier }))
        );
        showStatus('Step 2: Encoding PKCE session into state parameter...');
        // Keep sessionStorage as an optional backup (same-origin case)
        sessionStorage.setItem('oauth_code_verifier', codeVerifier);
        sessionStorage.setItem('oauth_state',         state);
        sessionStorage.setItem('oauth_server_url',    serverUrl);
        sessionStorage.setItem('oauth_redirect_uri',  redirectUri);

        // ------------------------------------------------------------------
        // Step 3: Build authorization URL and redirect browser to server
        //         Server will show its own login form at /oauth/pkce/authorize
        // ------------------------------------------------------------------
        const authorizeUrl = new URL(`${serverUrl}/oauth/pkce/authorize`);
        authorizeUrl.searchParams.set('response_type',         'code');
        authorizeUrl.searchParams.set('client_id',             PKCE_CLIENT_ID);
        authorizeUrl.searchParams.set('redirect_uri',          redirectUri);
        authorizeUrl.searchParams.set('state',                 statePayload);
        authorizeUrl.searchParams.set('code_challenge',        codeChallenge);
        authorizeUrl.searchParams.set('code_challenge_method', 'S256');
        authorizeUrl.searchParams.set('scope',                 PKCE_SCOPE);

        showStatus(`Step 3: Redirecting browser to Authorization Server...`);
        showStatus(`&nbsp;&nbsp;${authorizeUrl.toString().substring(0, 80)}...`);

        // Small delay so user can see the status before the page navigates away
        await new Promise(resolve => setTimeout(resolve, 800));

        window.location.href = authorizeUrl.toString();

    } catch (error) {
        showAlert(`Error: ${error.message}`, 'error');
        const btn = document.getElementById('login-btn');
        btn.disabled  = false;
        btn.innerHTML = 'Login with OAuth PKCE';
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const registerBtn = document.getElementById('register-btn');
    if (registerBtn) registerBtn.addEventListener('click', oauthRegister);

    const loginBtn = document.getElementById('login-btn');
    if (loginBtn) loginBtn.addEventListener('click', oauthLogin);

    const clearBtn = document.getElementById('clear-monitor-btn');
    if (clearBtn) clearBtn.addEventListener('click', clearNetworkMonitor);
});
