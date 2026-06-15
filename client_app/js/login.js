function showStatus(message) {
    const statusDiv = document.getElementById('auth-status');
    const statusContent = document.getElementById('auth-status-content');
    if (!statusDiv || !statusContent) {
        console.log('[status]', message);
        return;
    }
    statusDiv.style.display = 'block';
    statusContent.innerHTML += `<div class="status-item">${message}</div>`;
    statusContent.scrollTop = statusContent.scrollHeight;
}

function resetForm() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('auth-success').style.display = 'none';
    document.getElementById('auth-status').style.display = 'none';
    hideAlert();
    document.getElementById('auth-status-content').innerHTML = '';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
}

async function authenticate() {
    console.log('authenticate called');
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const serverUrl = document.getElementById('server-url').value.trim();

    if (!username || !password) {
        showAlert('Please enter username and password', 'error');
        return;
    }

    try {
        const btn = document.getElementById('login-btn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>Authenticating...';

        const statusContent = document.getElementById('auth-status-content');
        if (statusContent) statusContent.innerHTML = '';
        const statusBox = document.getElementById('auth-status');
        if (statusBox) statusBox.style.display = 'block';

        // Step 0: Fetch parameters from server
        showStatus('Fetching parameters from server...');
        await fetchParameters(serverUrl);
        showStatus(`Parameters received: P=${P}, G=${G}`);

        // Step 1: Derive password_x
        const password_x = await derivePasswordX(password, username);
        showStatus(`Derived password x=${password_x}`);

        // Step 2: Generate random r
        const r = randomInRange(1n, Q - 1n);
        showStatus(`Generated secure random r=${r}`);

        // Step 3: Compute commitment t = g^r mod p
        const t = modPow(G, r, P);
        showStatus(`Computed commitment t=${t}`);

        // Step 4: Send commitment to server
        showStatus('Sending commitment to server...');
        const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const commitResponse = await fetch(`${serverUrl}/login/commit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Accept': 'application/json',
                'Accept-Language': navigator.language || 'en-US',
                'API-Version': 'S1.0',
                'Request-ID': requestId,
            },
            body: JSON.stringify({client_id: username, commitment_t: t.toString()}),
            mode: 'cors'
        });

        const commitResult = await commitResponse.json();
        if (!commitResponse.ok) {
            throw new Error(commitResult.reason || 'Commit failed');
        }
        const challenge_c = BigInt(commitResult.challenge_c);
        showStatus(`Received challenge c=${challenge_c}`);

        // Step 5: Compute response s = r + c*x mod (p-1)
        const solution_s = (r + challenge_c * password_x) % Q;
        showStatus(`Computed response s=${solution_s}`);

        // Step 6: Send response to server for verification
        showStatus('Sending response to server...');
        const verifyResponse = await fetch(`${serverUrl}/login/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Accept': 'application/json',
                'Accept-Language': navigator.language || 'en-US',
                'API-Version': '1.0',
                'Request-ID': requestId,
                'X-Auth-Session': commitResult.session_id
            },
            body: JSON.stringify({solution_s: solution_s.toString()}),
            mode: 'cors'
        });

        const result = await verifyResponse.json();

        if (verifyResponse.ok) {
            showStatus('Authentication successful!');
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('auth-success').style.display = 'block';
            document.getElementById('token-display').textContent = result.token;
            showAlert('Authentication successful!', 'success');
        } else {
            throw new Error(result.reason || 'Verification failed');
        }

        btn.disabled = false;
        btn.innerHTML = 'Login';
    } catch (error) {
        showAlert(`Error: ${error.message}`, 'error');
        const btn = document.getElementById('login-btn');
        btn.disabled = false;
        btn.innerHTML = 'Login';
    }
}

handleEnterKey(authenticate);
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('login-btn').addEventListener('click', authenticate);
    document.getElementById('reset-btn').addEventListener('click', resetForm);
    document.getElementById('clear-monitor-btn').addEventListener('click', clearNetworkMonitor);
});
