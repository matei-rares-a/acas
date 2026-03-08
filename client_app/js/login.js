function showStatus(message) {
    const statusDiv = document.getElementById('auth-status');
    const statusContent = document.getElementById('auth-status-content');
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
        showAlert('❌ Please enter username and password', 'error');
        return;
    }

    try {
        const btn = document.getElementById('login-btn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>Authenticating...';

        const statusContent = document.getElementById('auth-status-content');
        statusContent.innerHTML = '';
        document.getElementById('auth-status').style.display = 'block';

        // Step 1: Derive password_x
        const password_x = hashPassword(password);
        showStatus(`✓ Derived password x: ${password_x}`);

        // Step 2: Generate random r
        const r = Math.floor(Math.random() * (P - 2)) + 1;
        showStatus(`✓ Generated random r: ${r}`);

        // Step 3: Compute commitment t = g^r mod p
        const t = modpow(G, r, P);
        showStatus(`✓ Computed commitment t: ${t}`);

        // Step 4: Send commitment to server
        showStatus('⏳ Sending commitment to server...');
        const commitResponse = await fetch(`${serverUrl}/commit`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({client_id: username, t: t}),
            mode: 'cors'
        });

        const commitResult = await commitResponse.json();
        if (commitResult.status !== 'committed') {
            throw new Error(commitResult.reason || 'Commit failed');
        }

        const c = commitResult.c;
        showStatus(`✓ Received challenge c: ${c}`);

        // Step 5: Compute response s = r + c*x mod (p-1)
        const s = (r + c * password_x) % (P - 1);
        showStatus(`✓ Computed response s: ${s}`);

        // Step 6: Send response to server for verification
        showStatus('⏳ Sending response to server...');
        const verifyResponse = await fetch(`${serverUrl}/verify`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({client_id: username, s: s, c: c}),
            mode: 'cors'
        });

        const result = await verifyResponse.json();

        if (result.status === 'authenticated') {
            showStatus('✓ Authentication successful!');
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('auth-success').style.display = 'block';
            document.getElementById('token-display').textContent = result.token;
            showAlert('✅ Authentication successful!', 'success');
        } else {
            throw new Error(result.reason || 'Verification failed');
        }

        btn.disabled = false;
        btn.innerHTML = 'Login';
    } catch (error) {
        showAlert(`❌ Error: ${error.message}`, 'error');
        const btn = document.getElementById('login-btn');
        btn.disabled = false;
        btn.innerHTML = 'Login';
    }
}

handleEnterKey(authenticate);
