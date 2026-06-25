async function register() {
    const client_id = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const serverUrl = document.getElementById('server-url').value.trim();

    if (!client_id || !password) {
        showAlert('Please enter client ID and password', 'error');
        return;
    }

    try {
        const btn = document.getElementById('register-btn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>Registering...';

        // Fetch parameters from server
        await fetchParameters(serverUrl);
        console.log(`Parameters received for registration`);

        // Derive password_x from password
        const password_x = await derivePasswordX(password, client_id);

        // Compute secret_y = g^x mod p
        const secret_y = modPow(G, password_x, P);
        const requestId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;

        // Send registration request directly to auth server
        const response = await fetch(`${serverUrl}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Accept': 'application/json',
                'Accept-Language': navigator.language || 'en-US',
                'API-Version': 'S1.0',
                'Request-ID': requestId,
                'Idempotency-Key': requestId
            },
            body: JSON.stringify({client_id: client_id, secret_y: secret_y.toString()}),
            mode: 'cors'
        });

        const result = await response.json();

        if (response.ok) {
            showAlert(`${result.status} successfully!`, 'success');

            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
        } else {
            showAlert(`Registration failed: ${result.reason}`, 'error');
        }

        btn.disabled = false;
        btn.innerHTML = 'Register';
    } catch (error) {
        showAlert(`Error: ${error.message}`, 'error');
        const btn = document.getElementById('register-btn');
        btn.disabled = false;
        btn.innerHTML = 'Register';
    }
}

// tie enter-key and button click
handleEnterKey(register);
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('register-btn').addEventListener('click', register);
    document.getElementById('clear-monitor-btn').addEventListener('click', clearNetworkMonitor);
});
