async function register() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const serverUrl = document.getElementById('server-url').value.trim();

    if (!username || !password) {
        showAlert('❌ Please enter username and password', 'error');
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
        const password_x = await derivePasswordX(password, username);

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
                'API-Version': '1.0',
                'Request-ID': requestId,
                'Idempotency-Key': requestId
            },
            body: JSON.stringify({client_id: username, secret_y: secret_y.toString()}),
            mode: 'cors'
        });

        const result = await response.json();

        if (response.ok) {
            const action = response.status === 201 ? 'Registered' : 'Updated';
            showAlert(`✅ ${action} successfully!`, 'success');

            document.getElementById('username').value = '';
            document.getElementById('password').value = '';

            // Redirect to login page after short delay if it's a successful registration (not update)
            // if (response.status === 201) {
            //     setTimeout(() => {
            //         window.location.href = 'login.html';
            //     }, 2000);
            // }
        } else {
            showAlert(`❌ Registration failed: ${result.reason}`, 'error');
        }

        btn.disabled = false;
        btn.innerHTML = 'Register';
    } catch (error) {
        showAlert(`❌ Error: ${error.message}`, 'error');
        const btn = document.getElementById('register-btn');
        btn.disabled = false;
        btn.innerHTML = 'Register';
    }
}

// tie enter-key
handleEnterKey(register);
