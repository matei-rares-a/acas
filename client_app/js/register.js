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

        // Derive password_x from password
        const password_x = hashPassword(password);

        // Compute secret_y = g^x mod p
        const secret_y = modpow(G, password_x, P);

        // Send registration request directly to auth server
        const response = await fetch(`${serverUrl}/register`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({client_id: username, secret: secret_y}),
            mode: 'cors'
        });

        const result = await response.json();

        if (result.status === 'registered' || result.status === 'updated') {
            showAlert(`✅ ${result.status.charAt(0).toUpperCase() + result.status.slice(1)} successfully!`, 'success');

            document.getElementById('username').value = '';
            document.getElementById('password').value = '';

            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
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
