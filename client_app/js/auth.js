// shared utilities for Schnorr authentication client

// public parameters (must match the server's values)
const P = 2089;
const G = 2;

function hashPassword(password) {
    // simple hash for demo; replace with secure KDF in production
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
        const char = password.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash) % (P - 1) + 1;
}

function modpow(base, exp, mod) {
    let result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 === 1) {
            result = (result * base) % mod;
        }
        exp = Math.floor(exp / 2);
        base = (base * base) % mod;
    }
    return result;
}

function showAlert(message, type = 'info') {
    console.log('showAlert called with:', message, type);
    const alertDiv = document.getElementById('alert');
    if (!alertDiv) {
        console.warn('Alert div not found');
        return;
    }
    alertDiv.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
    alertDiv.style.display = 'block';
}

function hideAlert() {
    const alertDiv = document.getElementById('alert');
    if (alertDiv) {
        alertDiv.style.display = 'none';
        alertDiv.innerHTML = '';
    }
}

function handleEnterKey(fn) {
    document.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            fn();
        }
    });
}
