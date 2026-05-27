// shared utilities for Schnorr authentication client

let P = 2089n;
let Q = (P - 1n) / 2n;
//subgroup generator of order Q (g = h^2 mod p with h = 2)
let G = 4n;

/**
 * Fetch global parameters P and G from the server
 * @param {string} serverUrl - The server URL
 * @returns {Promise<{P: number, G: number}>} The parameters from server
 */
async function fetchParameters(serverUrl) {
    try {
        const response = await fetch(`${serverUrl}/parameters`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Accept-Language': navigator.language || 'en-US',
                'API-Version': '1.0',
                'Request-ID': `req_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`
            },
            mode: 'cors'
        });
        
        if (!response.ok) {
            throw new Error(`Failed to fetch parameters: ${response.statusText}`);
        }
        
        const data = await response.json();
        P = BigInt(data.P);
        G = BigInt(data.G);
        Q = (P - 1n) / 2n;
        console.log(`Parameters fetched from server`);
        return { P, G };
    } catch (error) {
        console.error('Error fetching parameters:', error);
        console.warn('Using secure default parameters from local config');
        P = 2089n;
        G = 4n;
        Q = (P - 1n) / 2n;
        return { P, G };
    }
}

//NOTE: the client app should compute the secret_y using the password and the salt at registration and save the secret_y locally (in an encrypted manner) in order to be used at login
//Simplicity: the secret_y is computed everytime using password and client_id as salt
async function derivePasswordX(password, client_id = '') {
    const normalized = `${client_id}:${password}`; 

    if (window.crypto && window.crypto.subtle) {
        const encoded = new TextEncoder().encode(normalized);
        const digest = await window.crypto.subtle.digest('SHA-256', encoded);
        const digestBytes = new Uint8Array(digest);
        let value = 0n;
        for (const b of digestBytes) {
            value = (value << 8n) + BigInt(b);
        }
        return (value % (P - 1n)) + 1n;
    }

    // Fallback if subtle crypto is unavailable.
    let fallback = 0n;
    for (let i = 0; i < normalized.length; i++) {
        fallback = (fallback * 257n + BigInt(normalized.charCodeAt(i))) % Q;
    }
    return (fallback % (P - 1n)) + 1n;
}

function modPow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}

function randomInRange(minInclusive, maxInclusive) {
    if (maxInclusive < minInclusive) {
        throw new Error('Invalid random range');
    }

    const range = maxInclusive - minInclusive + 1n;
    const bits = range.toString(2).length;
    const bytes = Math.ceil(bits / 8);
    const randomBytes = new Uint8Array(bytes);
    let candidate;

    do {
        window.crypto.getRandomValues(randomBytes);
        candidate = 0n;
        for (const byte of randomBytes) {
            candidate = (candidate << 8n) + BigInt(byte);
        }
    } while (candidate >= range);

    return minInclusive + candidate;
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
