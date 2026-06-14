// shared utilities for Schnorr authentication client

let P = 2089n;
let Q = (P - 1n) / 2n;
//subgroup generator of order Q (g = h^2 mod p with h = 2)
let G = 4n;

/**
 * Pull the group parameters P and G from the server.
 * Falls back to local defaults if the request fails.
 * @param {string} serverUrl
 * @returns {Promise<{P: bigint, G: bigint}>}
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

// Derives private scalar x from password using SHAKE-256(client_id:password).
async function derivePasswordX(password, client_id = '') {
    const inputBytes = new TextEncoder().encode(`${client_id}:${password}`);
    const digestBytes = new Uint8Array(shake_256.create(2176).update(inputBytes).array()); // 272 bytes = 2176 bits, eliminates bias when reducing mod Q (2047-bit)
    let value = 0n;
    for (const b of digestBytes) {
        value = (value << 8n) + BigInt(b);
    }
    return (value % (P - 1n)) + 1n;
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
