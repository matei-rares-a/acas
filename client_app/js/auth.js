// shared utilities for Schnorr authentication client (secp256r1 EC Schnorr)

// ── secp256r1 (NIST P-256) constants ──────────────────────────────────────────
const EC_P     = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFn;
const EC_A     = EC_P - 3n;  // a = -3 mod p
const EC_B     = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bn;
const EC_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const EC_GX    = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296n;
const EC_GY    = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5n;
const EC_GENERATOR = { x: EC_GX, y: EC_GY };

// ── EC field arithmetic ────────────────────────────────────────────────────────
function modInv(a, m) {
    // Extended Euclidean algorithm — returns a^-1 mod m
    let [old_r, r] = [((a % m) + m) % m, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    if (old_r !== 1n) throw new Error('modInv: no inverse');
    return ((old_s % m) + m) % m;
}

function ecPointAdd(P1, P2) {
    if (P1 === null) return P2;
    if (P2 === null) return P1;
    if (P1.x === P2.x) {
        if (P1.y !== P2.y) return null;  // P + (-P) = infinity
        // Point doubling
        const lam = (3n * P1.x * P1.x + EC_A) * modInv(2n * P1.y, EC_P) % EC_P;
        const x3 = (lam * lam - 2n * P1.x + EC_P * 2n) % EC_P;
        const y3 = (lam * (P1.x - x3) - P1.y + EC_P * 2n) % EC_P;
        return { x: x3, y: y3 };
    }
    const lam = (P2.y - P1.y + EC_P) * modInv((P2.x - P1.x + EC_P) % EC_P, EC_P) % EC_P;
    const x3 = (lam * lam - P1.x - P2.x + EC_P * 2n) % EC_P;
    const y3 = (lam * (P1.x - x3) - P1.y + EC_P * 2n) % EC_P;
    return { x: x3, y: y3 };
}

function ecScalarMult(k, pt) {
    // Double-and-add
    k = ((k % EC_ORDER) + EC_ORDER) % EC_ORDER;
    let result = null;
    let addend = pt;
    while (k > 0n) {
        if (k & 1n) result = ecPointAdd(result, addend);
        addend = ecPointAdd(addend, addend);
        k >>= 1n;
    }
    return result;
}

// ── Password KDF ──────────────────────────────────────────────────────────────
//NOTE: the client app should compute the secret_y using the password and the salt at registration
//and save the secret_y locally (in an encrypted manner) in order to be used at login.
//Simplicity: the secret_y is computed everytime using password and client_id as salt.
async function derivePasswordX(password, client_id = '') {
    const normalized = `${client_id}:${password}`;
    const encoded = new TextEncoder().encode(normalized);
    const digest = await window.crypto.subtle.digest('SHA-256', encoded);
    const digestBytes = new Uint8Array(digest);
    let value = 0n;
    for (const b of digestBytes) {
        value = (value << 8n) + BigInt(b);
    }
    const x = value % EC_ORDER;
    return x === 0n ? 1n : x;
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
