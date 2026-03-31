# REST Headers and Status Codes Specification

This document defines the concrete header policy and status-code behavior for this Schnorr authentication API.

## 1. Headers Implemented

### 1.1 Request headers (client -> server)
- `Accept: application/json`
- `Accept-Language: <locale>`
- `Content-Type: application/json; charset=utf-8` (for JSON body requests)
- `Authorization: Bearer <token>` (preferred for protected endpoints)
- `API-Version: 1.0`
- `Request-ID: <unique-id>`
- `Idempotency-Key: <unique-id>` (for POST/PUT retries)

### 1.2 Response headers (server -> client)
- `Content-Type: application/json; charset=utf-8`
- `Cache-Control` (endpoint-specific)
- `API-Version: 1.0`
- `Request-ID: <echoed-or-generated-id>`
- `Vary: Accept, Origin`
- `Server-Timing: app;dur=<ms>`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; base-uri 'self'; frame-ancestors 'none'`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `WWW-Authenticate: Bearer realm="Schnorr Authentication", charset="UTF-8"` (on `401`)
- `Strict-Transport-Security` only when request is HTTPS/forwarded HTTPS

### 1.3 CORS policy
- Allow methods: `GET, POST, PUT, OPTIONS`
- Allow headers: `Content-Type, Accept, Accept-Language, Authorization, API-Version, Request-ID, Idempotency-Key`
- Expose headers: `Request-ID, API-Version, Server-Timing, ETag, WWW-Authenticate`

## 2. Authorization Policy

### 2.1 Preferred scheme
- `Authorization: Bearer <JWT>`

### 2.2 Compatibility schemes (accepted)
- `Authorization: Token <token>`
- `Authorization: JWT <token>`
- `Authorization: DPoP <token>`
- Raw token in `Authorization` (compatibility fallback)
- JSON body field `token` (legacy fallback)

Note: multi-scheme support must be extensively verified before production hardening.

## 3. Endpoint Status Codes

### 3.1 `GET /health`
- `200 OK`: service reachable

### 3.2 `GET /get-parameters`
- `200 OK`: returns public parameters (`P`, `G`)

### 3.3 `POST /register`
- `201 Created`: new user registered
- `200 OK`: existing user public key updated
- `400 Bad Request`: missing required parameters
- `422 Unprocessable Entity`: provided public value is not valid in subgroup

### 3.4 `POST /login/commit`
- `200 OK`: commitment accepted, challenge returned
- `400 Bad Request`: missing required parameters
- `404 Not Found`: user not registered
- `409 Conflict`: existing pending commitment for same client
- `422 Unprocessable Entity`: invalid commitment value

### 3.5 `POST /login/verify`
- `200 OK`: proof valid, token returned
- `400 Bad Request`: missing required parameters
- `401 Unauthorized`: proof invalid
- `404 Not Found`: user not found
- `409 Conflict`: protocol state missing (`commitment`/`challenge` absent)
- `422 Unprocessable Entity`: solution value out of valid range

### 3.6 `POST /forgetme`
- `200 OK`: user data deleted
- `400 Bad Request`: missing required `client_id`
- `401 Unauthorized`: token provided but invalid
- `404 Not Found`: user not found

### 3.7 `GET|POST|PUT /data`
- `200 OK`: read success or update existing value
- `201 Created`: created new personal data entry
- `400 Bad Request`: missing required body field (`data`) for write
- `401 Unauthorized`: missing/expired/invalid token
- `404 Not Found`: user or personal data not found

## 4. Caching Rules

- `/get-parameters`:
  - `Cache-Control: public, max-age=3600`
  - `ETag: W/"v1.0-schnorr"`
- Auth/data endpoints:
  - default `Cache-Control: private, no-store, no-cache, must-revalidate`

## 5. HTTP and HTTPS Operation

- Protocol works on HTTP and HTTPS.
- HTTPS is recommended in production.
- `Strict-Transport-Security` is emitted only when request is secure, so HTTP deployments are still functional.

## 6. Standards Alignment

- HTTP semantics and status classes: RFC 9110 (supersedes RFC 7231/7235 semantics)
- Bearer auth scheme: RFC 6750
- Security and browser policy headers: MDN HTTP headers reference
