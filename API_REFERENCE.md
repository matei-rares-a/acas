# API Reference – ZKP Authentication Server

Covers all endpoints, headers, status codes, and OAuth2 flows for this server.

---

## 1. Request Headers

| Header | Required | Description |
|---|---|---|
| `Content-Type: application/json; charset=utf-8` | Yes (JSON body requests) | |
| `Accept: application/json` | Recommended | |
| `Authorization: Bearer <JWT>` | Protected endpoints | See §3 |
| `X-Auth-Session: <session_id>` | `POST /login/verify` only | Session ID returned by `/login/commit` |
| `Request-ID: <uuid>` | Optional | Echoed back in response; generated server-side if absent |
| `API-Version: S1.0` | Optional | Informational; server emits same value in response |

---

## 2. Response Headers (emitted on every response)

> **Scope**: security and metadata headers are applied to the core ZKP paths (`/health`, `/parameters`, `/register`, `/login/*`, `/data`). OAuth endpoints (`/oauth/*`, `/authlib/*`) do not inherit them.

| Header | Value |
|---|---|
| `Content-Type` | `application/json; charset=utf-8` |
| `API-Version` | `S1.0` |
| `Request-ID` | Echoed from request or server-generated UUID |
| `X-Response-Time` | `<ms>` – wall-clock time for the request |
| `Server-Timing` | `app;dur=<ms>` |
| `Cache-Control` | `private, no-store, no-cache, must-revalidate` (default; overridden per endpoint) |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'; base-uri 'self'; frame-ancestors 'none'` |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (HTTPS only) |
| `WWW-Authenticate` | `Bearer realm="Schnorr Authentication", charset="UTF-8"` (401 responses only) |

---

## 3. Authorization Schemes (accepted)

- `Authorization: Bearer <token>` ← preferred (RFC 6750)
- `Authorization: Token <token>`
- `Authorization: JWT <token>`
- `Authorization: DPoP <token>`
- Raw token without scheme (compatibility fallback)

---

## 4. CORS Policy

- Allowed origins: `*` (development; restrict in production)
- Allowed methods: `GET, POST, PUT, OPTIONS`

---

## 5. Endpoints

### 5.1 `GET /health`
- `200 OK` – service reachable

### 5.2 `GET /parameters`
Returns the public Schnorr group parameters `P` and `G`.
- `200 OK`
- Override headers: `Cache-Control: public, max-age=3600` · `ETag: W/"v1.0-schnorr"`

### 5.3 `POST /register`
Register a ZKP user. Client sends `client_id` and `secret_y = G^x mod P`.
- `201 Created` – new user registered
- `409 Conflict` – `client_id` already registered
- `400 Bad Request` – missing `client_id` or `secret_y`
- `422 Unprocessable Entity` – `secret_y` is not a valid subgroup member

### 5.4 `POST /login/commit`
Step 1 of the ZKP login. Client sends commitment `t = G^r mod P`.
- `200 OK` – `{ "challenge_c": "<int>", "session_id": "<token>" }`. The challenge is **deterministic**: derived via `SHA-256(remote_addr | user-agent | session_id | client_id | t) mod Q`, binding the authentication attempt to the exact network connection.
- `400 Bad Request` – missing `client_id` or `commitment_t`
- `404 Not Found` – user not registered
- `409 Conflict` – existing pending session for this `client_id`; second commit within 50 ms treated as a benign race (first writer wins); after 50 ms the old session is invalidated as a hijack attempt. Client should start a new session.
- `422 Unprocessable Entity` – `commitment_t` is not a valid subgroup member

### 5.5 `POST /login/verify`
Step 2 of the ZKP login. Requires `X-Auth-Session: <session_id>` header. The commit → verify window is **5 seconds** (SESSION_TTL).
- `200 OK` – proof valid → `{ "token": "<JWT>" }`. JWT is HS256-signed and valid for **1 hour** (`expires_in: 3600`).
- `400 Bad Request` – missing `X-Auth-Session` header
- `401 Unauthorized` – session expired (TTL exceeded between commit and verify)
- `401 Unauthorized` – session binding mismatch: remote address or User-Agent changed between commit and verify (relay / MitM detection)
- `401 Unauthorized` – proof verification failed (`G^s ≠ t · y^c mod P`)
- `404 Not Found` – session or user not found
- `422 Unprocessable Entity` – `solution_s` is missing, `≤ 0`, or `≥ Q` (valid range: `0 < s < Q`)

### 5.6 `GET /data` · `POST /data` · `PUT /data`
Read or write personal data. Requires valid Bearer JWT.
- `200 OK` – read success, or existing data updated
- `201 Created` – new personal data entry created
- `400 Bad Request` – missing `data` field (write)
- `401 Unauthorized` – missing, expired, or invalid token
- `404 Not Found` – user or personal data not found

---

## 6. OAuth2 Endpoints

All OAuth2 error responses use the RFC 6749 error object:
```json
{ "error": "<code>", "error_description": "<message>" }
```

### 6.1 OAuth2 PKCE (`/oauth/pkce/…`)

#### `POST /oauth/pkce/register`
Register a user for the PKCE OAuth2 flow (requires prior `/register`).
- `201 Created` – registered
- `400 Bad Request` – missing `client_id` / `password`, or user not in ZKP registry

#### `POST /oauth/pkce/authorize`
Issue an authorization code (PKCE S256 required).
- `200 OK` – `{ "code": "<opaque>", "expires_in": <s>, "scope": "..." }`
- `302 Found` – when `response_mode=redirect`
- `400 Bad Request` – missing params, unsupported `response_type`, missing/invalid `code_challenge`
- `401 Unauthorized` – resource owner authentication failed

#### `POST /oauth/pkce/token`
Exchange authorization code or refresh token for an access token.
- `200 OK` – `{ "access_token": "<JWT>", "token_type": "Bearer", "expires_in": <s>, "refresh_token": "<token>", "scope": "..." }`
- `400 Bad Request` – missing params, invalid/expired code, PKCE verifier mismatch, unsupported `grant_type`
- Override headers: `Cache-Control: no-store` · `Pragma: no-cache`

---

### 6.2 OAuth2 Simple (`/oauth/simple/…`)

Same flow as PKCE but without `code_challenge` / `code_verifier`.

#### `POST /oauth/simple/register` – same as §6.1 register
#### `POST /oauth/simple/authorize` – same as §6.1 authorize, PKCE params not required
#### `POST /oauth/simple/token` – same as §6.1 token, `code_verifier` not required

---

### 6.3 OAuth2 Aliases (map to PKCE implementation)

| Alias | Resolves to |
|---|---|
| `POST /oauth/register` | `/oauth/pkce/register` |
| `POST /oauth/authorize` | `/oauth/pkce/authorize` |
| `POST /oauth/token` | `/oauth/pkce/token` |

---

### 6.4 Authlib PKCE (`/authlib/…`)

Authlib-backed PKCE implementation. Parameters must be **form-encoded** (`Content-Type: application/x-www-form-urlencoded`), not JSON.

#### `POST /authlib/register` – JSON body, same fields as §6.1 register
#### `POST /authlib/oauth/authorize` – form-encoded, same fields as §6.1 authorize
#### `POST /authlib/oauth/token` – form-encoded, same fields as §6.1 token

---

## 7. Standards

| Concern | Reference |
|---|---|
| HTTP semantics & status codes | RFC 9110 |
| Bearer auth scheme | RFC 6750 |
| OAuth2 Authorization Code | RFC 6749 |
| PKCE | RFC 7636 |
| JWT | RFC 7519 |
| Security headers | MDN HTTP headers reference |

---

## 8. Implementation Constants

| Constant | Value | Notes |
|---|---|---|
| `SESSION_TTL` | 5 s | Commit → verify window; expired sessions return `401` |
| `COMMIT_RACE_WINDOW_S` | 50 ms | Two commits within this window = benign race; after = hijack, old session invalidated |
| JWT `exp` | `iat + 3600 s` | HS256, signed with server secret |
| OAuth2 access token TTL | 3600 s | Custom PKCE, Simple, and Authlib implementations |
| OAuth2 auth code TTL | 120 s | |
| OAuth2 refresh token TTL | 86400 s | |
| Group parameters | P = 2048-bit safe prime, Q = (P-1)/2, G = 4 | Validated: `pow(v, Q, P) == 1` |
