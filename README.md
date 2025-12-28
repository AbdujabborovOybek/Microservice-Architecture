# Microservice Auth (JWT + Cookies) with Nginx Gateway, OTP, and MySQL (mysql2)

This repo is a **reference implementation** for a microservice architecture where:

- **Nginx** acts as an API Gateway (routing + enforcement) using `auth_request`.
- **Auth Service (Node.js/Express)** is the single source of truth for authentication:
  - issues **Access JWT** (15 min) and **Refresh JWT** (15 days)
  - supports **OTP (2FA)**, where access tokens may be issued with `mfa=false` until OTP is verified
  - exposes `/api/auth/verify` for Nginx (and optionally client) to validate tokens coming from **Authorization header** or **cookies**
- **MySQL** stores users + OTP + refresh token sessions.
- Optional: Redis can be added later for caching, but this example uses **MySQL only** (as requested).

Author: **Abdujabborov Oybek + ChatGPT**

---

## 1) Architecture

Client → Nginx → (auth_request) → Auth Service `/api/auth/verify` → Microservices

Protected routes (e.g. `/api/orders/*`) are checked by Nginx first:

1. Nginx runs a subrequest to `/_auth_check` (internal)
2. `/_auth_check` proxies to Auth Service `/api/auth/verify`
3. If Auth Service returns `200`, Nginx forwards the original request to the downstream service
4. If Auth Service returns `401/403`, Nginx blocks the request

---

## 2) Token Model

### Access Token (JWT)
- Lifetime: **15 minutes**
- Sent by client as either:
  - `Authorization: Bearer <accessToken>` **(recommended)**
  - Cookie: `access_token=<accessToken>` (optional)
- Contains claims:

```json
{
  "sub": "userId",
  "role": "user",
  "ver": 5,
  "jti": "uuid",
  "mfa": false,
  "typ": "access"
}
```

`mfa=false` means user is logged in but **OTP is not yet verified** (if your app requires OTP).

### Refresh Token (JWT)
- Lifetime: **15 days**
- Stored as **HttpOnly cookie**: `refresh_token=<refreshToken>`
- Stored server-side in MySQL as a hashed value (rotation supported)

---

## 3) OTP (2FA) Behavior

### Flow
1) `POST /api/auth/login`  
   - validates email/password  
   - generates OTP (demo logs OTP to console)  
   - returns **Access token** with `mfa=false` and a **Refresh token cookie**

2) Client shows OTP input UI.

3) `POST /api/auth/otp/verify`  
   - requires access token (header or cookie)  
   - validates OTP  
   - returns a **new access token** with `mfa=true`

4) Now, protected APIs can be used.

### Enforcement
- `/api/auth/verify` checks:
  - signature/expiry
  - `token_version` (supports forced logout)
  - `mfa` requirement (optional via query header)
- For **microservices**, you usually require `mfa=true` before allowing business actions.

---

## 4) Database Schema (MySQL)

Run:

```bash
mysql -u root -p < schema.sql
```

Tables:
- `users` (credentials + token_version)
- `otp_codes` (temporary OTP storage)
- `refresh_sessions` (rotating refresh tokens, hashed)

---

## 5) Environment Variables

Create `.env`:

```bash
PORT=8000

MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DATABASE=authdb

JWT_ACCESS_SECRET=change_me_access
JWT_REFRESH_SECRET=change_me_refresh

ACCESS_TTL_SECONDS=900
REFRESH_TTL_SECONDS=1296000

COOKIE_SECURE=false
COOKIE_SAMESITE=lax
```

---

## 6) Install & Run

```bash
npm i
node server.js
```

---

## 7) Nginx Gateway Config (Example)

See `nginx.conf` in this repo.

Key points:
- `/_auth_check` is `internal` so **clients cannot call it**
- protected routes use `auth_request /_auth_check;`
- Nginx passes `Authorization` and `Cookie` to Auth Service verify endpoint

---

## 8) API Endpoints

### Login
`POST /api/auth/login`

Body:
```json
{ "email": "a@a.com", "password": "123456" }
```

Response:
```json
{ "access_token": "..." , "otp_required": true }
```

Refresh token is set as an HttpOnly cookie.

### OTP Verify
`POST /api/auth/otp/verify`

Body:
```json
{ "code": "123456" }
```

Requires access token (header or cookie). Returns:
```json
{ "access_token": "..." , "mfa": true }
```

### Verify (for Nginx auth_request)
`GET /api/auth/verify`

- Reads access token from:
  - `Authorization: Bearer ...` OR
  - `access_token` cookie
- Returns `200 OK` and sets headers:
  - `X-User-Id`
  - `X-User-Role`
  - `X-User-Mfa`

### Refresh
`POST /api/auth/refresh`

Uses refresh token cookie, rotates refresh session, returns new access token.

### Logout (single session)
`POST /api/auth/logout`

- deletes refresh session associated with the cookie refresh token
- clears cookie

### Logout All (force logout on all devices)
`POST /api/auth/logout-all`

- increments `users.token_version`
- after this, all existing access tokens become invalid at the **next request**

---

## 9) Security Notes (Production)

- Use HTTPS and set `COOKIE_SECURE=true`
- Keep Auth Service not exposed publicly if possible (only through gateway)
- Consider rate limiting OTP verification attempts
- Consider moving OTP delivery to SMS/email provider (this demo prints OTP to console)

---

## 10) Author

**Abdujabborov Oybek + ChatGPT**
