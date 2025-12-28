# Microservice Architecture with Nginx API Gateway & Centralized Authentication

---

## 1) Maqsad

Ushbu hujjat Nginx API Gateway orqali microservice’larni **markaziy autentifikatsiya** (centralized authentication) bilan himoyalash modelini tushuntiradi. Asosiy e’tibor:

- `auth_request` yordamida barcha protected `/api/*` trafikni auth-service orqali tekshirish
- `_auth_check` — Nginx ichida umumiy “gate” sifatida ishlashi
- JWT **Access** va **Refresh** tokenlarni **Authorization header** va **HttpOnly cookie** orqali ishlatish
- Auth-service’ning **Express.js** (default namunaviy) implementatsiyasi: `login`, `refresh`, `verify/check`, `logout`

---

## 2) Nginx konfiguratsiya (API Gateway)

Quyidagi konfiguratsiyada:

- `/api/auth/*` endpointlari **public**
- `/api/products/*`, `/api/orders/*`, `/api/payments/*` endpointlari **protected**
- Har protected request oldidan Nginx `/_auth_check` subrequest qiladi
- `/_auth_check` auth-service’dagi `/api/auth/verify` ni chaqiradi

```nginx
worker_processes auto;

events { worker_connections 1024; }

http {
  upstream auth_service    { server auth-service:8000; }
  upstream product_service { server product-service:3000; }
  upstream order_service   { server order-service:3001; }
  upstream payment_service { server payment-service:8080; }

  server {
    listen 80;

    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Auth endpoints are public
    location /api/auth/ {
      proxy_pass http://auth_service;
    }

    # Internal auth check used by auth_request
    location = /_auth_check {
      internal;

      proxy_pass http://auth_service/api/auth/verify;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";

      # Forward token sources to auth-service
      proxy_set_header Authorization $http_authorization;
      proxy_set_header Cookie        $http_cookie;
    }

    # Protected: products
    location /api/products/ {
      auth_request /_auth_check;

      auth_request_set $user_id $upstream_http_x_user_id;
      auth_request_set $role    $upstream_http_x_user_role;
      auth_request_set $mfa     $upstream_http_x_user_mfa;

      proxy_set_header X-User-Id   $user_id;
      proxy_set_header X-User-Role $role;
      proxy_set_header X-User-Mfa  $mfa;

      proxy_pass http://product_service;
    }

    # Protected: orders
    location /api/orders/ {
      auth_request /_auth_check;

      auth_request_set $user_id $upstream_http_x_user_id;
      auth_request_set $role    $upstream_http_x_user_role;
      auth_request_set $mfa     $upstream_http_x_user_mfa;

      proxy_set_header X-User-Id   $user_id;
      proxy_set_header X-User-Role $role;
      proxy_set_header X-User-Mfa  $mfa;

      proxy_pass http://order_service;
    }

    # Protected: payments
    location /api/payments/ {
      auth_request /_auth_check;

      auth_request_set $user_id $upstream_http_x_user_id;
      auth_request_set $role    $upstream_http_x_user_role;
      auth_request_set $mfa     $upstream_http_x_user_mfa;

      proxy_set_header X-User-Id   $user_id;
      proxy_set_header X-User-Role $role;
      proxy_set_header X-User-Mfa  $mfa;

      proxy_pass http://payment_service;
    }
  }
}
```

---

## 3) `auth_request` va `/_auth_check` qanday ishlaydi?

### 3.1. Protected endpointga request kelganda
Misol:

```
GET /api/orders/123
Authorization: Bearer <ACCESS_TOKEN>
```

Oqim:
1) Request `/api/orders/` locationiga tushadi.
2) `auth_request /_auth_check;` sabab Nginx avval **subrequest** qiladi: `GET /_auth_check`.
3) `/_auth_check` (`internal`) auth-service’ga proxy qiladi: `GET /api/auth/verify`.
4) Auth-service javobi:
   - **2xx** → Nginx asosiy requestni microservice’ga yuboradi.
   - **401/403** → Nginx requestni bloklaydi.

---

## 4) Token modeli (amaliy tavsiya)

- **Access Token (JWT)**: 10–15 daqiqa, `Authorization: Bearer ...` bilan yuboriladi.
- **Refresh Token (JWT yoki opaque)**: 7–30 kun, **HttpOnly cookie**da saqlanadi.
- Refresh token server-side nazorat qilinadi (Redis/DB). Rotation tavsiya.

---

## 5) JWT Access + Refresh bilan ishlash (client misollar)

### 5.1. Login
`POST /api/auth/login`

```bash
curl -i -X POST http://localhost/api/auth/login   -H "Content-Type: application/json"   -d '{"email":"a@a.com","password":"123456"}'
```

Kutiladigan natija:
- `Set-Cookie: refresh_token=...; HttpOnly; ...`
- Body: `{ "access_token": "<JWT_ACCESS>" }`

### 5.2. Protected endpoint
```bash
curl -i http://localhost/api/orders/123   -H "Authorization: Bearer <JWT_ACCESS>"
```

### 5.3. Refresh (cookie orqali)
```bash
curl -i -X POST http://localhost/api/auth/refresh   --cookie "refresh_token=<JWT_REFRESH>"
```

Browser fetch:
```js
const res = await fetch("/api/auth/refresh", { method: "POST", credentials: "include" });
const { access_token } = await res.json();
```

### 5.4. Logout
```bash
curl -i -X POST http://localhost/api/auth/logout   --cookie "refresh_token=<JWT_REFRESH>"   -H "Authorization: Bearer <JWT_ACCESS>"
```

---

## 6) Auth Service (Express.js) — default namunaviy implementatsiya

Quyidagi kod **namuna** sifatida beriladi (production’da DB, audit, rate-limit, TLS va boshqalar qo‘shiladi). Maqsad — Nginx’ning `/api/auth/verify` kontraktini to‘liq qondirish.

### 6.1. O‘rnatish

```bash
npm i express cookie-parser jsonwebtoken bcrypt ioredis uuid
```

### 6.2. Environment (misol)

```bash
JWT_ACCESS_SECRET=access_secret_dev
JWT_REFRESH_SECRET=refresh_secret_dev
REDIS_URL=redis://redis:6379
```

### 6.3. `server.js` (Express) — login/refresh/verify/logout

> Izohlar:
> - Access token: `typ=access`, `sub=userId`, `role`, `ver` (token version), `jti`.
> - Refresh token: `typ=refresh`, `sub=userId`, `rid` (refresh session id).
> - Redis:
>   - `user_ver:<userId>` — global logout uchun
>   - `rt:<rid>` — refresh token store (hashed), rotation uchun
>   - `revoked:<jti>` — (ixtiyoriy) access denylist uchun

```js
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import Redis from "ioredis";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(express.json());
app.use(cookieParser());

const redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");

const ACCESS_TTL_SEC = 15 * 60;              // 15 min
const REFRESH_TTL_SEC = 15 * 24 * 60 * 60;   // 15 days

const JWT_ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET  || "access_secret_dev";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refresh_secret_dev";

/**
 * DEMO user store (o‘rniga DB ishlating)
 * password: 123456
 */
const users = new Map();
users.set("1", {
  id: "1",
  email: "a@a.com",
  role: "user",
  passwordHash: await bcrypt.hash("123456", 10)
});

function getAccessFromRequest(req) {
  const auth = req.header("Authorization");
  if (auth && auth.startsWith("Bearer ")) return auth.slice("Bearer ".length);
  // ixtiyoriy: access_token cookie’dan
  if (req.cookies?.access_token) return req.cookies.access_token;
  return null;
}

function getRefreshFromRequest(req) {
  // tavsiya: refresh token faqat HttpOnly cookie’da
  if (req.cookies?.refresh_token) return req.cookies.refresh_token;
  // ixtiyoriy: body orqali ham qabul qilish mumkin
  if (req.body?.refresh_token) return req.body.refresh_token;
  return null;
}

async function getUserVersion(userId) {
  const key = `user_ver:${userId}`;
  let v = await redis.get(key);
  if (v === null) {
    v = "0";
    await redis.set(key, v);
  }
  return Number(v);
}

function signAccessToken({ userId, role, tokenVersion }) {
  const jti = uuidv4();
  const token = jwt.sign(
    { sub: userId, role, ver: tokenVersion, jti, typ: "access" },
    JWT_ACCESS_SECRET,
    { expiresIn: ACCESS_TTL_SEC }
  );
  return { token, jti };
}

function signRefreshToken({ userId, refreshId }) {
  return jwt.sign(
    { sub: userId, rid: refreshId, typ: "refresh" },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TTL_SEC }
  );
}

/**
 * 1) LOGIN
 * - refresh cookie set qiladi (HttpOnly)
 * - access token JSON qaytaradi
 */
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const user = [...users.values()].find(u => u.email === email);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const tokenVersion = await getUserVersion(user.id);

  // Access
  const { token: access_token } = signAccessToken({
    userId: user.id,
    role: user.role,
    tokenVersion
  });

  // Refresh (rotation store)
  const rid = uuidv4();
  const refresh_token = signRefreshToken({ userId: user.id, refreshId: rid });

  // Refresh tokenni server-side hashed saqlaymiz
  const refreshHash = await bcrypt.hash(refresh_token, 10);
  await redis.setex(`rt:${rid}`, REFRESH_TTL_SEC, refreshHash);

  // HttpOnly cookie
  res.cookie("refresh_token", refresh_token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // prod’da true (HTTPS)
    maxAge: REFRESH_TTL_SEC * 1000
  });

  return res.json({ access_token });
});

/**
 * 2) VERIFY / CHECK
 * - Nginx auth_request shu endpointga uradi
 * - tokenni Authorization headerdan (yoki cookie’dan) oladi
 * - 2xx qaytsa Nginx requestni o‘tkazadi
 * - 401/403 qaytsa Nginx requestni bloklaydi
 */
app.get("/api/auth/verify", async (req, res) => {
  try {
    const token = getAccessFromRequest(req);
    if (!token) return res.status(401).send("No token");

    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    if (payload.typ !== "access") return res.status(401).send("Wrong token type");

    const userId = String(payload.sub);
    const role = String(payload.role || "user");
    const tokenVer = Number(payload.ver);
    const jti = String(payload.jti || "");

    // (ixtiyoriy) Single-token revoke (denylist)
    if (jti) {
      const revoked = await redis.get(`revoked:${jti}`);
      if (revoked) return res.status(401).send("Revoked");
    }

    // Global logout: token_version check
    const currentVer = await getUserVersion(userId);
    if (tokenVer !== currentVer) return res.status(401).send("Session expired");

    // OK => Nginx uchun identity headerlar
    res.setHeader("X-User-Id", userId);
    res.setHeader("X-User-Role", role);
    res.setHeader("X-User-Mfa", "0"); // misol (realda user profilidan keladi)

    return res.status(200).send("OK");
  } catch {
    return res.status(401).send("Unauthorized");
  }
});

/**
 * 3) REFRESH (rotation)
 * - refresh cookie’dan olinadi
 * - server-side store tekshiriladi
 * - eski refresh invalid qilinadi, yangi refresh beriladi
 * - yangi access JSON qaytariladi
 */
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const refresh = getRefreshFromRequest(req);
    if (!refresh) return res.status(401).json({ message: "No refresh token" });

    const payload = jwt.verify(refresh, JWT_REFRESH_SECRET);
    if (payload.typ !== "refresh") return res.status(401).json({ message: "Wrong token type" });

    const userId = String(payload.sub);
    const rid = String(payload.rid);

    const storedHash = await redis.get(`rt:${rid}`);
    if (!storedHash) return res.status(401).json({ message: "Refresh revoked/expired" });

    const ok = await bcrypt.compare(refresh, storedHash);
    if (!ok) return res.status(401).json({ message: "Refresh invalid" });

    // rotation: eski rid o‘chadi
    await redis.del(`rt:${rid}`);

    const user = users.get(userId);
    if (!user) return res.status(401).json({ message: "User not found" });

    const tokenVersion = await getUserVersion(userId);
    const { token: access_token } = signAccessToken({ userId, role: user.role, tokenVersion });

    const newRid = uuidv4();
    const newRefresh = signRefreshToken({ userId, refreshId: newRid });
    const newHash = await bcrypt.hash(newRefresh, 10);
    await redis.setex(`rt:${newRid}`, REFRESH_TTL_SEC, newHash);

    res.cookie("refresh_token", newRefresh, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: REFRESH_TTL_SEC * 1000
    });

    return res.json({ access_token });
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
});

/**
 * 4) LOGOUT
 * - refresh sessionni invalid qiladi (rt:<rid> o‘chadi)
 * - ixtiyoriy: access jti’ni denylistga qo‘shadi (access qolgan TTL bilan)
 * - cookie tozalanadi
 */
app.post("/api/auth/logout", async (req, res) => {
  // refreshni invalid qilish
  const refresh = getRefreshFromRequest(req);
  if (refresh) {
    try {
      const p = jwt.verify(refresh, JWT_REFRESH_SECRET);
      if (p?.rid) await redis.del(`rt:${String(p.rid)}`);
    } catch {}
  }

  // ixtiyoriy: accessni revoke (single token)
  const access = getAccessFromRequest(req);
  if (access) {
    try {
      const p = jwt.verify(access, JWT_ACCESS_SECRET);
      const jti = String(p.jti || "");
      if (jti) {
        const nowSec = Math.floor(Date.now() / 1000);
        const ttl = Math.max(1, (p.exp || nowSec) - nowSec);
        await redis.setex(`revoked:${jti}`, ttl, "1");
      }
    } catch {}
  }

  res.clearCookie("refresh_token");
  return res.status(200).json({ message: "Logged out" });
});

/**
 * 5) (Ixtiyoriy) LOGOUT-ALL / FORCE LOGOUT
 * - user_ver:<userId> ni oshiradi
 * - natija: userda access token muddati qolgan bo‘lsa ham keyingi requestda 401 bo‘ladi
 */
app.post("/api/auth/logout-all", async (req, res) => {
  // demo: user_id body’dan (realda auth qilingan userId yoki admin policy)
  const { user_id } = req.body || {};
  if (!user_id) return res.status(400).json({ message: "user_id required" });

  await redis.incr(`user_ver:${String(user_id)}`);
  return res.status(200).json({ message: "All sessions revoked" });
});

app.listen(8000, () => console.log("auth-service on :8000"));
```

---

## 7) Auth-service endpointlar (tez test)

### 7.1. Login
```bash
curl -i -X POST http://localhost/api/auth/login   -H "Content-Type: application/json"   -d '{"email":"a@a.com","password":"123456"}'
```

### 7.2. Verify (odatiy holatda Nginx chaqiradi)
```bash
curl -i http://localhost/api/auth/verify   -H "Authorization: Bearer <JWT_ACCESS>"
```

### 7.3. Refresh (cookie bilan)
```bash
curl -i -X POST http://localhost/api/auth/refresh   --cookie "refresh_token=<JWT_REFRESH>"
```

### 7.4. Logout
```bash
curl -i -X POST http://localhost/api/auth/logout   --cookie "refresh_token=<JWT_REFRESH>"   -H "Authorization: Bearer <JWT_ACCESS>"
```

### 7.5. Logout-all (force logout)
```bash
curl -i -X POST http://localhost/api/auth/logout-all   -H "Content-Type: application/json"   -d '{"user_id":"1"}'
```

---

## 8) Production shartlar va xavfsizlik

1) Auth-service va microservice portlari internetga ochilmasin (faqat Nginx public).
2) `/_auth_check` `internal;` bo‘lishi shart (sizda bor).
3) HTTPS bo‘lsa cookie `Secure` qiling.
4) Refresh tokenlarni server-side saqlash/rotation tavsiya (Redis/DB).
5) Microservice’lar faqat internal network’da bo‘lsin; Nginx orqali chaqirilsin.
6) Auth-service verify endpointi tez bo‘lishi kerak (Redis kesh + minimal IO).

---

## 9) Muallif

Abdujabborov Oybek + ChatGPT
