# Microservice Architecture with Nginx API Gateway & Centralized Auth

**Muallif:** Abdujabborov Oybek + ChatGPT

---

## 📌 Overview

Ushbu hujjat **microservice architecture** uchun ishlab chiqilgan **Nginx API Gateway + Auth Service** asosidagi **markaziy avtorizatsiya** (authentication) yechimini tushuntiradi.

Asosiy maqsad:
- Barcha `/api/*` trafikni **bitta joyda** tekshirish
- JWT access token muddati tugashini kutmasdan **darhol logout / force logout** qilish
- Microservice’larni auth logikadan tozalash

---

## 🧱 Arxitektura

```
Client
  |
  v
Nginx (API Gateway)
  |
  |-- auth_request --> Auth Service (/verify)
  |
  +--> Product Service
  +--> Order Service
  +--> Payment Service
```

### Rollar:
- **Nginx** – routing + enforcement
- **Auth Service** – authentication, token verify, logout
- **Microservice’lar** – faqat biznes logika

---

## 🔐 Token Model

| Token        | Muddat     | Saqlanish joyi |
|--------------|------------|----------------|
| Access Token | 15 daqiqa  | Client (Header) |
| Refresh Token| 15 kun     | HttpOnly Cookie |
| Session Ver  | doimiy     | Redis / DB      |

---

## ⚙️ Asosiy Mexanizmlar

### 1️⃣ auth_request (Nginx)

- Har protected endpoint oldidan auth-service’ga subrequest yuboriladi
- 2xx → request o‘tadi
- 401/403 → request bloklanadi

```nginx
location /api/orders/ {
  auth_request /_auth_check;
  proxy_pass http://order_service;
}
```

---

### 2️⃣ Token Version (Global Logout)

**Muammo:**  
JWT stateless → token muddati tugamaguncha ishlayveradi.

**Yechim:**  
- JWT ichida `ver` (token_version)
- Serverda `user_ver:<userId>`
- Logout bo‘lsa → `user_ver++`
- Keyingi request → 401

```js
if (payload.ver !== currentVersion) {
  return res.status(401).send("Session expired");
}
```

---

### 3️⃣ JTI Blacklist (Single Token Logout)

- Access token ichida `jti`
- Logout bo‘lsa → Redis `revoked:<jti>` (TTL bilan)
- Verify paytida tekshiriladi

```js
const revoked = await redis.get(`revoked:${jti}`);
if (revoked) return res.status(401);
```

---

### 4️⃣ Refresh Token Rotation

- Har refresh’da eski refresh invalid bo‘ladi
- Refresh token server-side saqlanadi (hashed)

```js
await redis.del(`rt:${oldRefreshId}`);
```

---

## 🔁 Request Flow

```
Client → /api/orders
  ↓
Nginx → /_auth_check
  ↓
Auth Service → /verify
  ↓
OK → Order Service
401 → Client
```

---

## 🧪 API Endpointlar

### Auth Service

| Method | Endpoint | Tavsif |
|------|---------|-------|
| POST | /login | Login |
| POST | /refresh | Token yangilash |
| GET | /verify | Nginx subrequest |
| POST | /logout | Session logout |
| POST | /logout-all | Global logout |

---

## 🧠 Nima uchun shunday qilingan?

- 🔒 Xavfsizlik: barcha auth bitta joyda
- ⚡ Tezlik: microservice’lar yengil
- 🔁 Immediate logout: token muddati kutib o‘tilmaydi
- 📈 Scale: Redis + stateless access token

---

## 🛑 Xavfsizlik Talablari

- Auth-service tashqariga ochilmasin (faqat internal network)
- Refresh token → httpOnly + secure (prod)
- Nginx `/_auth_check` → `internal`
- HTTPS majburiy (prod)

---

## 🚀 Ishga tushirish

```bash
docker compose up -d
```

Talab qilinadi:
- Nginx
- Auth Service
- Redis
- Product / Order / Payment services

---

## 🧑‍💻 Kimlar uchun mos?

- SaaS platformalar
- Fintech
- E-commerce
- High-security API’lar
- Microservice + Gateway arxitekturasi

---

## ✍️ Muallif

**Abdujabborov Oybek**  
**ChatGPT**

---

✅ Ushbu arxitektura production-ready va kengaytiriladigan.
