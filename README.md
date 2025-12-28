# Microservice Architecture with Nginx API Gateway & Centralized Authentication

---

## 1) Maqsad

Ushbu hujjat Nginx API Gateway orqali microservice’larni **markaziy autentifikatsiya** (centralized authentication) bilan himoyalash modelini tushuntiradi. Asosiy e’tibor:

- `auth_request` yordamida barcha protected `/api/*` trafikni auth-service orqali tekshirish
- `_auth_check` — Nginx ichida umumiy “gate” sifatida ishlashi
- JWT **Access** va **Refresh** tokenlarni **Authorization header** va **HttpOnly cookie** orqali ishlatish namunalarini ko‘rsatish

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
2) `auth_request /_auth_check;` sabab Nginx avval **subrequest** qiladi:
   - `GET /_auth_check`
3) `/_auth_check` location `internal;` bo‘lgani uchun uni **tashqi client** chaqira olmaydi (faqat Nginx ichki chaqiradi).
4) `/_auth_check` auth-service’ga proxy qiladi:
   - `GET http://auth_service/api/auth/verify`
   - va token manbalarini forward qiladi:
     - `Authorization` header
     - `Cookie` header
5) Auth-service javobi:
   - **2xx** → Nginx asosiy requestni microservice’ga yuboradi
   - **401/403** → Nginx requestni bloklaydi

### 3.2. Nega `_auth_check` “umumiy gate”?
Chunki u bitta joyda turadi va barcha protected locationlar uni ishlatadi:
- `/api/products/*`
- `/api/orders/*`
- `/api/payments/*`

---

## 4) `auth_request_set` orqali identity headerlar

Auth-service `/api/auth/verify` muvaffaqiyatli bo‘lsa, u Nginx o‘qiy oladigan headerlar qaytaradi (misol):

- `X-User-Id: 123`
- `X-User-Role: admin`
- `X-User-Mfa: 1`

Nginx ularni olib microservice’ga uzatadi:

```nginx
auth_request_set $user_id $upstream_http_x_user_id;
proxy_set_header X-User-Id $user_id;
```

Natija: microservice JWT tekshirmaydi; u Nginx’dan kelgan `X-User-*` headerlar asosida ishlaydi (biznes ruxsatlar, role-based policy, va h.k.).

---

## 5) JWT Access + Refresh bilan ishlash namunalar

Quyida amaliyotda eng ko‘p ishlatiladigan model keltirilgan:

- **Access Token**: 10–15 daqiqa (stateless), odatda `Authorization: Bearer ...` orqali yuboriladi
- **Refresh Token**: 7–30 kun (server-side nazorat), odatda `HttpOnly cookie`da saqlanadi
- Refresh token yordamida yangi access token olinadi (rotation tavsiya)

### 5.1. Tokenlarni qayerda saqlash va qanday yuborish?

**Tavsiya etiladigan model:**
- Access token → frontend memory (yoki secure storage) → har requestda header orqali yuboriladi
- Refresh token → `HttpOnly` cookie → brauzer avtomatik yuboradi (JS o‘qiy olmaydi)

**Cookie nomlari (misol):**
- `refresh_token` (HttpOnly)
- (ixtiyoriy) `access_token` cookie’da ham bo‘lishi mumkin, lekin odatda access headerda bo‘ladi

### 5.2. Login: access token JSON’da, refresh token cookie’da

#### HTTP (misol)
`POST /api/auth/login`
```http
POST /api/auth/login HTTP/1.1
Content-Type: application/json

{"email":"a@a.com","password":"123456"}
```

#### Javob (misol)
- refresh token → `Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Lax`
- access token → JSON body

```json
{ "access_token": "<JWT_ACCESS>" }
```

### 5.3. Protected API chaqirish (Authorization header)

#### curl misol
```bash
curl -i http://localhost/api/orders/123   -H "Authorization: Bearer <JWT_ACCESS>"
```

Nginx:
- `Authorization` headerni `/_auth_check` ga uzatadi
- auth-service `/verify` 2xx qaytarsa request microservice’ga o‘tadi

### 5.4. Refresh qilish (cookie orqali)

Frontend access token eskirsa:
- `POST /api/auth/refresh` chaqiradi
- refresh token cookie’da bo‘lgani uchun brauzer **avtomatik yuboradi**
- server yangi access token qaytaradi va (rotation bo‘lsa) yangi refresh cookie beradi

#### curl misol (cookie bilan)
```bash
curl -i -X POST http://localhost/api/auth/refresh   --cookie "refresh_token=<JWT_REFRESH>"
```

#### Browser fetch misol (cookie yuborilishi uchun)
```js
// cookie yuborilishi uchun credentials shart (frontend va gateway domeniga bog‘liq)
const res = await fetch("/api/auth/refresh", {
  method: "POST",
  credentials: "include"
});
const data = await res.json();
const accessToken = data.access_token;
```

### 5.5. Verify endpoint tokenni qayerdan oladi?

Auth-service `verify` odatda tokenni quyidagi tartibda qidiradi (tavsiya):

1) `Authorization: Bearer <access>` (birinchi prioritet)
2) agar bo‘lmasa: `Cookie: access_token=<access>` (agar siz access’ni cookie’da saqlasangiz)

Nginx konfiguratsiyangiz har ikkisini auth-service’ga uzatadi:
- `proxy_set_header Authorization $http_authorization;`
- `proxy_set_header Cookie $http_cookie;`

### 5.6. Logout (refreshni bekor qilish + ixtiyoriy access revoke)

Logout odatda refresh tokenni server-side invalid qiladi (rotation bo‘lsa juda muhim).

#### curl logout (cookie yuborib)
```bash
curl -i -X POST http://localhost/api/auth/logout   --cookie "refresh_token=<JWT_REFRESH>"   -H "Authorization: Bearer <JWT_ACCESS>"
```

### 5.7. “Darhol chiqarish” (force logout) — token muddatini kutmasdan

Agar siz “userda access token 10 daqiqa qolgan bo‘lsa ham, keyingi requestdayoq 401 bo‘lsin” desangiz,
auth-service `verify` ichida **server-side state** tekshiruv bo‘lishi kerak:

- `token_version` (global logout) yoki
- `jti` denylist (single token logout)

Bu logika auth-service’da bo‘ladi; Nginx faqat `/verify` natijasiga qarab requestni o‘tkazadi yoki bloklaydi.

---

## 6) Production shartlar va xavfsizlik

1) Auth-service va microservice portlari internetga ochilmasin (faqat Nginx public).
2) `/_auth_check` `internal;` bo‘lishi shart (sizda bor).
3) HTTPS bo‘lsa cookie `Secure` qiling.
4) Refresh tokenlarni server-side saqlash/rotation tavsiya (Redis/DB).
5) Microservice’lar to‘g‘ridan-to‘g‘ri internetdan chaqirilmasin; faqat Nginx orqali.

---

## 7) Tez test (curl)

### Token yo‘q → 401
```bash
curl -i http://localhost/api/products
```

### Token bilan → 200 yoki 401
```bash
curl -i http://localhost/api/products   -H "Authorization: Bearer <JWT_ACCESS>"
```

### `_auth_check` tashqaridan chaqirib bo‘lmaydi (kutilgan)
```bash
curl -i http://localhost/_auth_check
```

---

## 8) Muallif

Abdujabborov Oybek + ChatGPT
