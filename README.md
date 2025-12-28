# Nginx API Gateway + `auth_request` orqali umumiy `_auth_check` (Microservices uchun)

**Muallif:** Abdujabborov Oybek + ChatGPT

---

## 1) Maqsad

Ushbu README quyidagi Nginx konfiguratsiyaning **qanday ishlashini**, ayniqsa **`auth_request` + umumiy `/_auth_check`** mexanizmini batafsil tushuntiradi:

- `/api/auth/*` endpointlari **public**
- `/api/products/*`, `/api/orders/*`, `/api/payments/*` endpointlari **protected**
- Har bir protected request oldidan Nginx **ichki subrequest** (`/_auth_check`) yuboradi
- `/_auth_check` auth-service’dagi `/api/auth/verify` ni chaqiradi
- Auth-service `2xx` qaytarsa request davom etadi, `401/403` qaytarsa to‘xtatiladi

---

## 2) Nginx konfiguratsiya (berilgan holat)

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

## 3) Bu setup qanday ishlaydi? (qadam-baqadam)

### 3.1. “Public” va “Protected” farqi
- **Public:** `location /api/auth/ { ... }`
  - Login, refresh, register va hokazo endpointlar shu yerda bo‘ladi.
  - Bu `location` ichida `auth_request` yo‘q, shuning uchun tekshiruvsiz o‘tadi.

- **Protected:** `location /api/products/`, `/api/orders/`, `/api/payments/`
  - Bu `location`lar ichida `auth_request /_auth_check;` bor.
  - Demak har requestdan oldin auth tekshiruv bo‘ladi.

### 3.2. `auth_request` nima qiladi?
`auth_request` — Nginx’ning built-in mexanizmi: u asosiy requestni upstreamga yuborishdan oldin **subrequest** bajaradi.

Misol: client quyidagini chaqirdi:
```
GET /api/orders/123
Authorization: Bearer <access_token>
```

Nginx oqimi:
1) `GET /api/orders/123` request `/api/orders/` locationiga tushadi.
2) Shu location ichida `auth_request /_auth_check;` borligi uchun Nginx avval:
   - ichki subrequest: `GET /_auth_check` ni bajaradi.
3) `/_auth_check` location `internal;` bo‘lgani uchun:
   - **tashqi client uni bevosita chaqira olmaydi**
   - faqat Nginx o‘zi `auth_request` orqali chaqira oladi.
4) `/_auth_check` esa auth-service’ga proxy qiladi:
   - `proxy_pass http://auth_service/api/auth/verify;`
   - va client yuborgan tokenlarni auth-service’ga uzatadi:
     - `Authorization` header
     - `Cookie` header
5) Auth-service `/api/auth/verify` javobi:
   - **2xx** → Nginx asosiy requestni order-service’ga yuboradi
   - **401/403** → Nginx asosiy requestni **bloklaydi** va clientga shu statusni qaytaradi

> Muhim: `auth_request` natijasi asosiy requestga “gate” bo‘ladi. Ya’ni auth o‘tmasa, mikroservis umuman chaqirilmaydi.

---

## 4) Nega `_auth_check` “umumiy” hisoblanadi?

Chunki `/_auth_check` bitta joyda turadi va quyidagi barcha protected locationlar **bir xil** tekshiruv endpointidan foydalanadi:

- `/api/products/*`
- `/api/orders/*`
- `/api/payments/*`

Ya’ni tekshiruv mantiqi:
- Nginx’da takrorlanmaydi
- Har bir mikroservisga ham tarqatilmaydi
- Bitta markaziy auth-service’da boshqariladi

---

## 5) `auth_request_set` va header mapping

Auth-service verify endpointi muvaffaqiyatli bo‘lsa, u quyidagi headerlarni qaytarishi mumkin:

- `X-User-Id: 123`
- `X-User-Role: admin`
- `X-User-Mfa: true` (yoki `1`)

Nginx shu headerlarni `auth_request_set` orqali o‘zgaruvchilarga oladi:

```nginx
auth_request_set $user_id $upstream_http_x_user_id;
auth_request_set $role    $upstream_http_x_user_role;
auth_request_set $mfa     $upstream_http_x_user_mfa;
```

So‘ng ularni mikroservisga forward qiladi:

```nginx
proxy_set_header X-User-Id   $user_id;
proxy_set_header X-User-Role $role;
proxy_set_header X-User-Mfa  $mfa;
```

### Mikroservis tomonda nima bo‘ladi?
Microservice endi JWT tekshirmaydi. U shunchaki:

- `X-User-Id` mavjudligini tekshiradi (yoki majburiy deb qabul qiladi)
- `X-User-Role` bo‘yicha biznes ruxsatlarni ishlatadi
- `X-User-Mfa` bo‘yicha qo‘shimcha policy ishlatadi

> Eslatma: Bu modelda ishonch chegarasi (trust boundary) — Nginx. Shu sababli mikroservislar faqat internal network’da bo‘lishi, to‘g‘ridan-to‘g‘ri internetdan ochiq bo‘lmasligi kerak.

---

## 6) Auth-service `/api/auth/verify` contract (shartnoma)

### 6.1. Nginx verify’dan nimani kutadi?
- **Status code** muhim:
  - `200` (yoki umumiy 2xx) → “OK, user authenticated”
  - `401/403` → “Not allowed”
- Optional: qo‘shimcha “identity” headerlar:
  - `X-User-Id`
  - `X-User-Role`
  - `X-User-Mfa`

### 6.2. Minimal verify pseudocode
```js
// 1) Access tokenni ol
// 2) JWT verify (signature + exp)
// 3) Qo‘shimcha policy (revoked/jti, token_version, mfa, etc)
// 4) OK bo‘lsa 200 va X-User-* headerlar
// 5) Aks holda 401/403
```

---

## 7) Nega `proxy_pass_request_body off;` ishlatilgan?

`/_auth_check` faqat “kimligi”ni tekshiradi.
Body yuborish shart emas va ortiqcha overhead:

- network traffic kamayadi
- auth-service yuklanishi kamayadi
- tekshiruv tezlashadi

Shuning uchun:

```nginx
proxy_pass_request_body off;
proxy_set_header Content-Length "";
```

---

## 8) “Har doim ishlaydimi?” — aniq javob

Ha, quyidagi shart bilan:

- Request protected locationga tushsa (`/api/products/`, `/api/orders/`, `/api/payments/`)
- O‘sha location ichida `auth_request /_auth_check;` bo‘lsa

Shunda **har bir requestda** Nginx verify subrequest qiladi.

Lekin `/api/auth/*` public bo‘lgani uchun u yerda `/_auth_check` ishlamaydi.

---

## 9) Amaliy shartlar (Production uchun)

1) **Auth-service va microservice portlari internetga ochilmasin**
   - faqat Nginx public bo‘lsin
2) `/_auth_check` `internal;` bo‘lishi shart (sizda bor)
3) HTTPS bo‘lsa cookie `secure: true`
4) Agar CORS preflight (`OPTIONS`) ko‘p bo‘lsa, uni authsiz o‘tkazish kerak bo‘lishi mumkin (case-by-case)
5) Auth-service `verify` endpointi tez ishlashi kerak (Redis kesh tavsiya)

---

## 10) Tez test (curl)

### 10.1. Token yo‘q (401)
```bash
curl -i http://localhost/api/orders/123
```

### 10.2. Token bilan (200 yoki 401)
```bash
curl -i http://localhost/api/orders/123 \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### 10.3. `_auth_check` tashqaridan chaqirib bo‘lmaydi (kutilgan)
```bash
curl -i http://localhost/_auth_check
# natija: 404 yoki 403 (Nginx internal sababli)
```

---

## 11) Xulosa

Sizning Nginx konfiguratsiyangiz:
- Markaziy auth tekshiruvni (`/_auth_check`) bitta joyga jamlaydi
- Har protected endpointda `auth_request` orqali “gatekeeper” vazifasini bajaradi
- Auth-service `verify` orqali identity headerlarni qaytaradi
- Microservice’lar esa auth logikasiz, faqat `X-User-*` headerlar bilan ishlaydi

---

**Muallif:** Abdujabborov Oybek + ChatGPT
