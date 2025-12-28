import express from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mysql from "mysql2/promise";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// =====================
// Config
// =====================
const PORT = Number(process.env.PORT || 8000);

const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS || 15 * 60);
const REFRESH_TTL_SECONDS = Number(process.env.REFRESH_TTL_SECONDS || 15 * 24 * 60 * 60);

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "access_secret_dev";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refresh_secret_dev";

const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "false") === "true";
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "lax";

// =====================
// MySQL Pool (mysql2)
// =====================
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || "root",
  password: process.env.MYSQL_PASSWORD || "",
  database: process.env.MYSQL_DATABASE || "authdb",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// =====================
// Helpers
// =====================
function readAccessToken(req) {
  const auth = req.header("Authorization");
  if (auth && auth.startsWith("Bearer ")) return auth.slice("Bearer ".length);
  if (req.cookies?.access_token) return req.cookies.access_token;
  return null;
}

function readRefreshToken(req) {
  if (req.cookies?.refresh_token) return req.cookies.refresh_token;
  if (req.body?.refresh_token) return req.body.refresh_token;
  return null;
}

function setRefreshCookie(res, refreshToken) {
  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    maxAge: REFRESH_TTL_SECONDS * 1000,
    path: "/"
  });
}

function clearRefreshCookie(res) {
  res.clearCookie("refresh_token", { path: "/" });
}

function signAccessToken({ userId, role, tokenVersion, mfa }) {
  const jti = uuidv4();
  const token = jwt.sign(
    { sub: String(userId), role, ver: tokenVersion, jti, mfa: Boolean(mfa), typ: "access" },
    JWT_ACCESS_SECRET,
    { expiresIn: ACCESS_TTL_SECONDS }
  );
  return { token, jti };
}

function signRefreshToken({ userId, refreshId }) {
  return jwt.sign(
    { sub: String(userId), rid: refreshId, typ: "refresh" },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TTL_SECONDS }
  );
}

function nowPlusSeconds(sec) {
  return new Date(Date.now() + sec * 1000);
}

async function ensureDemoUser() {
  const email = "a@a.com";
  const password = "123456";

  const [rows] = await pool.query("SELECT id FROM users WHERE email = ?", [email]);
  if (rows.length > 0) return;

  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO users (email, password_hash, role, token_version, otp_enabled) VALUES (?, ?, 'user', 0, 1)",
    [email, hash]
  );
  console.log("Demo user created: a@a.com / 123456");
}

async function getUserByEmail(email) {
  const [rows] = await pool.query(
    "SELECT id, email, password_hash, role, token_version, otp_enabled FROM users WHERE email = ? LIMIT 1",
    [email]
  );
  return rows[0] || null;
}

async function getUserById(id) {
  const [rows] = await pool.query(
    "SELECT id, email, role, token_version, otp_enabled FROM users WHERE id = ? LIMIT 1",
    [id]
  );
  return rows[0] || null;
}

async function createOtpForUser(userId) {
  const code = String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = nowPlusSeconds(5 * 60); // 5 minutes

  // Invalidate old OTPs
  await pool.query("UPDATE otp_codes SET consumed = 1 WHERE user_id = ? AND consumed = 0", [userId]);

  await pool.query(
    "INSERT INTO otp_codes (user_id, code_hash, expires_at, attempts, consumed) VALUES (?, ?, ?, 0, 0)",
    [userId, codeHash, expiresAt]
  );

  // Demo: print OTP. In production, send via SMS/email.
  console.log(`[OTP] userId=${userId} code=${code} (expires in 5 min)`);
  return { expiresAt };
}

async function verifyOtp(userId, code) {
  const [rows] = await pool.query(
    "SELECT id, code_hash, expires_at, attempts, consumed FROM otp_codes WHERE user_id = ? AND consumed = 0 ORDER BY id DESC LIMIT 1",
    [userId]
  );
  const rec = rows[0];
  if (!rec) return { ok: false, reason: "NO_OTP" };

  if (rec.consumed) return { ok: false, reason: "CONSUMED" };
  if (new Date(rec.expires_at).getTime() < Date.now()) return { ok: false, reason: "EXPIRED" };
  if (rec.attempts >= 5) return { ok: false, reason: "TOO_MANY_ATTEMPTS" };

  const ok = await bcrypt.compare(code, rec.code_hash);
  await pool.query("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", [rec.id]);

  if (!ok) return { ok: false, reason: "INVALID_CODE" };

  await pool.query("UPDATE otp_codes SET consumed = 1 WHERE id = ?", [rec.id]);
  return { ok: true };
}

async function storeRefreshSession({ refreshId, userId, refreshToken }) {
  const tokenHash = await bcrypt.hash(refreshToken, 10);
  const expiresAt = nowPlusSeconds(REFRESH_TTL_SECONDS);
  await pool.query(
    "INSERT INTO refresh_sessions (id, user_id, token_hash, revoked, expires_at, rotated_from) VALUES (?, ?, ?, 0, ?, NULL)",
    [refreshId, userId, tokenHash, expiresAt]
  );
}

async function rotateRefreshSession({ oldRefreshId, userId, newRefreshId, newRefreshToken }) {
  // Revoke old
  await pool.query("UPDATE refresh_sessions SET revoked = 1 WHERE id = ? AND user_id = ?", [oldRefreshId, userId]);

  const tokenHash = await bcrypt.hash(newRefreshToken, 10);
  const expiresAt = nowPlusSeconds(REFRESH_TTL_SECONDS);
  await pool.query(
    "INSERT INTO refresh_sessions (id, user_id, token_hash, revoked, expires_at, rotated_from) VALUES (?, ?, ?, 0, ?, ?)",
    [newRefreshId, userId, tokenHash, expiresAt, oldRefreshId]
  );
}

async function validateRefreshSession(refreshId, refreshToken) {
  const [rows] = await pool.query(
    "SELECT id, user_id, token_hash, revoked, expires_at FROM refresh_sessions WHERE id = ? LIMIT 1",
    [refreshId]
  );
  const rec = rows[0];
  if (!rec) return { ok: false, reason: "NOT_FOUND" };
  if (rec.revoked) return { ok: false, reason: "REVOKED" };
  if (new Date(rec.expires_at).getTime() < Date.now()) return { ok: false, reason: "EXPIRED" };

  const ok = await bcrypt.compare(refreshToken, rec.token_hash);
  if (!ok) return { ok: false, reason: "HASH_MISMATCH" };

  return { ok: true, userId: rec.user_id };
}

// Middleware to require a valid access token (no MFA enforcement here; verify endpoint handles it)
function requireAccessToken(req, res, next) {
  const token = readAccessToken(req);
  if (!token) return res.status(401).json({ message: "No access token" });
  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    if (payload.typ !== "access") return res.status(401).json({ message: "Wrong token type" });
    req.auth = payload;
    next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

// =====================
// Routes
// =====================

// LOGIN: email/password -> issue access (mfa=false if otp enabled) + refresh cookie + create OTP
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: "email and password required" });

  const user = await getUserByEmail(email);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const otpRequired = Boolean(user.otp_enabled);

  // OTP create (demo prints to console)
  if (otpRequired) await createOtpForUser(user.id);

  // Access token: mfa=false until OTP verified (if otpRequired)
  const { token: accessToken } = signAccessToken({
    userId: user.id,
    role: user.role,
    tokenVersion: user.token_version,
    mfa: otpRequired ? false : true
  });

  // Refresh token session
  const refreshId = uuidv4();
  const refreshToken = signRefreshToken({ userId: user.id, refreshId });
  await storeRefreshSession({ refreshId, userId: user.id, refreshToken });
  setRefreshCookie(res, refreshToken);

  return res.json({ access_token: accessToken, otp_required: otpRequired });
});

// OTP VERIFY: requires access token; validates OTP; returns new access token with mfa=true
app.post("/api/auth/otp/verify", requireAccessToken, async (req, res) => {
  const code = String(req.body?.code || "");
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ message: "OTP code must be 6 digits" });

  const userId = req.auth.sub;
  const user = await getUserById(userId);
  if (!user) return res.status(401).json({ message: "User not found" });

  if (!user.otp_enabled) {
    return res.status(400).json({ message: "OTP not enabled for this user" });
  }

  const result = await verifyOtp(user.id, code);
  if (!result.ok) return res.status(401).json({ message: "OTP failed", reason: result.reason });

  // Issue new access token with mfa=true
  const { token: accessToken } = signAccessToken({
    userId: user.id,
    role: user.role,
    tokenVersion: user.token_version,
    mfa: true
  });

  return res.json({ access_token: accessToken, mfa: true });
});

// VERIFY: used by Nginx auth_request. Checks access token from header OR cookie.
// Enforces token_version and optionally MFA requirement.
app.get("/api/auth/verify", async (req, res) => {
  try {
    const token = readAccessToken(req);
    if (!token) return res.status(401).send("No token");

    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    if (payload.typ !== "access") return res.status(401).send("Wrong token type");

    const userId = Number(payload.sub);
    const user = await getUserById(userId);
    if (!user) return res.status(401).send("User not found");

    // Forced logout support: token_version check
    if (Number(payload.ver) !== Number(user.token_version)) {
      return res.status(401).send("Session expired");
    }

    // MFA enforcement: for microservices you typically require OTP to be verified
    // Default: require MFA if user has otp_enabled=1
    const requireMfa = Boolean(user.otp_enabled);
    if (requireMfa && !payload.mfa) {
      return res.status(403).send("MFA required");
    }

    // Return identity headers for gateway to forward
    res.setHeader("X-User-Id", String(user.id));
    res.setHeader("X-User-Role", String(user.role));
    res.setHeader("X-User-Mfa", payload.mfa ? "true" : "false");
    return res.status(200).send("OK");
  } catch {
    return res.status(401).send("Unauthorized");
  }
});

// REFRESH: rotate refresh token session and return new access token (keeps MFA based on your policy)
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const refreshToken = readRefreshToken(req);
    if (!refreshToken) return res.status(401).json({ message: "No refresh token" });

    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    if (payload.typ !== "refresh") return res.status(401).json({ message: "Wrong token type" });

    const refreshId = payload.rid;
    const userId = Number(payload.sub);

    const valid = await validateRefreshSession(refreshId, refreshToken);
    if (!valid.ok) return res.status(401).json({ message: "Refresh invalid", reason: valid.reason });

    const user = await getUserById(userId);
    if (!user) return res.status(401).json({ message: "User not found" });

    // Create new access token.
    // Note: if you require MFA for protected APIs, you can require the client to OTP verify again
    // or store "mfa state" server-side. This demo sets mfa=true only if otp_enabled=0.
    const mfa = user.otp_enabled ? false : true;

    const { token: newAccessToken } = signAccessToken({
      userId: user.id,
      role: user.role,
      tokenVersion: user.token_version,
      mfa
    });

    // Rotate refresh token
    const newRefreshId = uuidv4();
    const newRefreshToken = signRefreshToken({ userId: user.id, refreshId: newRefreshId });
    await rotateRefreshSession({
      oldRefreshId: refreshId,
      userId: user.id,
      newRefreshId,
      newRefreshToken
    });
    setRefreshCookie(res, newRefreshToken);

    return res.json({ access_token: newAccessToken });
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
});

// LOGOUT: revoke refresh session from cookie and clear cookie
app.post("/api/auth/logout", async (req, res) => {
  try {
    const refreshToken = readRefreshToken(req);
    if (refreshToken) {
      try {
        const p = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
        await pool.query("UPDATE refresh_sessions SET revoked = 1 WHERE id = ?", [p.rid]);
      } catch {}
    }
  } finally {
    clearRefreshCookie(res);
    return res.status(200).json({ message: "Logged out" });
  }
});

// LOGOUT ALL: force logout across all devices by incrementing token_version
app.post("/api/auth/logout-all", requireAccessToken, async (req, res) => {
  const userId = Number(req.auth.sub);
  await pool.query("UPDATE users SET token_version = token_version + 1 WHERE id = ?", [userId]);
  return res.status(200).json({ message: "All sessions revoked" });
});

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// Boot
ensureDemoUser()
  .then(() => {
    app.listen(PORT, () => console.log(`Auth service listening on :${PORT}`));
  })
  .catch((e) => {
    console.error("Failed to start:", e);
    process.exit(1);
  });
