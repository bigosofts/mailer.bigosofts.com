require("dotenv").config();

const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

// =========================
// Storage Setup
// =========================

const DATA_DIR = path.join(__dirname, "data");
const MAIL_FILE = path.join(DATA_DIR, "mails.json");
const OTP_FILE = path.join(DATA_DIR, "otps.json");
const META_FILE = path.join(DATA_DIR, "meta.json"); // stores important flags etc

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(MAIL_FILE))
  fs.writeFileSync(MAIL_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(OTP_FILE))
  fs.writeFileSync(OTP_FILE, JSON.stringify({}, null, 2));
if (!fs.existsSync(META_FILE))
  fs.writeFileSync(
    META_FILE,
    JSON.stringify({ important: [], read: [] }, null, 2),
  );

// =========================
// Mail Transporter
// =========================

const OAUTH_TOKEN_FILE = path.join(DATA_DIR, "google-oauth-token.json");
const OAUTH_SCOPES = ["https://mail.google.com/"];
const oauthStates = new Map();

function getOAuthRedirectUri(req) {
  const forwardedHost = req.get("x-forwarded-host");
  const host = (forwardedHost ? forwardedHost.split(",")[0] : req.get("host"))
    .trim()
    .toLowerCase();
  const localHosts = new Set(["localhost:3000"]);
  const productionHosts = new Set([
    "www.bigosofts.com",
    "mailer.bigosofts.com",
  ]);
  if (localHosts.has(host)) return `http://${host}/v1/auth/google/callback`;
  if (productionHosts.has(host))
    return `https://${host}/v1/auth/google/callback`;
  return null;
}

function getOAuthToken() {
  try {
    return JSON.parse(fs.readFileSync(OAUTH_TOKEN_FILE, "utf8"));
  } catch {
    return {};
  }
}

function createMailTransporter() {
  const token = getOAuthToken();
  const user = process.env.MAIL_USER || process.env.MAIL_FROM;
  if (
    !process.env.OAUTH_CLIENT ||
    !process.env.OAUTH_SECRET ||
    !token.refresh_token ||
    !user
  ) {
    throw new Error(
      "Google OAuth is not authorized. Visit /v1/auth/google to authorize the sender mailbox.",
    );
  }
  return nodemailer.createTransport({
    host: process.env.MAIL_HOST || "smtp.gmail.com",
    port: Number(process.env.MAIL_PORT || 465),
    secure: Number(process.env.MAIL_PORT || 465) === 465,
    auth: {
      type: "OAuth2",
      user,
      clientId: process.env.OAUTH_CLIENT,
      clientSecret: process.env.OAUTH_SECRET,
      refreshToken: token.refresh_token,
    },
  });
}

// =========================
// File Helpers
// =========================

function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
    return true;
  } catch (e) {
    console.error("Write error:", e.message);
    return false;
  }
}

function getMails() {
  return readJSON(MAIL_FILE, []);
}
function saveMail(data) {
  const mails = getMails();
  mails.unshift(data);
  writeJSON(MAIL_FILE, mails);
}

function getMeta() {
  return readJSON(META_FILE, { important: [], read: [] });
}
function saveMeta(meta) {
  writeJSON(META_FILE, meta);
}

function getOTPs() {
  return readJSON(OTP_FILE, {});
}
function saveOTPs(otps) {
  writeJSON(OTP_FILE, otps);
}

// =========================
// OTP Helpers
// =========================

function generateOTP(length = 6) {
  return crypto.randomInt(10 ** (length - 1), 10 ** length).toString();
}

function cleanExpiredOTPs() {
  const otps = getOTPs();
  const now = Date.now();
  let changed = false;
  for (const key of Object.keys(otps)) {
    if (otps[key].expiresAt < now) {
      delete otps[key];
      changed = true;
    }
  }
  if (changed) saveOTPs(otps);
}

// =========================
// Routes — Health
// =========================

app.get("/", (req, res) => {
  res.json({ success: true, message: "Mail API running successfully" });
});

// =========================
// Google OAuth Authorization
// =========================

app.get("/v1/auth/google", (req, res) => {
  if (!process.env.OAUTH_CLIENT || !process.env.OAUTH_SECRET) {
    return res
      .status(500)
      .send("OAUTH_CLIENT and OAUTH_SECRET must be configured.");
  }
  const redirectUri = getOAuthRedirectUri(req);
  if (!redirectUri)
    return res
      .status(400)
      .send(
        "OAuth is enabled only for the configured localhost and BigOSofts domains.",
      );
  const state = crypto.randomBytes(24).toString("hex");
  oauthStates.set(state, Date.now() + 10 * 60 * 1000);
  const authorizationUrl = new URL(
    "https://accounts.google.com/o/oauth2/v2/auth",
  );
  authorizationUrl.search = new URLSearchParams({
    client_id: process.env.OAUTH_CLIENT,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: OAUTH_SCOPES.join(" "),
    access_type: "offline",
    prompt: "consent",
    state,
  }).toString();
  return res.redirect(authorizationUrl.toString());
});

app.get("/v1/auth/google/callback", async (req, res) => {
  const { code, state, error } = req.query;
  const stateExpiry = oauthStates.get(state);
  oauthStates.delete(state);
  if (error)
    return res
      .status(400)
      .send(`Google authorization failed: ${String(error)}`);
  if (!code || !stateExpiry || stateExpiry < Date.now()) {
    return res
      .status(400)
      .send(
        "Google authorization could not be verified. Restart at /v1/auth/google.",
      );
  }
  const redirectUri = getOAuthRedirectUri(req);
  if (!redirectUri)
    return res.status(400).send("OAuth callback host is not configured.");
  try {
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: String(code),
        client_id: process.env.OAUTH_CLIENT,
        client_secret: process.env.OAUTH_SECRET,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }),
    });
    const result = await response.json();
    if (!response.ok) {
      console.error(
        "Google OAuth token exchange failed:",
        result.error || response.status,
      );
      return res
        .status(502)
        .send(
          "Google authorization succeeded, but token exchange failed. Check the OAuth redirect URI and server logs.",
        );
    }
    const currentToken = getOAuthToken();
    const token = {
      refresh_token: result.refresh_token || currentToken.refresh_token,
      updated_at: new Date().toISOString(),
    };
    if (!token.refresh_token) {
      return res
        .status(502)
        .send(
          "Google did not return a refresh token. Restart authorization and approve access.",
        );
    }
    fs.writeFileSync(OAUTH_TOKEN_FILE, JSON.stringify(token, null, 2), {
      mode: 0o600,
    });
    return res.send(
      "Google mail authorization is complete. You can close this page.",
    );
  } catch (exchangeError) {
    console.error("Google OAuth callback error:", exchangeError.message);
    return res
      .status(502)
      .send(
        "Google authorization could not be completed. Check the server logs.",
      );
  }
});

// =========================
// Send Mail API
// =========================

app.post("/send-mail", async (req, res) => {
  try {
    const { to, subject, text, html } = req.body;
    if (!to || !subject)
      return res
        .status(400)
        .json({ success: false, message: "to and subject are required" });

    await createMailTransporter().sendMail({
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM}>`,
      to,
      subject,
      text,
      html,
    });

    saveMail({
      id: Date.now().toString(),
      to,
      subject,
      text,
      html,
      createdAt: new Date().toISOString(),
    });

    console.log(`Email sent to ${to}: ${subject}`);
    return res.json({ success: true, message: "Email sent successfully" });
  } catch (error) {
    console.error(`Failed to send email: ${error.message}`);
    return res.status(500).json({ success: false, message: error.message });
  }
});

// =========================
// Raw JSON Mail API
// =========================

app.get("/api/mails", (req, res) => {
  const mails = getMails();
  const meta = getMeta();
  const enriched = mails.map((m) => ({
    ...m,
    important: meta.important.includes(m.id),
    read: meta.read.includes(m.id),
  }));
  return res.json({ success: true, total: mails.length, data: enriched });
});

// Mark / Unmark Important
app.post("/api/mails/:id/important", (req, res) => {
  const { id } = req.params;
  const meta = getMeta();
  const idx = meta.important.indexOf(id);
  let isImportant;
  if (idx === -1) {
    meta.important.push(id);
    isImportant = true;
  } else {
    meta.important.splice(idx, 1);
    isImportant = false;
  }
  saveMeta(meta);
  return res.json({ success: true, important: isImportant });
});

// Mark as Read
app.post("/api/mails/:id/read", (req, res) => {
  const { id } = req.params;
  const meta = getMeta();
  if (!meta.read.includes(id)) meta.read.push(id);
  saveMeta(meta);
  return res.json({ success: true, read: true });
});

// Delete Mail
app.delete("/api/mails/:id", (req, res) => {
  const { id } = req.params;
  let mails = getMails();
  const before = mails.length;
  mails = mails.filter((m) => m.id !== id);
  writeJSON(MAIL_FILE, mails);
  const meta = getMeta();
  meta.important = meta.important.filter((i) => i !== id);
  meta.read = meta.read.filter((i) => i !== id);
  saveMeta(meta);
  return res.json({ success: true, deleted: mails.length < before });
});

// =========================
// OTP API
// =========================

// Send / Generate OTP
app.post("/api/otp/send", async (req, res) => {
  try {
    const {
      email,
      length = 6,
      expiresInMinutes = 10,
      subject,
      templateText,
    } = req.body;
    if (!email)
      return res
        .status(400)
        .json({ success: false, message: "email is required" });

    cleanExpiredOTPs();

    const otp = generateOTP(length);
    const expiresAt = Date.now() + expiresInMinutes * 60 * 1000;

    const otps = getOTPs();
    otps[email] = {
      otp,
      expiresAt,
      attempts: 0,
      createdAt: new Date().toISOString(),
    };
    saveOTPs(otps);

    // Send email if transporter configured
    const mailSubject = subject || "Your OTP Code";
    const mailText = templateText
      ? templateText
          .replace("{otp}", otp)
          .replace("{minutes}", expiresInMinutes)
      : `Your OTP code is: ${otp}\n\nThis code will expire in ${expiresInMinutes} minutes.\n\nDo not share this code with anyone.`;

    const mailHtml = `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:32px;background:#f8f9fa;border-radius:12px;">
        <h2 style="color:#1a1a2e;margin-bottom:8px;">Verification Code</h2>
        <p style="color:#555;margin-bottom:24px;">Use the code below to verify your identity. It expires in <strong>${expiresInMinutes} minutes</strong>.</p>
        <div style="background:#fff;border:2px dashed #667eea;border-radius:10px;padding:24px;text-align:center;margin-bottom:24px;">
          <span style="font-size:40px;font-weight:900;letter-spacing:12px;color:#667eea;font-family:monospace;">${otp}</span>
        </div>
        <p style="color:#888;font-size:13px;">If you didn't request this code, please ignore this email.</p>
      </div>`;

    await createMailTransporter().sendMail({
      from: `"${process.env.MAIL_FROM_NAME}" <${process.env.MAIL_FROM}>`,
      to: email,
      subject: mailSubject,
      text: mailText,
      html: mailHtml,
    });

    saveMail({
      id: Date.now().toString(),
      to: email,
      subject: mailSubject,
      text: mailText,
      html: mailHtml,
      createdAt: new Date().toISOString(),
    });

    console.log(`OTP sent to ${email}`);
    return res.json({
      success: true,
      message: `OTP sent to ${email}`,
      expiresAt: new Date(expiresAt).toISOString(),
    });
  } catch (error) {
    console.error(`OTP send error: ${error.message}`);
    return res.status(500).json({ success: false, message: error.message });
  }
});

// Verify OTP
app.post("/api/otp/verify", (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp)
      return res
        .status(400)
        .json({ success: false, message: "email and otp are required" });

    cleanExpiredOTPs();

    const otps = getOTPs();
    const record = otps[email];

    if (!record)
      return res
        .status(400)
        .json({
          success: false,
          message: "No OTP found for this email or it has expired",
        });
    if (Date.now() > record.expiresAt) {
      delete otps[email];
      saveOTPs(otps);
      return res
        .status(400)
        .json({ success: false, message: "OTP has expired" });
    }

    record.attempts = (record.attempts || 0) + 1;
    if (record.attempts > 5) {
      delete otps[email];
      saveOTPs(otps);
      return res
        .status(429)
        .json({
          success: false,
          message: "Too many attempts. OTP invalidated.",
        });
    }

    if (record.otp !== otp.toString()) {
      saveOTPs(otps);
      return res
        .status(400)
        .json({
          success: false,
          message: "Invalid OTP",
          attemptsLeft: 5 - record.attempts,
        });
    }

    delete otps[email];
    saveOTPs(otps);
    return res.json({ success: true, message: "OTP verified successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

// Resend OTP (alias — clears old, sends new)
app.post("/api/otp/resend", async (req, res) => {
  req.body._resend = true;
  // Delegate to send handler by internal call simulation
  const otps = getOTPs();
  if (otps[req.body.email]) {
    delete otps[req.body.email];
    saveOTPs(otps);
  }
  // Forward to send handler logic by re-using the route
  return app._router.handle(
    { ...req, url: "/api/otp/send", path: "/api/otp/send" },
    res,
    () => {},
  );
});

// Check OTP status (is there a valid pending OTP?)
app.get("/api/otp/status/:email", (req, res) => {
  cleanExpiredOTPs();
  const otps = getOTPs();
  const record = otps[req.params.email];
  if (!record) return res.json({ success: true, pending: false });
  return res.json({
    success: true,
    pending: true,
    expiresAt: new Date(record.expiresAt).toISOString(),
    attemptsUsed: record.attempts || 0,
  });
});

// =========================
// Mail UI — Impressive
// =========================

app.get("/mails", (req, res) => {
  const mails = getMails();
  const meta = getMeta();

  const enriched = mails.map((m) => ({
    ...m,
    important: meta.important.includes(m.id),
    read: meta.read.includes(m.id),
    textPreview: (m.text || m.subject || "").substring(0, 120),
  }));

  const mailsJSON = JSON.stringify(enriched)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>MailVault — Sent Emails</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;1,9..40,300&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#0b0e1a;
  --surface:#111527;
  --surface2:#161c35;
  --border:#1e2748;
  --border2:#252d55;
  --accent:#4f7dff;
  --accent2:#7c5cfc;
  --accent3:#00d4aa;
  --danger:#ff4d6d;
  --warn:#ffb830;
  --text:#e8ecff;
  --text2:#8892b8;
  --text3:#4a5480;
  --card-hover:#181e3a;
  --shadow:0 4px 24px rgba(0,0,0,0.45);
  --radius:14px;
}

html{scroll-behavior:smooth}

body{
  font-family:'DM Sans',sans-serif;
  background:var(--bg);
  color:var(--text);
  min-height:100vh;
  overflow-x:hidden;
}

/* Animated background */
body::before{
  content:'';
  position:fixed;
  inset:0;
  background:
    radial-gradient(ellipse 80% 50% at 20% -10%, rgba(79,125,255,0.12) 0%, transparent 60%),
    radial-gradient(ellipse 60% 40% at 85% 110%, rgba(124,92,252,0.10) 0%, transparent 60%),
    radial-gradient(ellipse 50% 30% at 50% 50%, rgba(0,212,170,0.04) 0%, transparent 70%);
  pointer-events:none;
  z-index:0;
}

.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:0 20px 60px}

/* ---- Header ---- */
header{
  padding:36px 0 28px;
  display:flex;
  align-items:center;
  justify-content:space-between;
  flex-wrap:wrap;
  gap:16px;
  border-bottom:1px solid var(--border);
  margin-bottom:32px;
}

.logo{
  display:flex;
  align-items:center;
  gap:12px;
}

.logo-icon{
  width:42px;height:42px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  font-size:20px;
  box-shadow:0 0 24px rgba(79,125,255,0.35);
}

.logo-text{
  font-family:'Syne',sans-serif;
  font-size:24px;
  font-weight:800;
  background:linear-gradient(90deg,#fff 0%,#8ba4ff 100%);
  -webkit-background-clip:text;
  -webkit-text-fill-color:transparent;
  background-clip:text;
}

.logo-sub{
  font-size:12px;
  color:var(--text3);
  font-weight:400;
  display:block;
  letter-spacing:0.05em;
  font-family:'DM Sans',sans-serif;
  -webkit-text-fill-color:var(--text3);
}

.header-stats{
  display:flex;
  gap:24px;
}

.stat{
  text-align:right;
}

.stat-num{
  font-family:'Syne',sans-serif;
  font-size:22px;
  font-weight:700;
  color:#fff;
}

.stat-label{
  font-size:11px;
  color:var(--text3);
  letter-spacing:0.06em;
  text-transform:uppercase;
}

/* ---- Toolbar ---- */
.toolbar{
  display:flex;
  gap:12px;
  flex-wrap:wrap;
  align-items:center;
  margin-bottom:20px;
}

.search-wrap{
  flex:1;
  min-width:220px;
  position:relative;
}

.search-wrap .icon{
  position:absolute;
  left:14px;
  top:50%;
  transform:translateY(-50%);
  color:var(--text3);
  font-size:15px;
  pointer-events:none;
}

input[type=search],input[type=text]{
  width:100%;
  background:var(--surface2);
  border:1.5px solid var(--border);
  border-radius:10px;
  padding:10px 14px 10px 40px;
  color:var(--text);
  font-size:14px;
  font-family:'DM Sans',sans-serif;
  outline:none;
  transition:border-color .2s,box-shadow .2s;
}

input[type=search]:focus,input[type=text]:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(79,125,255,0.15);
}

input[type=search]::placeholder{color:var(--text3)}

.filter-btns{
  display:flex;
  gap:6px;
}

.filter-btn{
  background:var(--surface2);
  border:1.5px solid var(--border);
  border-radius:8px;
  color:var(--text2);
  font-size:13px;
  font-family:'DM Sans',sans-serif;
  padding:8px 14px;
  cursor:pointer;
  transition:all .18s;
  font-weight:500;
}

.filter-btn:hover,.filter-btn.active{
  background:var(--accent);
  border-color:var(--accent);
  color:#fff;
}

.filter-btn.important-filter.active{
  background:var(--warn);
  border-color:var(--warn);
  color:#1a1a00;
}

/* ---- Per-page selector ---- */
.perpage{
  background:var(--surface2);
  border:1.5px solid var(--border);
  border-radius:8px;
  color:var(--text2);
  font-size:13px;
  font-family:'DM Sans',sans-serif;
  padding:8px 10px;
  cursor:pointer;
  outline:none;
}

/* ---- Result info ---- */
.result-info{
  font-size:13px;
  color:var(--text3);
  margin-bottom:14px;
  min-height:20px;
}

.result-info span{color:var(--text2)}

/* ---- Mail cards ---- */
#mail-list{
  display:flex;
  flex-direction:column;
  gap:10px;
}

.mail-card{
  background:var(--surface);
  border:1.5px solid var(--border);
  border-radius:var(--radius);
  padding:18px 20px;
  cursor:pointer;
  transition:all .2s;
  position:relative;
  overflow:hidden;
  animation:fadeUp .35s ease both;
}

@keyframes fadeUp{
  from{opacity:0;transform:translateY(12px)}
  to{opacity:1;transform:translateY(0)}
}

.mail-card:hover{
  background:var(--card-hover);
  border-color:var(--border2);
  transform:translateY(-2px);
  box-shadow:var(--shadow);
}

.mail-card.unread::before{
  content:'';
  position:absolute;
  left:0;top:0;bottom:0;
  width:3px;
  background:linear-gradient(180deg,var(--accent),var(--accent2));
  border-radius:2px 0 0 2px;
}

.mail-card.important-card{
  border-color:rgba(255,184,48,0.3);
}

.mail-card.important-card::after{
  content:'';
  position:absolute;
  inset:0;
  background:radial-gradient(ellipse 40% 30% at 95% 10%, rgba(255,184,48,0.06), transparent);
  pointer-events:none;
}

.card-top{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
  margin-bottom:8px;
}

.card-to{
  font-size:13px;
  color:var(--accent);
  font-weight:500;
  display:flex;
  align-items:center;
  gap:6px;
  flex-wrap:wrap;
  flex:1;
}

.badge{
  display:inline-flex;
  align-items:center;
  gap:4px;
  font-size:10px;
  padding:2px 8px;
  border-radius:20px;
  font-weight:600;
  letter-spacing:0.04em;
  text-transform:uppercase;
}

.badge-unread{background:rgba(79,125,255,0.15);color:var(--accent)}
.badge-important{background:rgba(255,184,48,0.15);color:var(--warn)}

.card-actions{
  display:flex;
  gap:6px;
  align-items:center;
  flex-shrink:0;
}

.action-btn{
  background:none;
  border:none;
  cursor:pointer;
  color:var(--text3);
  font-size:16px;
  width:30px;height:30px;
  border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  transition:all .18s;
}

.action-btn:hover{background:var(--surface2);color:var(--text)}
.action-btn.starred{color:var(--warn)}
.action-btn.del:hover{background:rgba(255,77,109,0.12);color:var(--danger)}

.card-subject{
  font-family:'Syne',sans-serif;
  font-size:15px;
  font-weight:700;
  color:var(--text);
  margin-bottom:5px;
  line-height:1.3;
}

.mail-card.read-card .card-subject{
  font-weight:600;
  color:var(--text2);
}

.card-preview{
  font-size:13px;
  color:var(--text3);
  line-height:1.5;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
  max-width:700px;
}

.card-time{
  font-size:11px;
  color:var(--text3);
  margin-top:8px;
  display:flex;
  align-items:center;
  gap:5px;
}

/* ---- Pagination ---- */
.pagination{
  display:flex;
  align-items:center;
  justify-content:center;
  gap:6px;
  margin-top:32px;
  flex-wrap:wrap;
}

.page-btn{
  background:var(--surface2);
  border:1.5px solid var(--border);
  border-radius:8px;
  color:var(--text2);
  font-size:13px;
  font-family:'Syne',sans-serif;
  font-weight:600;
  width:36px;height:36px;
  cursor:pointer;
  transition:all .18s;
  display:flex;align-items:center;justify-content:center;
}

.page-btn:hover,.page-btn.current{
  background:var(--accent);
  border-color:var(--accent);
  color:#fff;
  box-shadow:0 0 12px rgba(79,125,255,0.35);
}

.page-btn:disabled{
  opacity:0.35;
  cursor:not-allowed;
}

.page-btn.arrow{font-size:16px;font-family:sans-serif}
.page-ellipsis{color:var(--text3);padding:0 4px;line-height:36px}

/* ---- Empty state ---- */
.empty{
  text-align:center;
  padding:80px 20px;
  color:var(--text3);
}

.empty-icon{font-size:52px;margin-bottom:16px;opacity:0.4}
.empty-title{font-family:'Syne',sans-serif;font-size:18px;font-weight:700;color:var(--text2);margin-bottom:8px}
.empty-sub{font-size:14px}

/* ---- Modal ---- */
.overlay{
  display:none;
  position:fixed;
  inset:0;
  background:rgba(0,0,0,0.75);
  backdrop-filter:blur(6px);
  z-index:1000;
  align-items:center;
  justify-content:center;
  padding:20px;
}

.overlay.open{display:flex}

.modal{
  background:var(--surface);
  border:1.5px solid var(--border2);
  border-radius:20px;
  width:100%;
  max-width:680px;
  max-height:85vh;
  overflow-y:auto;
  box-shadow:0 24px 80px rgba(0,0,0,0.6);
  animation:modalIn .25s cubic-bezier(.34,1.56,.64,1) both;
}

@keyframes modalIn{
  from{opacity:0;transform:scale(0.92) translateY(20px)}
  to{opacity:1;transform:scale(1) translateY(0)}
}

.modal-header{
  padding:24px 24px 0;
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
  position:sticky;
  top:0;
  background:var(--surface);
  z-index:1;
  padding-bottom:16px;
  border-bottom:1px solid var(--border);
}

.modal-title{
  font-family:'Syne',sans-serif;
  font-size:18px;
  font-weight:800;
  color:#fff;
  line-height:1.3;
  flex:1;
}

.modal-close{
  background:var(--surface2);
  border:none;
  border-radius:8px;
  width:32px;height:32px;
  font-size:18px;
  cursor:pointer;
  color:var(--text2);
  display:flex;align-items:center;justify-content:center;
  transition:all .18s;
  flex-shrink:0;
}

.modal-close:hover{background:rgba(255,77,109,0.15);color:var(--danger)}

.modal-meta{
  padding:16px 24px;
  display:flex;
  flex-direction:column;
  gap:8px;
  border-bottom:1px solid var(--border);
}

.meta-row{
  display:flex;
  gap:8px;
  font-size:13px;
  align-items:baseline;
}

.meta-label{
  color:var(--text3);
  min-width:60px;
  font-weight:500;
}

.meta-val{color:var(--text2)}

.modal-body{
  padding:20px 24px 24px;
}

.modal-section-title{
  font-size:11px;
  text-transform:uppercase;
  letter-spacing:0.08em;
  color:var(--text3);
  font-weight:600;
  margin-bottom:10px;
}

.text-preview-box{
  background:var(--surface2);
  border:1px solid var(--border);
  border-radius:10px;
  padding:16px;
  font-size:13px;
  color:var(--text2);
  line-height:1.6;
  white-space:pre-wrap;
  word-break:break-word;
  max-height:140px;
  overflow-y:auto;
}

.html-preview-box{
  border:1px solid var(--border);
  border-radius:10px;
  overflow:hidden;
  margin-top:10px;
}

.html-preview-box iframe{
  width:100%;
  height:320px;
  background:#fff;
  border:none;
  display:block;
}

/* ---- Toast ---- */
.toast-wrap{
  position:fixed;
  bottom:24px;
  right:24px;
  z-index:9999;
  display:flex;
  flex-direction:column;
  gap:8px;
}

.toast{
  background:var(--surface2);
  border:1.5px solid var(--border2);
  border-radius:10px;
  padding:10px 16px;
  font-size:13px;
  color:var(--text);
  box-shadow:var(--shadow);
  animation:toastIn .25s ease both;
  display:flex;
  align-items:center;
  gap:8px;
  max-width:300px;
}

.toast.success{border-color:var(--accent3);color:var(--accent3)}
.toast.warn{border-color:var(--warn);color:var(--warn)}
.toast.error{border-color:var(--danger);color:var(--danger)}

@keyframes toastIn{
  from{opacity:0;transform:translateX(30px)}
  to{opacity:1;transform:translateX(0)}
}

@keyframes toastOut{
  from{opacity:1;transform:translateX(0)}
  to{opacity:0;transform:translateX(30px)}
}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--text3)}

/* Responsive */
@media(max-width:600px){
  header{flex-direction:column;align-items:flex-start}
  .card-preview{max-width:100%}
  .header-stats{gap:16px}
}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="logo">
      <div class="logo-icon">✉</div>
      <div>
        <div class="logo-text">MailVault <span class="logo-sub">Sent Email Dashboard</span></div>
      </div>
    </div>
    <div class="header-stats">
      <div class="stat">
        <div class="stat-num" id="stat-total">0</div>
        <div class="stat-label">Total Sent</div>
      </div>
      <div class="stat">
        <div class="stat-num" id="stat-unread">0</div>
        <div class="stat-label">Unread</div>
      </div>
      <div class="stat">
        <div class="stat-num" id="stat-important">0</div>
        <div class="stat-label">Important</div>
      </div>
    </div>
  </header>

  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔍</span>
      <input type="search" id="search-input" placeholder="Search by email address or content…" oninput="onSearch()"/>
    </div>
    <div class="filter-btns">
      <button class="filter-btn active" data-filter="all" onclick="setFilter('all',this)">All</button>
      <button class="filter-btn" data-filter="unread" onclick="setFilter('unread',this)">Unread</button>
      <button class="filter-btn important-filter" data-filter="important" onclick="setFilter('important',this)">⭐ Important</button>
    </div>
    <select class="perpage" id="perpage" onchange="setPerPage(this.value)">
      <option value="10">10 / page</option>
      <option value="20">20 / page</option>
      <option value="50">50 / page</option>
    </select>
  </div>

  <div class="result-info" id="result-info"></div>
  <div id="mail-list"></div>
  <div class="pagination" id="pagination"></div>

</div>

<!-- Modal -->
<div class="overlay" id="overlay" onclick="closeModal(event)">
  <div class="modal" id="modal">
    <div class="modal-header">
      <div class="modal-title" id="modal-subject">—</div>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-meta" id="modal-meta"></div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<!-- Toast container -->
<div class="toast-wrap" id="toast-wrap"></div>

<script>
const ALL_MAILS = ${mailsJSON};

let mails = [...ALL_MAILS];
let filter = 'all';
let query = '';
let page = 1;
let perPage = 10;

// Sync important/read state from allMails (source of truth per load)
// Mutations go via API and reload page or update in memory
let localMeta = {
  important: ALL_MAILS.filter(m=>m.important).map(m=>m.id),
  read: ALL_MAILS.filter(m=>m.read).map(m=>m.id),
};

function isImportant(id){ return localMeta.important.includes(id) }
function isRead(id){ return localMeta.read.includes(id) }

// ---- Stats ----
function updateStats(){
  const total = ALL_MAILS.length;
  const unread = ALL_MAILS.filter(m=>!isRead(m.id)).length;
  const imp = localMeta.important.length;
  animateNum('stat-total', total);
  animateNum('stat-unread', unread);
  animateNum('stat-important', imp);
}

function animateNum(id, target){
  const el = document.getElementById(id);
  const start = parseInt(el.textContent)||0;
  const diff = target-start;
  if(diff===0) return;
  const steps = 20;
  let i=0;
  const t = setInterval(()=>{
    i++;
    el.textContent = Math.round(start + diff*(i/steps));
    if(i>=steps){ el.textContent=target; clearInterval(t); }
  }, 16);
}

// ---- Filter & Search ----
function setFilter(f, btn){
  filter=f; page=1;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  render();
}

function onSearch(){ query=document.getElementById('search-input').value.trim().toLowerCase(); page=1; render(); }

function setPerPage(v){ perPage=parseInt(v); page=1; render(); }

function getFiltered(){
  return ALL_MAILS.filter(m=>{
    const imp = isImportant(m.id);
    const rd = isRead(m.id);
    if(filter==='unread' && rd) return false;
    if(filter==='important' && !imp) return false;
    if(query){
      const haystack = [m.to,m.subject,m.text,m.html||''].join(' ').toLowerCase();
      if(!haystack.includes(query)) return false;
    }
    return true;
  });
}

// ---- Render ----
function render(){
  const filtered = getFiltered();
  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total/perPage));
  if(page>totalPages) page=totalPages;
  const start=(page-1)*perPage, end=start+perPage;
  const slice = filtered.slice(start, end);

  // Result info
  const info = document.getElementById('result-info');
  if(total===0){
    info.innerHTML='No emails found';
  } else {
    info.innerHTML='Showing <span>'+(start+1)+'–'+Math.min(end,total)+'</span> of <span>'+total+'</span> emails'+(query?' matching <span>"'+escHtml(query)+'"</span>':'');
  }

  // Cards
  const list = document.getElementById('mail-list');
  if(slice.length===0){
    list.innerHTML='<div class="empty"><div class="empty-icon">📭</div><div class="empty-title">Nothing here</div><div class="empty-sub">Try a different filter or search term</div></div>';
  } else {
    list.innerHTML = slice.map((m,i)=>{
      const imp = isImportant(m.id);
      const rd = isRead(m.id);
      const timeStr = formatTime(m.createdAt);
      const preview = stripHtml(m.text||m.subject||'');
      return \`<div class="mail-card \${rd?'read-card':'unread'} \${imp?'important-card':''}" 
          style="animation-delay:\${i*0.04}s"
          onclick="openMail('\${m.id}')">
        <div class="card-top">
          <div class="card-to">
            📧 \${escHtml(m.to)}
            \${!rd?'<span class="badge badge-unread">New</span>':''}
            \${imp?'<span class="badge badge-important">⭐ Important</span>':''}
          </div>
          <div class="card-actions" onclick="event.stopPropagation()">
            <button class="action-btn \${imp?'starred':''}" title="\${imp?'Unmark':'Mark'} important" onclick="toggleImportant('\${m.id}',this)">
              \${imp?'⭐':'☆'}
            </button>
            <button class="action-btn del" title="Delete" onclick="deleteMail('\${m.id}',this)">🗑</button>
          </div>
        </div>
        <div class="card-subject">\${escHtml(m.subject||'(no subject)')}</div>
        <div class="card-preview">\${escHtml(preview)}</div>
        <div class="card-time">🕐 \${timeStr}</div>
      </div>\`;
    }).join('');
  }

  renderPagination(totalPages);
  updateStats();
}

function renderPagination(totalPages){
  const el = document.getElementById('pagination');
  if(totalPages<=1){ el.innerHTML=''; return; }

  let html='';
  html+=\`<button class="page-btn arrow" \${page<=1?'disabled':''} onclick="goPage(\${page-1})">‹</button>\`;

  const pages = getPageNums(page, totalPages);
  let prev=null;
  for(const p of pages){
    if(prev!==null && p-prev>1) html+='<span class="page-ellipsis">…</span>';
    html+=\`<button class="page-btn \${p===page?'current':''}" onclick="goPage(\${p})">\${p}</button>\`;
    prev=p;
  }

  html+=\`<button class="page-btn arrow" \${page>=totalPages?'disabled':''} onclick="goPage(\${page+1})">›</button>\`;
  el.innerHTML=html;
}

function getPageNums(cur, total){
  if(total<=7) return Array.from({length:total},(_,i)=>i+1);
  const s=new Set([1,2,total-1,total,cur-1,cur,cur+1].filter(p=>p>=1&&p<=total));
  return [...s].sort((a,b)=>a-b);
}

function goPage(p){ page=p; render(); window.scrollTo({top:0,behavior:'smooth'}); }

// ---- Mail Detail ----
function openMail(id){
  const m = ALL_MAILS.find(x=>x.id===id);
  if(!m) return;
  document.getElementById('modal-subject').textContent = m.subject||'(no subject)';
  document.getElementById('modal-meta').innerHTML=\`
    <div class="meta-row"><span class="meta-label">To</span><span class="meta-val">\${escHtml(m.to)}</span></div>
    <div class="meta-row"><span class="meta-label">Sent</span><span class="meta-val">\${formatTime(m.createdAt)}</span></div>
    <div class="meta-row"><span class="meta-label">Status</span><span class="meta-val">
      \${isImportant(id)?'<span style="color:var(--warn)">⭐ Important</span>&nbsp;&nbsp;':''}
      \${isRead(id)?'<span style="color:var(--text3)">Read</span>':'<span style="color:var(--accent)">● Unread</span>'}
    </span></div>
  \`;

  let body='';
  if(m.text){
    body+=\`<div class="modal-section-title">Plain Text</div><div class="text-preview-box">\${escHtml(m.text)}</div>\`;
  }
  if(m.html){
    body+=\`<div class="modal-section-title" style="margin-top:18px">HTML Preview</div>
    <div class="html-preview-box"><iframe srcdoc="\${escAttr(m.html)}" sandbox="allow-same-origin"></iframe></div>\`;
  }
  if(!body) body='<span style="color:var(--text3);font-size:13px">No content</span>';
  document.getElementById('modal-body').innerHTML=body;

  document.getElementById('overlay').classList.add('open');

  // Mark read
  if(!isRead(id)){
    localMeta.read.push(id);
    fetch('/api/mails/'+id+'/read',{method:'POST'}).catch(()=>{});
    render();
  }
}

function closeModal(e){
  if(!e || e.target===document.getElementById('overlay')){
    document.getElementById('overlay').classList.remove('open');
  }
}

// ---- Actions ----
async function toggleImportant(id, btn){
  try{
    const res = await fetch('/api/mails/'+id+'/important',{method:'POST'});
    const data = await res.json();
    if(data.success){
      if(data.important){ localMeta.important.push(id); toast('Marked as important ⭐','warn'); }
      else { localMeta.important=localMeta.important.filter(i=>i!==id); toast('Removed from important','success'); }
      render();
    }
  }catch(e){ toast('Failed to update','error'); }
}

async function deleteMail(id, btn){
  if(!confirm('Delete this email record?')) return;
  try{
    const res = await fetch('/api/mails/'+id,{method:'DELETE'});
    const data = await res.json();
    if(data.success){
      const idx = ALL_MAILS.findIndex(m=>m.id===id);
      if(idx!==-1) ALL_MAILS.splice(idx,1);
      localMeta.important=localMeta.important.filter(i=>i!==id);
      localMeta.read=localMeta.read.filter(i=>i!==id);
      toast('Email deleted','success');
      render();
    }
  }catch(e){ toast('Delete failed','error'); }
}

// ---- Utils ----
function escHtml(str){
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escAttr(str){
  return String(str||'').replace(/"/g,'&quot;');
}
function stripHtml(str){
  return String(str||'').replace(/<[^>]*>/g,'').replace(/\\s+/g,' ').trim();
}
function formatTime(iso){
  try{
    const d=new Date(iso);
    const now=new Date();
    const diff=now-d;
    if(diff<60000) return 'Just now';
    if(diff<3600000) return Math.floor(diff/60000)+'m ago';
    if(diff<86400000) return Math.floor(diff/3600000)+'h ago';
    if(diff<604800000) return Math.floor(diff/86400000)+'d ago';
    return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric',hour:'2-digit',minute:'2-digit'});
  }catch{return iso||''}
}

function toast(msg, type='success'){
  const wrap = document.getElementById('toast-wrap');
  const t = document.createElement('div');
  t.className='toast '+type;
  t.innerHTML = (type==='success'?'✓':type==='warn'?'⭐':'✕')+' '+escHtml(msg);
  wrap.appendChild(t);
  setTimeout(()=>{
    t.style.animation='toastOut .25s ease forwards';
    setTimeout(()=>t.remove(),300);
  },2800);
}

// Keyboard shortcuts
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeModal();
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){ e.preventDefault(); document.getElementById('search-input').focus(); }
});

// Init
render();
updateStats();
</script>
</body>
</html>`;

  res.send(html);
});

// =========================
// Start Server
// =========================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Mail UI:  http://localhost:${PORT}/mails`);
  console.log(`Mail API: http://localhost:${PORT}/api/mails`);
  console.log(`OTP Send: POST http://localhost:${PORT}/api/otp/send`);
  console.log(`OTP Verify: POST http://localhost:${PORT}/api/otp/verify`);
});
