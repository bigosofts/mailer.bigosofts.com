require("dotenv").config();

const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

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

function normalizeRecipients(value) {
  const input = Array.isArray(value) ? value.join(",") : String(value || "");
  const recipients = input.split(/[\s,;]+/).map((email) => email.trim()).filter(Boolean);
  const unique = new Map();
  for (const email of recipients) {
    if (/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(email)) {
      unique.set(email.toLowerCase(), email);
    }
  }
  return [...unique.values()];
}

function hasInvalidRecipients(value) {
  const input = Array.isArray(value) ? value.join(",") : String(value || "");
  return input.split(/[\s,;]+/).map((email) => email.trim()).filter(Boolean)
    .some((email) => !/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(email));
}

app.post("/send-mail", async (req, res) => {
  try {
    const { to, subject, text, html } = req.body;
    const recipients = normalizeRecipients(to);
    if (!recipients.length || hasInvalidRecipients(to) || !subject || (!text && !html))
      return res
        .status(400)
        .json({ success: false, message: "Valid recipients, a subject, and message content are required" });
    if (recipients.length > 100)
      return res.status(400).json({ success: false, message: "You can send to a maximum of 100 recipients per batch" });

    const transporter = createMailTransporter();
    const sent = [];
    const failed = [];
    for (const recipient of recipients) {
      try {
        await transporter.sendMail({
          from: `"${process.env.MAIL_FROM_NAME || "Mailer"}" <${process.env.MAIL_FROM}>`,
          to: recipient,
          subject,
          text: text || undefined,
          html: html || undefined,
        });
        saveMail({
          id: `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          to: recipient,
          subject,
          text: text || "",
          html: html || "",
          createdAt: new Date().toISOString(),
        });
        sent.push(recipient);
      } catch (sendError) {
        failed.push({ to: recipient, error: sendError.message });
      }
    }
    transporter.close();
    console.log(`Email batch finished: ${sent.length}/${recipients.length} sent`);
    return res.status(failed.length ? 207 : 200).json({
      success: failed.length === 0,
      message: failed.length ? `${sent.length} sent; ${failed.length} failed` : `Email sent to ${sent.length} recipient${sent.length === 1 ? "" : "s"}`,
      total: recipients.length,
      sent,
      failed,
    });
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

.header-actions{display:flex;align-items:center;gap:20px}
.compose-trigger,.send-btn,.secondary-btn,.tool-btn,.palette-item,.block-action{
  font:inherit;cursor:pointer;transition:all .18s;
}
.compose-trigger,.send-btn{
  border:0;border-radius:10px;padding:11px 17px;color:#fff;font-weight:700;
  background:linear-gradient(120deg,var(--accent),var(--accent2));
  box-shadow:0 8px 24px rgba(79,125,255,.22);
}
.compose-trigger:hover,.send-btn:hover{filter:brightness(1.1);transform:translateY(-1px)}
.compose-overlay{display:none;position:fixed;inset:0;z-index:1200;background:rgba(4,7,18,.82);backdrop-filter:blur(8px);padding:18px;align-items:center;justify-content:center}
.compose-overlay.open{display:flex}
.compose-window{width:min(1440px,100%);height:min(920px,96vh);background:#0e1324;border:1px solid var(--border2);border-radius:18px;box-shadow:0 28px 100px rgba(0,0,0,.65);display:flex;flex-direction:column;overflow:hidden}
.compose-head{padding:17px 22px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);flex-shrink:0}
.compose-head h2{font:700 20px 'Syne',sans-serif;color:#fff}
.compose-head p{font-size:12px;color:var(--text3);margin-top:3px}
.compose-close{border:0;border-radius:8px;background:var(--surface2);color:var(--text2);width:36px;height:36px;font-size:20px;cursor:pointer}
.compose-fields{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:16px 20px;border-bottom:1px solid var(--border);flex-shrink:0}
.compose-field{display:flex;flex-direction:column;gap:6px;min-width:0}
.compose-field.to-field{grid-column:1/-1}
.compose-field label{color:var(--text2);font-size:12px;font-weight:700;letter-spacing:.03em}
.compose-field input,.compose-field textarea{width:100%;border:1px solid var(--border2);border-radius:9px;background:#090d19;color:var(--text);font:14px 'DM Sans',sans-serif;padding:10px 12px;outline:none}
.compose-field textarea{height:58px;resize:vertical}
.compose-field input:focus,.compose-field textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,125,255,.12)}
.compose-hint{font-size:11px;color:var(--text3)}
.compose-workspace{display:grid;grid-template-columns:176px minmax(300px,1fr) minmax(310px,42%);gap:14px;padding:14px;min-height:0;flex:1}
.builder-palette,.builder-panel,.preview-panel{border:1px solid var(--border);border-radius:12px;background:#111729;min-height:0;overflow:hidden}
.builder-palette{padding:14px;overflow-y:auto}
.panel-label{font-size:10px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--text3);margin:2px 0 12px}
.palette-list{display:flex;flex-direction:column;gap:8px}
.palette-item{border:1px solid var(--border);background:#171e32;color:var(--text2);border-radius:8px;padding:10px;text-align:left;font-size:12px}
.palette-item:hover{border-color:var(--accent);color:#fff;background:#1b2748}
.palette-note{font-size:10px;line-height:1.5;color:var(--text3);margin-top:14px}
.builder-panel,.preview-panel{display:flex;flex-direction:column}
.panel-toolbar{padding:10px 12px;display:flex;align-items:center;justify-content:space-between;gap:8px;border-bottom:1px solid var(--border);flex-shrink:0}
.tool-group{display:flex;gap:6px;flex-wrap:wrap}
.tool-btn,.secondary-btn{border:1px solid var(--border2);border-radius:7px;background:#1a2034;color:var(--text2);padding:7px 9px;font-size:11px}
.tool-btn:hover,.secondary-btn:hover{border-color:var(--accent);color:#fff}
.builder-canvas-wrap{padding:15px;overflow:auto;flex:1;background:#0a0e1a}
.builder-canvas{min-height:100%;max-width:650px;margin:0 auto;background:#fff;border-radius:4px;padding:36px 34px;color:#18243a;box-shadow:0 8px 28px rgba(0,0,0,.22)}
.builder-canvas.drop-target{outline:3px dashed #7692ff;outline-offset:-8px}
.canvas-empty{color:#7b8494;text-align:center;border:1px dashed #cbd2de;padding:40px 18px;border-radius:9px;font-size:13px}
.email-block{position:relative;border:1px solid transparent;border-radius:5px;padding:8px 7px;margin:0 0 5px;cursor:grab}
.email-block:hover,.email-block.selected{border-color:#9db2ff;background:#f6f8ff}
.email-block.dragging{opacity:.4}
.block-bar{position:absolute;top:-9px;right:0;display:none;align-items:center;gap:4px;background:#202b49;color:#dbe4ff;border-radius:6px;padding:3px 5px;font:10px 'DM Sans',sans-serif;z-index:2}
.email-block:hover .block-bar,.email-block.selected .block-bar{display:flex}
.block-action{border:0;background:transparent;color:#dbe4ff;font-size:10px;padding:2px 4px}
.block-action:hover{color:#fff}
.email-editable{outline:none;min-height:1em;white-space:pre-wrap;word-break:break-word}
.email-editable:empty:before{content:attr(data-placeholder);color:#aab1bf}
.email-editable[data-kind="title"]{font:700 13px 'DM Sans',sans-serif;color:#5c6c84}
.email-editable[data-kind="heading"]{font:700 28px/1.2 'Syne',sans-serif;color:#19243a}
.email-editable[data-kind="paragraph"],.email-editable[data-kind="footer"]{font:15px/1.65 'DM Sans',sans-serif;color:#536176}
.email-editable[data-kind="button"]{display:inline-block;background:#4263eb;color:#fff;border-radius:6px;padding:11px 19px;font:700 13px 'DM Sans',sans-serif;min-width:120px;text-align:center}
.email-image-preview{display:block;max-width:100%;max-height:180px;object-fit:contain;margin:0 auto}
.image-missing{padding:25px;background:#edf1f8;color:#69768c;text-align:center;border-radius:5px;font-size:12px}
.divider-preview{border:0;border-top:1px solid #d9dfeb;margin:12px 0}
.spacer-preview{height:22px;background:repeating-linear-gradient(135deg,#f0f2f6,#f0f2f6 6px,#fafbfc 6px,#fafbfc 12px);border:1px dashed #cbd2de}
.preview-title{font-size:12px;color:var(--text2);font-weight:700}
.preview-frame{border:0;background:#fff;width:100%;height:100%;min-height:250px;flex:1}
.editor-mode-tabs{display:flex;gap:4px;min-width:0}
.mode-btn{border:1px solid transparent;border-radius:7px;background:transparent;color:var(--text3);font:600 10px 'DM Sans',sans-serif;padding:7px 8px;cursor:pointer;white-space:nowrap}
.mode-btn:hover{color:#fff;background:#1a2034}
.mode-btn.active{color:#fff;background:#26375f;border-color:#384f84}
.builder-canvas-wrap[hidden],.rich-editor-wrap[hidden],.html-editor-wrap[hidden]{display:none!important}
.rich-editor-wrap,.html-editor-wrap{min-height:0;flex:1;display:flex;flex-direction:column;overflow:hidden;background:#0a0e1a}
.rich-toolbar{display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding:9px;border-bottom:1px solid var(--border);background:#111729}
.rich-tool{border:1px solid var(--border2);border-radius:6px;background:#1a2034;color:var(--text2);height:29px;min-width:29px;padding:0 7px;font:600 12px 'DM Sans',sans-serif;cursor:pointer}
.rich-tool:hover{border-color:var(--accent);color:#fff}
.rich-toolbar select{height:29px;max-width:105px;background:#1a2034;border:1px solid var(--border2);border-radius:6px;color:var(--text2);font:11px 'DM Sans',sans-serif}
.rich-toolbar input[type=color]{width:30px;height:29px;border:1px solid var(--border2);border-radius:6px;background:#1a2034;padding:3px;cursor:pointer}
.rich-editable{margin:18px auto;padding:34px;max-width:650px;width:calc(100% - 36px);min-height:480px;background:#fff;border-radius:5px;color:#17243b;outline:none;overflow:auto;font:16px/1.6 Arial,sans-serif}
.rich-editable:focus{box-shadow:0 0 0 2px #7893ff}
.html-source{width:calc(100% - 28px);height:calc(100% - 56px);min-height:300px;flex:1;resize:none;margin:14px;border:1px solid var(--border2);border-radius:8px;background:#080c16;color:#c4d4ff;padding:14px;font:12px/1.55 Consolas,'Courier New',monospace;tab-size:2;outline:none}
.html-source:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,125,255,.12)}
.html-source-hint{font-size:10px;color:var(--text3);padding:0 14px 12px}
.custom-html-frame{display:block;width:100%;height:220px;border:1px solid #d6dce8;background:#fff}
.custom-html-note{font:11px 'DM Sans',sans-serif;color:#67738a;padding:8px 4px}
.compose-footer{padding:12px 20px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-shrink:0}
.send-status{font-size:12px;color:var(--text2);min-width:0}
.send-status.error{color:#ff879a}.send-status.success{color:#6de4c2}
.send-btn:disabled{opacity:.5;cursor:wait;transform:none}
@media(max-width:1000px){.compose-workspace{grid-template-columns:140px minmax(260px,1fr)}.preview-panel{display:none}}
@media(max-width:650px){.compose-overlay{padding:0}.compose-window{height:100vh;border-radius:0}.compose-fields{grid-template-columns:1fr}.compose-field.to-field{grid-column:auto}.compose-workspace{grid-template-columns:105px minmax(0,1fr);padding:8px;gap:8px}.builder-palette{padding:8px}.builder-canvas{padding:28px 18px}.palette-item{padding:8px 6px;font-size:11px}.compose-footer{align-items:flex-start;flex-direction:column}.compose-trigger{padding:9px 12px}.header-actions{gap:10px}}
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
    <div class="header-actions">
      <button class="compose-trigger" onclick="openComposer()">＋ Compose</button>
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

<!-- Compose and drag/drop email builder -->
<div class="compose-overlay" id="compose-overlay" aria-hidden="true">
  <section class="compose-window" role="dialog" aria-modal="true" aria-labelledby="compose-title">
    <div class="compose-head">
      <div><h2 id="compose-title">Create an email</h2><p>Compose a message or build a polished HTML design</p></div>
      <button class="compose-close" onclick="closeComposer()" aria-label="Close composer">×</button>
    </div>
    <div class="compose-fields">
      <div class="compose-field to-field">
        <label for="compose-to">Recipients</label>
        <textarea id="compose-to" placeholder="name@example.com, another@example.com" oninput="updateRecipientCount()"></textarea>
        <div class="compose-hint"><span id="recipient-count">0 recipients</span> · separate addresses with commas, spaces, semicolons, or new lines · up to 100 per send</div>
      </div>
      <div class="compose-field">
        <label for="compose-subject">Subject</label>
        <input id="compose-subject" type="text" maxlength="180" placeholder="A thoughtful subject line"/>
      </div>
      <div class="compose-field">
        <label for="compose-preheader">Preview text <span style="color:var(--text3);font-weight:400">(optional)</span></label>
        <input id="compose-preheader" type="text" maxlength="160" placeholder="A short line shown in the inbox preview" oninput="updateEmailPreview()"/>
      </div>
    </div>
    <div class="compose-workspace">
      <aside class="builder-palette">
        <div class="panel-label">Drag blocks</div>
        <div class="palette-list">
          <button class="palette-item" draggable="true" data-block="title">✦ Eyebrow</button>
          <button class="palette-item" draggable="true" data-block="heading">▤ Heading</button>
          <button class="palette-item" draggable="true" data-block="paragraph">≡ Paragraph</button>
          <button class="palette-item" draggable="true" data-block="button">▣ Button</button>
          <button class="palette-item" draggable="true" data-block="image">▧ Image</button>
          <button class="palette-item" draggable="true" data-block="divider">— Divider</button>
          <button class="palette-item" draggable="true" data-block="spacer">↕ Spacer</button>
          <button class="palette-item" draggable="true" data-block="footer">⌑ Footer</button>
        </div>
        <p class="palette-note">Click or drag items into the canvas. Drag canvas blocks to reorder. Click text to edit it.</p>
      </aside>
      <section class="builder-panel">
        <div class="panel-toolbar">
          <div class="editor-mode-tabs" role="tablist" aria-label="Email editor mode">
            <button class="mode-btn active" id="mode-builder" onclick="setEditorMode('builder')">Blocks</button>
            <button class="mode-btn" id="mode-rich" onclick="setEditorMode('rich')">Rich text</button>
            <button class="mode-btn" id="mode-html" onclick="setEditorMode('html')">HTML</button>
          </div>
          <div class="tool-group" id="builder-tools">
            <button class="tool-btn" onclick="loadStarterTemplate()">Use starter</button>
            <button class="tool-btn" onclick="clearEmailCanvas()">Clear</button>
          </div>
        </div>
        <div class="builder-canvas-wrap">
          <div class="builder-canvas" id="builder-canvas" ondragover="allowCanvasDrop(event)" ondrop="dropOnCanvas(event)"></div>
        </div>
        <div class="rich-editor-wrap" id="rich-editor-wrap" hidden>
          <div class="rich-toolbar" aria-label="Rich text formatting">
            <button class="rich-tool" title="Bold" onclick="richCommand('bold')"><b>B</b></button>
            <button class="rich-tool" title="Italic" onclick="richCommand('italic')"><i>I</i></button>
            <button class="rich-tool" title="Underline" onclick="richCommand('underline')"><u>U</u></button>
            <button class="rich-tool" title="Strikethrough" onclick="richCommand('strikeThrough')"><s>S</s></button>
            <select aria-label="Text size" onchange="richCommand('fontSize',this.value)"><option value="3">Normal</option><option value="5">Large</option><option value="7">Title</option></select>
            <input type="color" aria-label="Text color" value="#17243b" onchange="richCommand('foreColor',this.value)"/>
            <button class="rich-tool" title="Bulleted list" onclick="richCommand('insertUnorderedList')">• List</button>
            <button class="rich-tool" title="Numbered list" onclick="richCommand('insertOrderedList')">1. List</button>
            <button class="rich-tool" title="Align left" onclick="richCommand('justifyLeft')">⇤</button>
            <button class="rich-tool" title="Center" onclick="richCommand('justifyCenter')">≡</button>
            <button class="rich-tool" title="Add link" onclick="richAddLink()">↗ Link</button>
            <button class="rich-tool" title="Add image" onclick="richAddImage()">▧ Image</button>
            <button class="rich-tool" title="Undo" onclick="richCommand('undo')">↶</button>
            <button class="rich-tool" title="Redo" onclick="richCommand('redo')">↷</button>
          </div>
          <div class="rich-editable" id="rich-editor" contenteditable="true" spellcheck="true" oninput="alternateEditorInput()"></div>
        </div>
        <div class="html-editor-wrap" id="html-editor-wrap" hidden>
          <textarea class="html-source" id="html-source" spellcheck="false" aria-label="Email HTML source" oninput="alternateEditorInput()"></textarea>
          <div class="html-source-hint">Edit the complete email HTML. Scripts, embedded frames, forms, and event handlers are removed before preview and sending.</div>
        </div>
      </section>
      <section class="preview-panel">
        <div class="panel-toolbar"><span class="preview-title">Inbox-ready preview</span></div>
        <iframe class="preview-frame" id="email-preview" title="Email preview" sandbox=""></iframe>
      </section>
    </div>
    <div class="compose-footer">
      <div class="send-status" id="send-status" role="status">Each recipient receives a separate email.</div>
      <button class="send-btn" id="send-button" onclick="sendComposedEmail()">Send email</button>
    </div>
  </section>
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

// ---- Compose and HTML email builder ----
let emailBlockSequence = 0;
let activeDraggedBlock = null;
let editorMode = 'builder';
let alternateEditorDirty = false;
let savedRichRange = null;

function sanitizeEmailHtml(source){
  const parsed=new DOMParser().parseFromString(String(source||''),'text/html');
  parsed.querySelectorAll('script,iframe,object,embed,form,meta[http-equiv="refresh"]').forEach(node=>node.remove());
  parsed.querySelectorAll('*').forEach(node=>{
    Array.from(node.attributes).forEach(attribute=>{
      const name=attribute.name.toLowerCase();
      const value=attribute.value.trim().toLowerCase();
      if(name.startsWith('on')||((name==='href'||name==='src'||name==='xlink:href')&&value.startsWith('javascript:')))node.removeAttribute(attribute.name);
    });
  });
  return '<!doctype html><html>'+parsed.documentElement.innerHTML+'</html>';
}

function emailBodyForEditor(source){
  const parsed=new DOMParser().parseFromString(sanitizeEmailHtml(source),'text/html');
  const styles=Array.from(parsed.head.querySelectorAll('style')).map(style=>style.outerHTML).join('');
  const editable=parsed.querySelector('[data-mailer-content]');
  return styles+(editable?editable.innerHTML:parsed.body.innerHTML);
}

function buildRichEmailHtml(){
  const content=document.getElementById('rich-editor').innerHTML;
  const preheader=escapeEmailText(document.getElementById('compose-preheader').value);
  return '<!doctype html><html><body style="margin:0;padding:0;background:#f3f5f9"><div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">'+preheader+'</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f3f5f9;padding:28px 12px"><tr><td align="center"><table role="presentation" width="600" cellspacing="0" cellpadding="0" style="width:100%;max-width:600px;background:#fff;border-radius:12px;padding:34px 38px"><tr><td><div data-mailer-content="true">'+content+'</div></td></tr></table></td></tr></table></body></html>';
}

function getCurrentEmailHtml(){
  if(editorMode==='rich')return buildRichEmailHtml();
  if(editorMode==='html')return document.getElementById('html-source').value;
  return buildEmailHtml();
}

function setEditorMode(mode){
  if(mode===editorMode)return;
  const priorMode=editorMode;
  const currentHtml=getCurrentEmailHtml();
  if(mode==='builder'){
    if(priorMode!=='builder'&&alternateEditorDirty){
      const canvas=document.getElementById('builder-canvas');canvas.innerHTML='';
      addEmailBlock('customHtml','',{html:sanitizeEmailHtml(currentHtml)});
    }
    alternateEditorDirty=false;
  }else if(mode==='rich'){
    document.getElementById('rich-editor').innerHTML=emailBodyForEditor(currentHtml);
    if(priorMode==='builder')alternateEditorDirty=false;
  }else if(mode==='html'){
    document.getElementById('html-source').value=currentHtml;
    if(priorMode==='builder')alternateEditorDirty=false;
  }
  editorMode=mode;
  document.getElementById('rich-editor-wrap').hidden=mode!=='rich';
  document.getElementById('html-editor-wrap').hidden=mode!=='html';
  document.querySelector('.builder-canvas-wrap').hidden=mode!=='builder';
  document.getElementById('builder-tools').style.display=mode==='builder'?'flex':'none';
  document.querySelectorAll('.mode-btn').forEach(button=>button.classList.remove('active'));
  document.getElementById(mode==='builder'?'mode-builder':mode==='rich'?'mode-rich':'mode-html').classList.add('active');
  updateEmailPreview();
}

function resetComposerEditorState(){
  editorMode='builder';alternateEditorDirty=false;savedRichRange=null;
  document.getElementById('rich-editor').innerHTML='';
  document.getElementById('html-source').value='';
  document.getElementById('rich-editor-wrap').hidden=true;
  document.getElementById('html-editor-wrap').hidden=true;
  document.querySelector('.builder-canvas-wrap').hidden=false;
  document.getElementById('builder-tools').style.display='flex';
  document.querySelectorAll('.mode-btn').forEach(button=>button.classList.remove('active'));
  document.getElementById('mode-builder').classList.add('active');
  clearEmailCanvas();
}

function alternateEditorInput(){alternateEditorDirty=true;updateEmailPreview();}

function richCommand(command,value){
  const editor=document.getElementById('rich-editor');editor.focus();restoreRichSelection();
  document.execCommand(command,false,value||null);
  rememberRichSelection();
  alternateEditorInput();
}

function rememberRichSelection(){
  const editor=document.getElementById('rich-editor');
  const selection=window.getSelection();
  if(selection&&selection.rangeCount&&editor.contains(selection.anchorNode))savedRichRange=selection.getRangeAt(0).cloneRange();
}

function restoreRichSelection(){
  if(!savedRichRange)return;
  const selection=window.getSelection();selection.removeAllRanges();selection.addRange(savedRichRange);
}

function richAddLink(){
  rememberRichSelection();
  const value=window.prompt('Enter a full https:// or http:// link, or a mailto: address');
  if(value===null)return;
  const safe=safeEmailUrl(value,false);
  if(!safe){toast('Enter a valid web link or mailto address','error');return;}
  richCommand('createLink',safe);
}

function richAddImage(){
  rememberRichSelection();
  const value=window.prompt('Enter a public image URL starting with https://');
  if(value===null)return;
  const safe=safeEmailUrl(value,true);
  if(!safe){toast('Enter a valid http or https image URL','error');return;}
  richCommand('insertImage',safe);
}

function openComposer(){
  document.getElementById('compose-overlay').classList.add('open');
  document.getElementById('compose-overlay').setAttribute('aria-hidden','false');
  if(!document.querySelector('#builder-canvas .email-block')) loadStarterTemplate();
  updateRecipientCount();
  updateEmailPreview();
  document.getElementById('compose-to').focus();
}

function closeComposer(){
  document.getElementById('compose-overlay').classList.remove('open');
  document.getElementById('compose-overlay').setAttribute('aria-hidden','true');
}

function parseComposerRecipients(){
  const raw=document.getElementById('compose-to').value.split(/[\\s,;]+/).map(x=>x.trim()).filter(Boolean);
  const valid=raw.filter(x=>/^[^\\s@,;<>]+@[^\\s@,;<>]+\\.[^\\s@,;<>]+$/.test(x));
  const unique=Array.from(new Map(valid.map(x=>[x.toLowerCase(),x])).values());
  return {raw,valid:unique,invalid:raw.filter(x=>!/^([^\\s@,;<>]+)@([^\\s@,;<>]+)\\.([^\\s@,;<>]+)$/.test(x))};
}

function updateRecipientCount(){
  const parsed=parseComposerRecipients();
  document.getElementById('recipient-count').textContent=parsed.valid.length+' recipient'+(parsed.valid.length===1?'':'s')+(parsed.invalid.length?' · '+parsed.invalid.length+' invalid':'');
  const button=document.getElementById('send-button');
  button.textContent=parsed.valid.length>1?'Send to '+parsed.valid.length+' recipients':'Send email';
}

function makeEditable(kind,text,placeholder){
  const el=document.createElement('div');
  el.className='email-editable';
  el.contentEditable='true';
  el.spellcheck=true;
  el.dataset.kind=kind;
  el.dataset.placeholder=placeholder||'Click to edit';
  el.textContent=text||'';
  el.addEventListener('input',updateEmailPreview);
  return el;
}

function addEmailBlock(type,text,options,beforeNode){
  const settings=options||{};
  const canvas=document.getElementById('builder-canvas');
  canvas.querySelector('.canvas-empty')?.remove();
  const block=document.createElement('div');
  block.className='email-block';
  block.draggable=true;
  block.dataset.blockType=type;
  block.dataset.blockId='email-block-'+(++emailBlockSequence);
  block.dataset.href=settings.href||'';
  block.dataset.src=settings.src||'';
  block.dataset.alt=settings.alt||'';
  block.dataset.html=settings.html||'';

  const bar=document.createElement('div');
  bar.className='block-bar';
  const handle=document.createElement('span');
  handle.textContent='⠿ '+type;
  bar.appendChild(handle);
  if(type==='button'||type==='image'){
    const editLink=document.createElement('button');
    editLink.type='button'; editLink.className='block-action';
    editLink.textContent=type==='image'?'Image URL':'Button link';
    editLink.addEventListener('click',event=>{event.stopPropagation();editBlockLink(block);});
    bar.appendChild(editLink);
  }
  const remove=document.createElement('button');
  remove.type='button'; remove.className='block-action'; remove.textContent='Remove';
  remove.addEventListener('click',event=>{event.stopPropagation();block.remove();showCanvasEmpty();updateEmailPreview();});
  bar.appendChild(remove);
  block.appendChild(bar);

  if(type==='title') block.appendChild(makeEditable('title',text||'A NOTE FROM BIGOSOFTS','Small intro line'));
  else if(type==='heading') block.appendChild(makeEditable('heading',text||'Your headline goes here','Write a clear, welcoming headline'));
  else if(type==='paragraph') block.appendChild(makeEditable('paragraph',text||'Add your message here. Click to edit this paragraph.','Write your message'));
  else if(type==='footer') block.appendChild(makeEditable('footer',text||'You are receiving this email from BigOSofts.','Add footer details'));
  else if(type==='button') block.appendChild(makeEditable('button',text||'Read more','Button label'));
  else if(type==='image'){
    const imgWrap=document.createElement('div');
    if(block.dataset.src){
      const img=document.createElement('img'); img.className='email-image-preview'; img.src=block.dataset.src; img.alt=block.dataset.alt; imgWrap.appendChild(img);
    }else{imgWrap.className='image-missing';imgWrap.textContent='Click “Image URL” to add a hosted image';}
    block.appendChild(imgWrap);
  }else if(type==='divider'){
    const hr=document.createElement('hr');hr.className='divider-preview';block.appendChild(hr);
  }else if(type==='spacer'){
    const spacer=document.createElement('div');spacer.className='spacer-preview';block.appendChild(spacer);
  }else if(type==='customHtml'){
    const frame=document.createElement('iframe');frame.className='custom-html-frame';frame.setAttribute('sandbox','');frame.title='Custom HTML block preview';frame.srcdoc=sanitizeEmailHtml(block.dataset.html);
    block.appendChild(frame);
    const note=document.createElement('div');note.className='custom-html-note';note.textContent='Custom HTML from the rich text or HTML editor';block.appendChild(note);
  }

  block.addEventListener('click',()=>{
    canvas.querySelectorAll('.email-block.selected').forEach(node=>node.classList.remove('selected'));
    block.classList.add('selected');
  });
  if(beforeNode) canvas.insertBefore(block,beforeNode); else canvas.appendChild(block);
  block.querySelector('[contenteditable="true"]')?.focus();
  updateEmailPreview();
  return block;
}

function showCanvasEmpty(){
  const canvas=document.getElementById('builder-canvas');
  if(!canvas.querySelector('.email-block')){
    const empty=document.createElement('div');empty.className='canvas-empty';
    empty.textContent='Drag a block here, or choose “Use starter” to begin with a polished email layout.';
    canvas.appendChild(empty);
  }
}

function addPaletteBlock(type){
  if(type==='image'){
    const url=window.prompt('Enter a public image URL starting with https://');
    if(!url)return;
    const safe=safeEmailUrl(url,true);
    if(!safe){toast('Enter a valid http or https image URL','error');return;}
    addEmailBlock('image','',{src:safe,alt:'Email image'});
    return;
  }
  addEmailBlock(type,'',type==='button'?{href:'https://www.bigosofts.com'}:{});
}

function clearEmailCanvas(){
  document.getElementById('builder-canvas').innerHTML='';
  showCanvasEmpty();
  updateEmailPreview();
}

function loadStarterTemplate(){
  const canvas=document.getElementById('builder-canvas');
  canvas.innerHTML='';
  addEmailBlock('title','A NOTE FROM BIGOSOFTS');
  addEmailBlock('heading','A little good news');
  addEmailBlock('paragraph','We have something new to share. Here is the latest from our team. Edit this message, add your own blocks, and make it yours.');
  addEmailBlock('button','See what is new',{href:'https://www.bigosofts.com'});
  addEmailBlock('divider');
  addEmailBlock('footer','You are receiving this email because you have a relationship with BigOSofts.');
  const subject=document.getElementById('compose-subject');
  if(!subject.value) subject.value='A quick update from BigOSofts';
  updateEmailPreview();
}

function safeEmailUrl(value,imageOnly){
  const raw=String(value||'').trim();
  try{
    const url=new URL(raw);
    if(url.protocol==='https:'||url.protocol==='http:') return url.href;
  }catch(e){}
  if(!imageOnly&&/^mailto:[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/i.test(raw)) return raw;
  return '';
}

function editBlockLink(block){
  if(block.dataset.blockType==='image'){
    const current=block.dataset.src||'';
    const url=window.prompt('Enter a public image URL starting with https://',current);
    if(url===null)return;
    const safe=safeEmailUrl(url,true);
    if(!safe){toast('Enter a valid http or https image URL','error');return;}
    block.dataset.src=safe;
    block.dataset.alt=window.prompt('Enter image alt text',block.dataset.alt||'')||'';
    const wrap=block.querySelector('div:not(.block-bar)');wrap.className='';wrap.textContent='';
    const img=document.createElement('img');img.className='email-image-preview';img.src=safe;img.alt=block.dataset.alt;wrap.appendChild(img);
  }else{
    const url=window.prompt('Enter a full https:// or http:// link, or a mailto: address',block.dataset.href||'https://www.bigosofts.com');
    if(url===null)return;
    const safe=safeEmailUrl(url,false);
    if(!safe){toast('Enter a valid web link or mailto address','error');return;}
    block.dataset.href=safe;
  }
  updateEmailPreview();
}

function allowCanvasDrop(event){
  event.preventDefault();
  const effect=event.dataTransfer.effectAllowed;
  event.dataTransfer.dropEffect=effect==='copy'?'copy':'move';
  document.getElementById('builder-canvas').classList.add('drop-target');
}

function dropOnCanvas(event){
  event.preventDefault();
  const canvas=document.getElementById('builder-canvas');canvas.classList.remove('drop-target');
  const target=event.target.closest('.email-block');
  const box=target?target.getBoundingClientRect():null;
  const insertBefore=target&&event.clientY<box.top+box.height/2?target:(target?target.nextSibling:null);
  const plain=event.dataTransfer.getData('text/plain');
  const moveId=event.dataTransfer.getData('application/x-email-move')||(plain.startsWith('move:')?plain.slice(5):'');
  const blockType=event.dataTransfer.getData('application/x-email-block')||(plain.startsWith('block:')?plain.slice(6):'');
  if(moveId){
    const moving=document.querySelector('[data-block-id="'+CSS.escape(moveId)+'"]');
    if(moving&&moving!==target) canvas.insertBefore(moving,insertBefore);
    updateEmailPreview();
  }else if(blockType){
    if(blockType==='image'){
      const url=window.prompt('Enter a public image URL starting with https://');
      if(!url){return;}
      const safe=safeEmailUrl(url,true);
      if(!safe){toast('Enter a valid http or https image URL','error');return;}
      addEmailBlock('image','',{src:safe,alt:'Email image'},insertBefore);
    }else addEmailBlock(blockType,'',blockType==='button'?{href:'https://www.bigosofts.com'}:{},insertBefore);
  }
}

function escapeEmailText(value){return String(value||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function blockEmailHtml(block){
  const type=block.dataset.blockType;
  if(type==='customHtml'){
    const parsed=new DOMParser().parseFromString(sanitizeEmailHtml(block.dataset.html||''),'text/html');
    const styles=Array.from(parsed.head.querySelectorAll('style')).map(style=>style.outerHTML).join('');
    const editable=parsed.querySelector('[data-mailer-content]');
    return styles+(editable?editable.innerHTML:parsed.body.innerHTML);
  }
  const text=block.querySelector('[contenteditable="true"]')?.innerText||'';
  const escaped=escapeEmailText(text).replace(/\\n/g,'<br>');
  if(type==='title')return '<p style="margin:0;color:#66758d;font:700 11px Arial,sans-serif;letter-spacing:2px;text-transform:uppercase">'+escaped+'</p>';
  if(type==='heading')return '<h1 style="margin:0;color:#17243b;font:700 30px/1.2 Arial,sans-serif">'+escaped+'</h1>';
  if(type==='paragraph')return '<p style="margin:0;color:#516078;font:16px/1.65 Arial,sans-serif">'+escaped+'</p>';
  if(type==='footer')return '<p style="margin:0;color:#7b8799;font:12px/1.6 Arial,sans-serif">'+escaped+'</p>';
  if(type==='button'){
    const url=safeEmailUrl(block.dataset.href,false)||'https://www.bigosofts.com';
    return '<a href="'+escapeEmailText(url)+'" style="display:inline-block;background:#4263eb;color:#fff;text-decoration:none;font:700 14px Arial,sans-serif;padding:13px 22px;border-radius:6px">'+escaped+'</a>';
  }
  if(type==='image'){
    const url=safeEmailUrl(block.dataset.src,true);
    return url?'<img src="'+escapeEmailText(url)+'" alt="'+escapeEmailText(block.dataset.alt)+'" width="560" style="display:block;width:100%;max-width:560px;height:auto;border:0">':'';
  }
  if(type==='divider')return '<hr style="border:0;border-top:1px solid #e2e7ef;margin:0">';
  if(type==='spacer')return '<div style="height:24px;line-height:24px;font-size:1px">&nbsp;</div>';
  return '';
}

function buildEmailHtml(){
  const blocks=Array.from(document.querySelectorAll('#builder-canvas .email-block'));
  const rows=blocks.map(block=>'<div style="padding:10px 0">'+blockEmailHtml(block)+'</div>').join('');
  const preheader=escapeEmailText(document.getElementById('compose-preheader').value);
  return '<!doctype html><html><body style="margin:0;padding:0;background:#f3f5f9"><div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">'+preheader+'</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f3f5f9;padding:28px 12px"><tr><td align="center"><table role="presentation" width="600" cellspacing="0" cellpadding="0" style="width:100%;max-width:600px;background:#fff;border-radius:12px;padding:34px 38px"><tr><td><div data-mailer-content="true">'+rows+'</div></td></tr></table></td></tr></table></body></html>';
}

function updateEmailPreview(){
  const frame=document.getElementById('email-preview');
  if(frame)frame.srcdoc=sanitizeEmailHtml(getCurrentEmailHtml());
}

function buildPlainText(){
  return Array.from(document.querySelectorAll('#builder-canvas .email-block')).map(block=>{
    if(block.dataset.blockType==='divider')return '—'.repeat(24);
    if(block.dataset.blockType==='image')return block.dataset.alt||'[image]';
    if(block.dataset.blockType==='spacer')return '';
    if(block.dataset.blockType==='customHtml')return new DOMParser().parseFromString(block.dataset.html||'','text/html').body.innerText||'';
    const text=block.querySelector('[contenteditable="true"]')?.innerText||'';
    return block.dataset.blockType==='button'?text+' ('+(block.dataset.href||'')+')':text;
  }).filter(Boolean).join('\\n\\n');
}

function setSendStatus(message,type){
  const status=document.getElementById('send-status');status.textContent=message;status.className='send-status'+(type?' '+type:'');
}

async function sendComposedEmail(){
  const parsed=parseComposerRecipients();
  const subject=document.getElementById('compose-subject').value.trim();
  const blocks=document.querySelectorAll('#builder-canvas .email-block');
  if(parsed.invalid.length){setSendStatus('Fix invalid addresses: '+parsed.invalid.join(', '),'error');return;}
  if(!parsed.valid.length){setSendStatus('Add at least one valid recipient.','error');return;}
  if(parsed.valid.length>100){setSendStatus('This batch exceeds the 100 recipient limit.','error');return;}
  if(!subject){setSendStatus('Add a subject before sending.','error');document.getElementById('compose-subject').focus();return;}
  if(!blocks.length){setSendStatus('Add at least one content block.','error');return;}
  if(parsed.valid.length>1&&!window.confirm('Send this email to '+parsed.valid.length+' recipients? Each person receives a separate email.'))return;

  const button=document.getElementById('send-button');button.disabled=true;
  setSendStatus('Sending '+parsed.valid.length+' email'+(parsed.valid.length===1?'':'s')+'…','');
  const html=sanitizeEmailHtml(getCurrentEmailHtml());
  const text=editorMode==='builder'?buildPlainText():new DOMParser().parseFromString(html,'text/html').body.innerText||'';
  try{
    const response=await fetch('/send-mail',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to:parsed.valid,subject,text,html})});
    const result=await response.json();
    const sent=Array.isArray(result.sent)?result.sent:[];
    const now=new Date().toISOString();
    sent.forEach((recipient,index)=>ALL_MAILS.unshift({id:'local-'+Date.now()+'-'+index,to:recipient,subject,text,html,createdAt:now,important:false,read:false}));
    if(result.failed&&result.failed.length){
      document.getElementById('compose-to').value=result.failed.map(item=>item.to).join(', ');
      updateRecipientCount();
      setSendStatus(result.sent.length+' sent; '+result.failed.length+' failed. Failed addresses remain in Recipients.','error');
      toast(result.sent.length+' sent; '+result.failed.length+' failed','error');
    }else if(response.ok&&result.success){
      render();setSendStatus(result.message,'success');toast(result.message,'success');
      closeComposer();
      document.getElementById('compose-to').value='';
      document.getElementById('compose-subject').value='';
      document.getElementById('compose-preheader').value='';
      resetComposerEditorState();
    }else{
      setSendStatus(result.message||'The message could not be sent.','error');
      toast(result.message||'The message could not be sent','error');
    }
  }catch(error){
    setSendStatus('Could not reach the mail server: '+error.message,'error');
    toast('Could not reach the mail server','error');
  }finally{button.disabled=false;updateRecipientCount();}
}

document.querySelectorAll('.palette-item').forEach(item=>{
  item.addEventListener('click',()=>addPaletteBlock(item.dataset.block));
  item.addEventListener('dragstart',event=>{
    event.dataTransfer.setData('application/x-email-block',item.dataset.block);
    event.dataTransfer.setData('text/plain','block:'+item.dataset.block);
    event.dataTransfer.effectAllowed='copy';
  });
});
document.querySelectorAll('.rich-tool,.rich-toolbar select,.rich-toolbar input').forEach(control=>control.addEventListener('mousedown',rememberRichSelection));
document.getElementById('rich-editor').addEventListener('keyup',rememberRichSelection);
document.getElementById('rich-editor').addEventListener('mouseup',rememberRichSelection);
document.getElementById('builder-canvas').addEventListener('dragstart',event=>{
  const block=event.target.closest('.email-block');
  if(!block||event.target.closest('[contenteditable="true"]')){event.preventDefault();return;}
  activeDraggedBlock=block;event.dataTransfer.setData('application/x-email-move',block.dataset.blockId);event.dataTransfer.setData('text/plain','move:'+block.dataset.blockId);event.dataTransfer.effectAllowed='move';
  requestAnimationFrame(()=>block.classList.add('dragging'));
});
document.getElementById('builder-canvas').addEventListener('dragend',()=>{
  document.querySelectorAll('.email-block.dragging').forEach(block=>block.classList.remove('dragging'));
  document.getElementById('builder-canvas').classList.remove('drop-target');activeDraggedBlock=null;
});

// Keyboard shortcuts
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){ closeModal(); closeComposer(); }
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
