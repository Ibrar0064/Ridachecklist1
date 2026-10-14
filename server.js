const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const port = Number(process.env.PORT || 10000);
const indexFile = path.join(__dirname, "index.html");
const SUPABASE_URL = (process.env.SUPABASE_URL || "https://mlaeaeuwxzavdioozxgi.supabase.co").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const INITIAL_DRIVER_PASSWORD = process.env.DRIVER_PASSWORD || "";
const FORMSPREE_URL = "https://formspree.io/f/xaeyknoa";
const sessions = new Map();
const loginAttempts = new Map();
const SESSION_MS = 8 * 60 * 60 * 1000;
const MAX_BODY = 64 * 1024;

function configured() {
  return Boolean(ADMIN_PASSWORD && INITIAL_DRIVER_PASSWORD && SUPABASE_SERVICE_ROLE_KEY && SUPABASE_URL);
}
function json(res, status, value, extraHeaders = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extraHeaders });
  res.end(JSON.stringify(value));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_BODY) {
        reject(Object.assign(new Error("Request is too large."), { statusCode: 413 }));
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { reject(Object.assign(new Error("Invalid request."), { statusCode: 400 })); }
    });
    req.on("error", reject);
  });
}
function timingSafeStringEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function makePasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return salt + ":" + hash;
}
function verifyPasswordHash(password, stored) {
  if (typeof stored !== "string" || !stored.includes(":")) return false;
  const [salt, expected] = stored.split(":");
  try {
    const actual = crypto.scryptSync(password, salt, 64).toString("hex");
    return timingSafeStringEqual(actual, expected);
  } catch { return false; }
}
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").map(part => part.trim()).filter(Boolean).map(part => {
    const i = part.indexOf("=");
    return i < 0 ? [part, ""] : [part.slice(0, i), decodeURIComponent(part.slice(i + 1))];
  }));
}
function currentSession(req) {
  const token = cookies(req).rida_session;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}
function cookieHeader(token, maxAge) {
  return "rida_session=" + encodeURIComponent(token) + "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=" + maxAge;
}
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const host = req.headers.host;
  const expected = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim() + "://" + host;
  return origin === expected;
}
async function supabaseRequest(pathname, options = {}) {
  const response = await fetch(SUPABASE_URL + pathname, {
    ...options,
    headers: {
      "apikey": SUPABASE_SERVICE_ROLE_KEY,
      "Authorization": "Bearer " + SUPABASE_SERVICE_ROLE_KEY,
      ...(options.headers || {})
    }
  });
  return response;
}
async function getDriverPasswordHash() {
  const response = await supabaseRequest("/rest/v1/app_security_settings?id=eq.1&select=driver_password_hash", { headers: { "Accept": "application/json" } });
  if (!response.ok) throw new Error("Unable to check password settings in the database.");
  const rows = await response.json();
  return rows.length ? rows[0].driver_password_hash : null;
}
async function checkDriverPassword(password) {
  const storedHash = await getDriverPasswordHash();
  return storedHash ? verifyPasswordHash(password, storedHash) : timingSafeStringEqual(password, INITIAL_DRIVER_PASSWORD);
}
function limited(ip) {
  const now = Date.now();
  const prior = loginAttempts.get(ip) || { count: 0, until: now + 15 * 60 * 1000 };
  if (prior.until <= now) {
    loginAttempts.set(ip, { count: 1, until: now + 15 * 60 * 1000 });
    return false;
  }
  if (prior.count >= 10) return true;
  prior.count += 1;
  loginAttempts.set(ip, prior);
  return false;
}
function securityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
}
function sendHtml(res, headOnly = false) {
  fs.readFile(indexFile, (error, content) => {
    if (error) {
      res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Unable to load checklist.");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(headOnly ? undefined : content);
  });
}
function formspreeBody(data) {
  const params = new URLSearchParams();
  const fields = {
    company: "Rida International Travel & Tourism",
    form_type: "Driver & Vehicle Daily Checklist",
    current_date: data.submission_date,
    current_time: data.submission_time,
    _subject: "Driver & Vehicle Checklist - Rida International Travel & Tourism",
    vehicle_number: data.vehicle_number,
    driver_name: data.driver_name,
    driver_hygiene: data.driver_hygiene,
    interior_cleanliness: data.interior_cleanliness,
    exterior_cleanliness: data.exterior_cleanliness,
    interior_damage: data.interior_damage,
    exterior_damage: data.exterior_damage,
    tyres_condition: data.tyres_condition,
    ac_cooling: data.ac_cooling,
    radiator_water: data.radiator_water,
    engine_oil: data.engine_oil,
    clutch_condition: data.clutch_condition,
    fuel_status: data.fuel_status,
    driver_comments: data.driver_comments || ""
  };
  for (const [key, value] of Object.entries(fields)) if (value !== undefined && value !== null) params.append(key, String(value));
  for (const belt of (Array.isArray(data.belts) ? data.belts : [])) params.append("belts", String(belt));
  return params;
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  const url = new URL(req.url || "/", "http://localhost");
  const pathname = url.pathname;
  const session = currentSession(req);

  try {
    if (pathname === "/api/session" && (req.method === "GET" || req.method === "HEAD")) {
      json(res, 200, { configured: configured(), authenticated: Boolean(session), role: session ? session.role : null });
      return;
    }

    if (pathname === "/api/login" && req.method === "POST") {
      if (!configured()) {
        json(res, 503, { error: "Security setup is not complete. Please ask the administrator to finish setup in Render." });
        return;
      }
      if (!originAllowed(req)) {
        json(res, 403, { error: "Request blocked." });
        return;
      }
      const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();
      if (limited(ip)) {
        json(res, 429, { error: "Too many attempts. Please wait 15 minutes and try again." });
        return;
      }
      const body = await readBody(req);
      const password = typeof body.password === "string" ? body.password : "";
      if (!password || password.length > 200) {
        json(res, 401, { error: "Incorrect password." });
        return;
      }
      let role = null;
      if (timingSafeStringEqual(password, ADMIN_PASSWORD)) role = "admin";
      else if (await checkDriverPassword(password)) role = "driver";
      if (!role) {
        json(res, 401, { error: "Incorrect password." });
        return;
      }
      loginAttempts.delete(ip);
      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, { role, expiresAt: Date.now() + SESSION_MS });
      json(res, 200, { ok: true, role }, { "Set-Cookie": cookieHeader(token, Math.floor(SESSION_MS / 1000)) });
      return;
    }

    if (pathname === "/api/logout" && req.method === "POST") {
      if (session) sessions.delete(session.token);
      json(res, 200, { ok: true }, { "Set-Cookie": cookieHeader("", 0) });
      return;
    }

    if (pathname === "/api/admin/driver-password" && req.method === "POST") {
      if (!session || session.role !== "admin") {
        json(res, 401, { error: "Administrator login required." });
        return;
      }
      if (!originAllowed(req)) {
        json(res, 403, { error: "Request blocked." });
        return;
      }
      const body = await readBody(req);
      const newPassword = typeof body.password === "string" ? body.password : "";
      if (newPassword.length < 10 || newPassword.length > 200) {
        json(res, 400, { error: "Use a driver password of at least 10 characters." });
        return;
      }
      const hash = makePasswordHash(newPassword);
      const response = await supabaseRequest("/rest/v1/app_security_settings?on_conflict=id", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Prefer": "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ id: 1, driver_password_hash: hash, updated_at: new Date().toISOString() })
      });
      if (!response.ok) {
        json(res, 500, { error: "Could not save the new password. Check the server's Supabase secret configuration." });
        return;
      }
      for (const [token, entry] of sessions.entries()) if (entry.role === "driver") sessions.delete(token);
      json(res, 200, { ok: true, message: "Driver password changed. Drivers must sign in again." });
      return;
    }

    if (pathname === "/api/checklist" && req.method === "POST") {
      if (!session) {
        json(res, 401, { error: "Your session expired. Please sign in again." });
        return;
      }
      if (!originAllowed(req)) {
        json(res, 403, { error: "Request blocked." });
        return;
      }
      const data = await readBody(req);
      const required = ["vehicle_number", "driver_name", "driver_hygiene", "interior_cleanliness", "exterior_cleanliness", "interior_damage", "exterior_damage", "tyres_condition", "ac_cooling", "radiator_water", "engine_oil", "clutch_condition", "fuel_status", "submission_date", "submission_time"];
      if (required.some(key => typeof data[key] !== "string" || !data[key].trim()) || !Array.isArray(data.belts) || data.belts.length === 0) {
        json(res, 400, { error: "Please complete all required checklist fields and check at least one belt item." });
        return;
      }
      const payload = {
        company: "Rida International Travel & Tourism",
        form_type: "Driver & Vehicle Daily Checklist",
        submission_date: data.submission_date,
        submission_time: data.submission_time,
        vehicle_number: data.vehicle_number.trim().slice(0, 100),
        driver_name: data.driver_name.trim().slice(0, 150),
        driver_hygiene: data.driver_hygiene,
        interior_cleanliness: data.interior_cleanliness,
        exterior_cleanliness: data.exterior_cleanliness,
        interior_damage: data.interior_damage,
        exterior_damage: data.exterior_damage,
        tyres_condition: data.tyres_condition,
        ac_cooling: data.ac_cooling,
        radiator_water: data.radiator_water,
        belts: data.belts.map(v => String(v).slice(0, 100)),
        engine_oil: data.engine_oil,
        clutch_condition: data.clutch_condition,
        fuel_status: data.fuel_status,
        driver_comments: typeof data.driver_comments === "string" ? data.driver_comments.trim().slice(0, 5000) || null : null
      };
      const [dbResult, emailResult] = await Promise.allSettled([
        supabaseRequest("/rest/v1/driver_vehicle_checklists", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Prefer": "return=minimal" },
          body: JSON.stringify(payload)
        }),
        fetch(FORMSPREE_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
          body: formspreeBody(payload)
        })
      ]);
      const saved = dbResult.status === "fulfilled" && dbResult.value.ok;
      const emailed = emailResult.status === "fulfilled" && emailResult.value.ok;
      if (!saved) {
        json(res, 502, { error: emailed ? "The email was sent, but database saving failed. Please contact the administrator before resubmitting." : "Submission failed. Please check your connection and try again." });
        return;
      }
      json(res, 200, { ok: true, emailDelivered: emailed });
      return;
    }

    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Allow": "GET, HEAD" });
      res.end("Method Not Allowed");
      return;
    }
    if (pathname !== "/" && pathname !== "/index.html") {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not Found");
      return;
    }
    sendHtml(res, req.method === "HEAD");
  } catch (error) {
    console.error("Request failed:", error.message);
    if (!res.headersSent) json(res, error.statusCode || 500, { error: error.statusCode === 413 ? "Request is too large." : "Server error. Please try again or contact the administrator." });
    else res.end();
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log("Rida Checklist listening on port " + port);
});
