// server.js
// Node 18+ (uses global fetch). Minimal deps: express, compression, dotenv
const express = require("express");
const compression = require("compression");
const path = require("path");
const crypto = require("crypto");

require("dotenv").config();

const app = express();
app.use(compression());
app.use(express.json());

// Small helper to enrich error messages coming from undici/fetch
function formatError(err) {
  const base = err && err.message ? String(err.message) : "Unknown error";
  const code = err && err.cause && err.cause.code ? ` (${err.cause.code})` : "";
  return base + code;
}

// Helper: perform a Shopware search with a retry toggling multi operator case
async function searchWithRetry(pathname, criteria, reqId) {
  // First try as-is
  try {
    return await shopwareFetch(pathname, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
      body: JSON.stringify(criteria),
    });
  } catch (e) {
    const msg = String(e && e.message || "");
    // Retry only on 400 Bad Request, which often indicates operator casing incompatibility
    if (!msg.startsWith("400 ")) throw e;
    try {
      const original = JSON.stringify(criteria);
      // Toggle between "or" and "OR" for multi filter operator occurrences
      const toggled = original
        .replace(/"operator":"or"/g, '"operator":"OR"')
        .replace(/"operator":"OR"/g, '"operator":"or"');
      if (toggled === original) throw e;
      return await shopwareFetch(pathname, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
        body: toggled,
      });
    } catch (e2) {
      throw e; // keep original error context
    }
  }
}

// ----------- Logger -----------
const LOG_LEVEL = (process.env.LOG_LEVEL || "info").toLowerCase();
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3, trace: 4 };
function shouldLog(level) {
  return (LEVELS[level] ?? 2) <= (LEVELS[LOG_LEVEL] ?? 2);
}
function log(level, msg, meta) {
  if (!shouldLog(level)) return;
  const ts = new Date().toISOString();
  const base = { ts, level, msg };
  if (meta && Object.keys(meta).length) console.log(JSON.stringify({ ...base, ...meta }));
  else console.log(JSON.stringify(base));
}

// Request logging with correlation id
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  const reqId = req.headers["x-request-id"] || crypto.randomUUID();
  res.setHeader("X-Request-ID", reqId);
  req.id = String(reqId);
  const { method, url, headers } = req;
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString();
  const ua = headers["user-agent"] || "";

  let bodyPreview;
  try {
    if (req.is && req.is("application/json") && typeof req.body === "object" && req.body) {
      const clone = JSON.parse(JSON.stringify(req.body));
      if (clone.password) clone.password = "***";
      bodyPreview = clone;
    }
  } catch {}

  log("info", "req", { reqId, method, url, ip, ua, body: bodyPreview });

  res.on("finish", () => {
    const durMs = Number(process.hrtime.bigint() - start) / 1e6;
    const status = res.statusCode;
    const len = res.getHeader("Content-Length");
    log("info", "res", { reqId, status, durMs: Math.round(durMs), bytes: Number(len) || 0 });
  });
  next();
});

// ----------- Config -----------
const PORT = process.env.PORT || 5173;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || "changeme";
const SHOPWARE_BASE_URL = (
  process.env.SHOPWARE_BASE_URL || "http://localhost:8000"
).replace(/\/$/, "");
const ADMIN_BASE = SHOPWARE_BASE_URL.endsWith("/api")
  ? SHOPWARE_BASE_URL
  : `${SHOPWARE_BASE_URL}/api`;
let adminBase = ADMIN_BASE;
let adminBaseProbed = false;

function toggleApiSuffix(base) {
  return base.endsWith("/api") ? base.slice(0, -4) : `${base}/api`;
}
const SHOPWARE_CLIENT_ID = process.env.SHOPWARE_CLIENT_ID || "";
const SHOPWARE_CLIENT_SECRET = process.env.SHOPWARE_CLIENT_SECRET || "";
const SHOP_NAME = process.env.SHOP_NAME || "Shop";
const ENABLE_INVOICE_ACTIONS = !["0", "false", "off"].includes(String(process.env.ENABLE_INVOICE_ACTIONS || "true").toLowerCase());
const ENABLE_ORDER_NUMBER_RESERVE = !["0", "false", "off"].includes(String(process.env.ENABLE_ORDER_NUMBER_RESERVE || "true").toLowerCase());
const ENABLE_ORDER_CONFIRMATION_EMAIL = ["1", "true", "on"].includes(String(process.env.ENABLE_ORDER_CONFIRMATION_EMAIL || "false").toLowerCase());

if (!SHOPWARE_CLIENT_ID || !SHOPWARE_CLIENT_SECRET) {
  console.warn(
    "[WARN] Missing SHOPWARE_CLIENT_ID/SHOPWARE_CLIENT_SECRET. Set them in .env"
  );
}

// Helper: ISO 8601 with local offset (e.g., 2025-09-09T10:31:00+02:00)
function toLocalOffsetIso(date) {
  const d = date instanceof Date ? date : new Date(date);
  const pad = (n) => String(n).padStart(2, "0");
  const y = d.getFullYear();
  const m = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const hh = pad(d.getHours());
  const mm = pad(d.getMinutes());
  const ss = pad(d.getSeconds());
  const tz = -d.getTimezoneOffset(); // minutes east of UTC
  const sign = tz >= 0 ? "+" : "-";
  const tzh = pad(Math.floor(Math.abs(tz) / 60));
  const tzm = pad(Math.abs(tz) % 60);
  return `${y}-${m}-${day}T${hh}:${mm}:${ss}${sign}${tzh}:${tzm}`;
}

// ----------- Tiny session (cookie) -----------
const activeSessions = new Set();
const COOKIE_NAME = "auth";

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return header.split(";").reduce((acc, cur) => {
    const [k, ...v] = cur.trim().split("=");
    if (!k) return acc;
    acc[k] = decodeURIComponent(v.join("="));
    return acc;
  }, {});
}

function setCookie(res, name, value, maxAgeSeconds) {
  const attrs = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (process.env.NODE_ENV === "production") attrs.push("Secure");
  if (maxAgeSeconds) attrs.push(`Max-Age=${maxAgeSeconds}`);
  res.setHeader("Set-Cookie", attrs.join("; "));
}

function clearCookie(res, name) {
  res.setHeader(
    "Set-Cookie",
    `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`
  );
}

function requireAuth(req, res, next) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (token && activeSessions.has(token)) return next();
  res.status(401).json({ ok: false, error: "Unauthorized" });
}

// ----------- Shopware OAuth token cache -----------
let tokenCache = { token: null, exp: 0 };

async function getShopwareToken() {
  const now = Date.now();
  if (tokenCache.token && now < tokenCache.exp - 10000) return tokenCache.token;

  const tokenUrl = `${adminBase}/oauth/token`;
  log("debug", "oauth.request", { url: tokenUrl, grant: "client_credentials" });
  let resp;
  try {
    resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: SHOPWARE_CLIENT_ID,
        client_secret: SHOPWARE_CLIENT_SECRET,
      }),
    });
  } catch (e) {
    log("error", "oauth.network_error", { url: tokenUrl, err: formatError(e) });
    throw e;
  }
  if (!resp.ok) {
    const t = await resp.text();
    // Try toggling /api suffix once if 404 and we haven't probed yet
    if (resp.status === 404 && !adminBaseProbed) {
      const altBase = toggleApiSuffix(adminBase);
      const altUrl = `${altBase}/oauth/token`;
      log("warn", "oauth.retry_alt_base", { from: adminBase, to: altBase, url: altUrl });
      adminBaseProbed = true;
      try {
        const altResp = await fetch(altUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_type: "client_credentials",
            client_id: SHOPWARE_CLIENT_ID,
            client_secret: SHOPWARE_CLIENT_SECRET,
          }),
        });
        if (!altResp.ok) {
          const altTxt = await altResp.text();
          log("error", "oauth.error_alt", { status: altResp.status, body: altTxt.slice(0, 500) });
          throw new Error(`OAuth token error: ${altResp.status} ${altTxt}`);
        }
        const altJson = await altResp.json();
        adminBase = altBase; // switch to working base
        tokenCache.token = altJson.access_token;
        tokenCache.exp = Date.now() + (altJson.expires_in || 600) * 1000;
        log("info", "admin_base_switched", { adminBase });
        log("debug", "oauth.success", { expiresIn: altJson.expires_in });
        return tokenCache.token;
      } catch (e) {
        // fall through after logging
        log("error", "oauth.retry_alt_base_failed", { err: formatError(e) });
        throw e;
      }
    }
    log("error", "oauth.error", { status: resp.status, body: t.slice(0, 500) });
    throw new Error(`OAuth token error: ${resp.status} ${t}`);
  }
  const j = await resp.json();
  tokenCache.token = j.access_token;
  tokenCache.exp = Date.now() + (j.expires_in || 600) * 1000;
  log("debug", "oauth.success", { expiresIn: j.expires_in });
  return tokenCache.token;
}

async function shopwareFetch(pathname, options = {}) {
  const token = await getShopwareToken();
  const headers = Object.assign(
    { Authorization: `Bearer ${token}`, Accept: "application/json" },
    options.headers || {}
  );
  const url = `${adminBase}${pathname}`;
  const started = Date.now();
  const bodyLen = options.body ? (typeof options.body === "string" ? options.body.length : undefined) : 0;
  log("debug", "shopware.request", { url, method: (options.method || "GET").toUpperCase(), bodyLen });
  let resp;
  try {
    resp = await fetch(url, { ...options, headers });
  } catch (e) {
    log("error", "shopware.network_error", { url, err: formatError(e) });
    throw new Error(`Upstream fetch failed: ${formatError(e)}`);
  }
  if (!resp.ok) {
    const txt = await resp.text();
    log("error", "shopware.response", { url, status: resp.status, durMs: Date.now() - started, body: txt.slice(0, 1000) });
    throw new Error(`${resp.status} ${txt}`);
  }
  log("debug", "shopware.response", { url, status: resp.status, durMs: Date.now() - started });
  return resp.json();
}

// ----------- Auth endpoints -----------
app.post("/api/login", (req, res) => {
  const { password } = req.body || {};
  if (!password || password !== DASHBOARD_PASSWORD) {
    return res.status(401).json({ ok: false, error: "Invalid password" });
  }
  const token = crypto.randomUUID();
  activeSessions.add(token);
  setCookie(res, COOKIE_NAME, token, 60 * 60 * 24 * 30); // 30 days
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const token = parseCookies(req)[COOKIE_NAME];
  if (token) activeSessions.delete(token);
  clearCookie(res, COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const token = parseCookies(req)[COOKIE_NAME];
  res.json({ ok: token ? activeSessions.has(token) : false });
});

// ----------- Protected API -----------
app.get("/api/products", requireAuth, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const limit = Math.min(
    50,
    Math.max(1, parseInt(req.query.limit || "20", 10))
  );
  const q = (req.query.q || "").trim();

  const criteria = {
    page,
    limit,
    sort: [{ field: "createdAt", order: "DESC" }],
    associations: {
      manufacturer: {},
      cover: { associations: { media: {} } },
    },
    "total-count-mode": "exact",
    filter: [],
  };
  if (q) {
    criteria.filter.push({ type: "contains", field: "name", value: q });
  }

  try {
    const sw = await shopwareFetch("/search/product", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(criteria),
    });

    const items = (sw.data || []).map((p) => ({
      id: p.id,
      name: p.name,
      productNumber: p.productNumber,
      stock: p.stock,
      active: p.active,
      price: Array.isArray(p.price) ? p.price[0]?.gross ?? null : null,
      manufacturer: p.manufacturer?.name || null,
      img: p.cover?.media?.url || null,
      createdAt: p.createdAt,
    }));

    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || items.length, data: items });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/products", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

app.get("/api/products/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  const criteria = {
    page: 1,
    limit: 1,
    associations: {
      manufacturer: {},
      cover: { associations: { media: {} } },
    },
    filter: [{ type: "equals", field: "id", value: id }],
  };

  try {
    const sw = await shopwareFetch("/search/product", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(criteria),
    });
    const p = (sw.data || [])[0];
    if (!p) return res.status(404).json({ error: "Product not found" });

    const out = {
      id: p.id,
      name: p.name,
      productNumber: p.productNumber,
      stock: p.stock,
      active: p.active,
      price: Array.isArray(p.price) ? p.price[0]?.gross ?? null : null,
      manufacturer: p.manufacturer?.name || null,
      img: p.cover?.media?.url || null,
      createdAt: p.createdAt,
      updatedAt: p.updatedAt,
    };
    res.set("Cache-Control", "no-store");
    res.json({ data: out });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/products/:id", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

app.get("/api/orders", requireAuth, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const limit = Math.min(
    50,
    Math.max(1, parseInt(req.query.limit || "20", 10))
  );
  const q = (req.query.q || "").trim();

  const filters = [];
  if (q) {
    filters.push({
      type: "multi",
      operator: "or",
      queries: [
        { type: "contains", field: "orderNumber", value: q },
        { type: "contains", field: "orderCustomer.email", value: q },
      ],
    });
  }

  const criteria = {
    page,
    limit,
    sort: [{ field: "createdAt", order: "DESC" }],
    associations: { stateMachineState: {}, currency: {}, orderCustomer: {} },
    "total-count-mode": "exact",
    filter: filters,
  };

  try {
    const sw = await searchWithRetry("/search/order", criteria, req.id);

    const items = (sw.data || []).map((o) => {
      const state = o.stateMachineState?.name || null;
      const stateColor =
        state && /cancel|fail|refus|declin/i.test(state) ? "bad" : "ok";
      return {
        id: o.id,
        orderNumber: o.orderNumber,
        createdAt: o.createdAt,
        amountTotal: o.amountTotal,
        currency: o.currency?.isoCode || "EUR",
        customerEmail: o.orderCustomer?.email || null,
        state,
        stateColor,
      };
    });

    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || items.length, data: items });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/orders", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Create a new order
app.post("/api/orders", requireAuth, async (req, res) => {
  const reqId = req.id;
  try {
    const body = req.body || {};
    const { customerId, customer, paymentMethodId, items } = body;
    let { salesChannelId, currencyId, languageId, shippingMethodId } = body;
    const shippingCostsOverride = Number(body.shippingCosts ?? 0) || 0;

    if (!paymentMethodId) {
      return res.status(400).json({ error: "paymentMethodId is required" });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "items array is required" });
    }
    if (!customerId && !customer) {
      return res.status(400).json({ error: "customerId or customer object is required" });
    }

    function hex32() {
      return crypto.randomBytes(16).toString("hex");
    }

    async function getDefaultSalesChannel() {
      if (salesChannelId) {
        try {
          const sc = await shopwareFetch(`/sales-channel/${encodeURIComponent(salesChannelId)}`);
          return sc && sc.data ? sc.data : sc;
        } catch (e) {
          // fall through to search
        }
      }
      const r = await shopwareFetch("/search/sales-channel", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
        body: JSON.stringify({
          page: 1,
          limit: 1,
          sort: [{ field: "createdAt", order: "ASC" }],
          filter: [{ type: "equals", field: "active", value: true }],
        }),
      });
      const sc = (r && r.data && r.data[0]) || null;
      if (!sc) throw new Error("No active sales channel found");
      return sc;
    }

    async function getCurrency(curId) {
      const c = await shopwareFetch(`/currency/${encodeURIComponent(curId)}`);
      return c && c.data ? c.data : c;
    }

    async function getStateId(machineTechnicalName, technicalName) {
      const r = await shopwareFetch("/search/state-machine-state", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
        body: JSON.stringify({
          page: 1,
          limit: 1,
          filter: [
            { type: "equals", field: "technicalName", value: technicalName },
            { type: "equals", field: "stateMachine.technicalName", value: machineTechnicalName },
          ],
        }),
      });
      const st = (r && r.data && r.data[0]) || null;
      if (!st) throw new Error(`State '${technicalName}' not found for ${machineTechnicalName}`);
      return st.id;
    }

    async function getDefaultSalutationId() {
      // Try not_specified then mr, else fallback to first
      for (const key of ["not_specified", "mr"]) {
        try {
          const r = await shopwareFetch("/search/salutation", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
            body: JSON.stringify({ page: 1, limit: 1, filter: [{ type: "equals", field: "salutationKey", value: key }] }),
          });
          if (r && r.data && r.data[0]) return r.data[0].id;
        } catch {}
      }
      const r = await shopwareFetch("/search/salutation", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
        body: JSON.stringify({ page: 1, limit: 1 }),
      });
      if (r && r.data && r.data[0]) return r.data[0].id;
      throw new Error("No salutation found");
    }

    async function getSalutationIdByKey(key) {
      try {
        const r = await shopwareFetch("/search/salutation", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
          body: JSON.stringify({ page: 1, limit: 1, filter: [{ type: "equals", field: "salutationKey", value: key }] }),
        });
        const s = (r && r.data && r.data[0]) || null;
        if (s && s.id) return s.id;
      } catch {}
      return getDefaultSalutationId();
    }

    async function getCustomerDetails(id) {
      const r = await shopwareFetch("/search/customer", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
        body: JSON.stringify({
          page: 1,
          limit: 1,
          associations: { defaultBillingAddress: {}, defaultShippingAddress: {}, salutation: {} },
          filter: [{ type: "equals", field: "id", value: id }],
        }),
      });
      const c = (r && r.data && r.data[0]) || null;
      if (!c) throw new Error("Customer not found");
      return c;
    }

    async function getProductBy(ref) {
      // ref: { productId?, productNumber? }
      if (ref.productId) {
        const r = await shopwareFetch("/search/product", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
          body: JSON.stringify({ page: 1, limit: 1, filter: [{ type: "equals", field: "id", value: ref.productId }] }),
        });
        return (r && r.data && r.data[0]) || null;
      }
      if (ref.productNumber) {
        const r = await shopwareFetch("/search/product", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
          body: JSON.stringify({ page: 1, limit: 1, filter: [{ type: "equals", field: "productNumber", value: ref.productNumber }] }),
        });
        return (r && r.data && r.data[0]) || null;
      }
      return null;
    }

    // 1) Resolve sales channel defaults
    const sc = await getDefaultSalesChannel();
    salesChannelId = salesChannelId || sc.id;
    currencyId = currencyId || sc.currencyId;
    languageId = languageId || sc.languageId;
    shippingMethodId = shippingMethodId || sc.shippingMethodId;

    // 2) Resolve currency rounding and factor
    const currency = await getCurrency(currencyId);
    function sanitizeRounding(r) {
      return {
        decimals: Number(r?.decimals ?? 2),
        interval: Number(r?.interval ?? 0.01),
        roundForNet: Boolean(r?.roundForNet ?? true),
      };
    }
    const itemRounding = sanitizeRounding(currency?.itemRounding || {});
    const totalRounding = sanitizeRounding(currency?.totalRounding || {});
    const currencyFactor = Number(currency?.factor ?? 1.0) || 1.0;

    // 3) Resolve states
    const orderStateId = await getStateId("order.state", "open");
    const transactionStateId = await getStateId("order_transaction.state", "open");
    const deliveryStateId = await getStateId("order_delivery.state", "open");

    // 4) Resolve customer payload and addresses
    const orderId = hex32();
    // Optionally reserve an order number from number-range (requires _action path to be reachable)
    let reservedOrderNumber = null;
    if (ENABLE_ORDER_NUMBER_RESERVE) {
      try {
        const url = `${adminBase}/_action/number-range/reserve/order/${encodeURIComponent(salesChannelId)}`;
        const resp = await fetch(url, { headers: { Authorization: `Bearer ${await getShopwareToken()}` } });
        if (resp.ok) {
          const j = await resp.json();
          if (j && j.number) reservedOrderNumber = String(j.number);
        } else {
          const t = await resp.text();
          log("warn", "order_number_reserve_failed", { status: resp.status, body: t.slice(0, 300) });
        }
      } catch (e) {
        log("warn", "order_number_reserve_error", { err: formatError(e) });
      }
    }
    let orderCustomer;
    let billingAddr;
    let shippingAddr;
    if (customerId) {
      const c = await getCustomerDetails(customerId);
      const salId = await getSalutationIdByKey('not_specified');
      // Optional hardening: if the underlying customer has no salutation, patch it to avoid admin UI issues
      try {
        if (!c.salutationId) {
          await shopwareFetch(`/customer/${encodeURIComponent(c.id)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", "X-Request-ID": reqId },
            body: JSON.stringify({ salutationId: salId }),
          });
        }
      } catch (e) {
        log("warn", "customer.salutation_patch_failed", { reqId, customerId: c.id, err: formatError(e) });
      }
      orderCustomer = {
        id: hex32(),
        orderId,
        customerId: c.id,
        email: c.email,
        salutationId: salId,
        firstName: c.firstName || "",
        lastName: c.lastName || "",
        customerNumber: c.customerNumber || undefined,
      };
      const b = c.defaultBillingAddress || c.defaultShippingAddress;
      if (!b) throw new Error("Customer has no default address");
      billingAddr = {
        id: hex32(),
        orderId,
        countryId: b.countryId,
        salutationId: salId,
        firstName: b.firstName || c.firstName || "",
        lastName: b.lastName || c.lastName || "",
        street: b.street || "",
        zipcode: b.zipcode || "",
        city: b.city || "",
        company: b.company || undefined,
      };
      const s = c.defaultShippingAddress || c.defaultBillingAddress;
      shippingAddr = {
        id: hex32(),
        orderId,
        countryId: s.countryId,
        salutationId: salId,
        firstName: s.firstName || c.firstName || "",
        lastName: s.lastName || c.lastName || "",
        street: s.street || "",
        zipcode: s.zipcode || "",
        city: s.city || "",
        company: s.company || undefined,
      };
    } else {
      const cust = customer || {};
      const salId = await getSalutationIdByKey('not_specified');
      if (!cust.email || !cust.firstName || !cust.lastName) {
        return res.status(400).json({ error: "customer.email, firstName, lastName are required when creating a guest order" });
      }
      const b = cust.billingAddress || {};
      if (!b.countryId || !b.street || !b.city) {
        return res.status(400).json({ error: "customer.billingAddress.countryId, street and city are required" });
      }
      orderCustomer = {
        id: hex32(),
        orderId,
        email: cust.email,
        salutationId: salId,
        firstName: cust.firstName,
        lastName: cust.lastName,
      };
      billingAddr = {
        id: hex32(),
        orderId,
        countryId: b.countryId,
        salutationId: salId,
        firstName: b.firstName || cust.firstName,
        lastName: b.lastName || cust.lastName,
        street: b.street,
        zipcode: b.zipcode || "",
        city: b.city,
        company: b.company || undefined,
      };
      const s = cust.shippingAddress || b;
      shippingAddr = {
        id: hex32(),
        orderId,
        countryId: s.countryId,
        salutationId: salId,
        firstName: s.firstName || cust.firstName,
        lastName: s.lastName || cust.lastName,
        street: s.street,
        zipcode: s.zipcode || "",
        city: s.city,
        company: s.company || undefined,
      };
    }

    // 5) Resolve products and build line items
    const lineItems = [];
    function makeCalculatedPrice(unitPrice, qty) {
      const u = Number(unitPrice) || 0;
      const q = Math.max(1, Number(qty) || 1);
      return {
        unitPrice: u,
        totalPrice: u * q,
        quantity: q,
        calculatedTaxes: [],
        taxRules: [],
      };
    }

    for (const it of items) {
      const qty = Math.max(1, parseInt(it.quantity || 1, 10));
      const p = await getProductBy(it);
      if (!p) return res.status(400).json({ error: `Product not found for item: ${JSON.stringify(it)}` });
      // Choose price for currencyId if available
      let unitPrice = null;
      if (Array.isArray(p.price)) {
        const match = p.price.find((x) => !x.currencyId || x.currencyId === currencyId) || p.price[0];
        if (match && typeof match.gross === "number") unitPrice = match.gross;
        else if (match && typeof match.net === "number") unitPrice = match.net;
      }
      if (unitPrice == null) unitPrice = Number(p.price?.gross) || Number(p.price?.net) || 0;
      lineItems.push({
        id: hex32(),
        orderId,
        productId: p.id,
        referencedId: p.id,
        identifier: p.productNumber || p.id,
        label: it.label || p.name || p.productNumber || "Item",
        quantity: qty,
        type: "product",
        states: [],
        good: true,
        stackable: true,
        removable: true,
        price: makeCalculatedPrice(unitPrice, qty),
        children: [],
        payload: { productNumber: p.productNumber || undefined },
      });
    }

    const itemsTotal = lineItems.reduce((sum, li) => sum + (Number(li.price?.totalPrice) || 0), 0);

    // 6) Build transactions
    const transaction = {
      id: hex32(),
      orderId,
      paymentMethodId,
      stateId: transactionStateId,
      amount: { ...makeCalculatedPrice(itemsTotal, 1) },
    };

    // 7) Build deliveries (minimal)
    const now = new Date();
    const latest = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000);
    const delivery = {
      id: hex32(),
      orderId,
      shippingOrderAddressId: shippingAddr.id,
      shippingMethodId,
      stateId: deliveryStateId,
      shippingDateEarliest: toLocalOffsetIso(now),
      shippingDateLatest: toLocalOffsetIso(latest),
      shippingCosts: { unitPrice: shippingCostsOverride, totalPrice: shippingCostsOverride, quantity: 1, calculatedTaxes: [], taxRules: [] },
    };
    // Optional: create delivery positions for each line item (closer to storefront structure)
    try {
      const positions = lineItems.map((li) => ({
        id: hex32(),
        orderDeliveryId: delivery.id,
        orderLineItemId: li.id,
        price: { ...li.price },
      }));
      if (positions.length) delivery.positions = positions;
    } catch {}

    // 8) Assemble order payload
    const orderPayload = {
      id: orderId,
      ...(reservedOrderNumber ? { orderNumber: reservedOrderNumber } : {}),
      salesChannelId,
      currencyId,
      languageId,
      orderDateTime: toLocalOffsetIso(new Date()),
      currencyFactor: Number(currencyFactor) || 1.0,
      stateId: orderStateId,
      itemRounding,
      totalRounding,
      price: {
        netPrice: itemsTotal, // approximate when gross is unknown
        totalPrice: itemsTotal,
        positionPrice: itemsTotal,
        rawTotal: itemsTotal,
        taxStatus: "gross",
        calculatedTaxes: [],
        taxRules: [],
      },
      shippingCosts: { unitPrice: shippingCostsOverride, totalPrice: shippingCostsOverride, quantity: 1, calculatedTaxes: [], taxRules: [] },
      orderCustomer,
      billingAddressId: billingAddr.id,
      billingAddress: billingAddr,
      addresses: [billingAddr, shippingAddr],
      lineItems,
      transactions: [transaction],
      deliveries: [delivery],
    };

    // 9) Create order (avoid _response query to reduce chance of WAF 403 on underscore params)
    // Use raw fetch so 204 No Content is handled correctly.
    {
      const url = `${adminBase}/order`;
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${await getShopwareToken()}`, Accept: "application/json" },
        body: JSON.stringify(orderPayload),
      });
      if (!resp.ok) {
        const txt = await resp.text();
        log("error", "shopware.create_order_failed", { url, status: resp.status, body: txt.slice(0, 500) });
        throw new Error(`${resp.status} ${txt}`);
      }
    }

    // Try to fetch the created order for the number
    let orderNumber = null;
    try {
      const det = await shopwareFetch(`/order/${orderId}`);
      const d = det && det.data ? det.data : det;
      orderNumber = d && d.orderNumber ? d.orderNumber : null;
    } catch {}

    // Optionally send an order confirmation via state transition (requires business events + _action route)
    if (ENABLE_ORDER_CONFIRMATION_EMAIL) {
      try {
        const url = `${adminBase}/_action/order/${orderId}/state/process`;
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${await getShopwareToken()}` },
          body: JSON.stringify({ sendMail: true }),
        });
        if (!resp.ok) {
          const t = await resp.text();
          log("warn", "order_confirmation_send_failed", { status: resp.status, body: t.slice(0, 300) });
        }
      } catch (e) {
        log("warn", "order_confirmation_send_error", { err: formatError(e) });
      }
    }

    res.json({ ok: true, data: { id: orderId, orderNumber: orderNumber || reservedOrderNumber || null } });
  } catch (e) {
    log("error", "route.error", { reqId, route: "/api/orders [POST]", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Orders metrics: counts for today, last 7/30 days, this year
app.get("/api/orders/metrics", requireAuth, async (req, res) => {
  // Use UTC-based date boundaries
  const now = new Date();
  const startOfUTCDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const start7 = new Date(startOfUTCDay); start7.setUTCDate(start7.getUTCDate() - 7);
  const start30 = new Date(startOfUTCDay); start30.setUTCDate(start30.getUTCDate() - 30);
  const startYear = new Date(Date.UTC(now.getUTCFullYear(), 0, 1));

  function criteriaSince(sinceIso) {
    return {
      page: 1,
      limit: 1,
      "total-count-mode": "exact",
      filter: [
        { type: "range", field: "createdAt", parameters: { gte: sinceIso } },
      ],
      // Keep payload small, but include an aggregation for total amount
      includes: { order: ["id"] },
      aggregations: [
        { name: "sumAmount", type: "sum", field: "amountTotal" },
      ],
    };
  }

  async function countAmountSince(d) {
    const c = criteriaSince(d.toISOString());
    const sw = await shopwareFetch("/search/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": (/** @type any */(req)).id },
      body: JSON.stringify(c),
    });
    const count = typeof sw.total === "number" ? sw.total : Array.isArray(sw.data) ? sw.data.length : 0;
    const aggs = sw.aggregations || {};
    const sumAgg = aggs.sumAmount || aggs["sumAmount"] || {};
    const amount =
      (typeof sumAgg.sum === "number" && sumAgg.sum) ||
      (typeof sumAgg.value === "number" && sumAgg.value) ||
      (sumAgg.results && typeof sumAgg.results.sum === "number" && sumAgg.results.sum) ||
      0;
    return { count, amount };
  }

  try {
    const [today, last7, last30, thisYear] = await Promise.all([
      countAmountSince(startOfUTCDay),
      countAmountSince(start7),
      countAmountSince(start30),
      countAmountSince(startYear),
    ]);
    res.set("Cache-Control", "no-store");
    res.json({ today, last7, last30, thisYear });
  } catch (e) {
    log("error", "route.error", { reqId: (/** @type any */(req)).id, route: "/api/orders/metrics", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  const criteria = {
    page: 1,
    limit: 1,
    associations: {
      stateMachineState: {},
      currency: {},
      orderCustomer: {},
      lineItems: { associations: { product: { associations: { cover: { associations: { media: {} } }, manufacturer: {} } } } },
      transactions: { associations: { stateMachineState: {} } },
      deliveries: { associations: { stateMachineState: {} } },
    },
    filter: [{ type: "equals", field: "id", value: id }],
  };

  try {
    const sw = await shopwareFetch("/search/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(criteria),
    });
    const o = (sw.data || [])[0];
    if (!o) return res.status(404).json({ error: "Order not found" });

    const state = o.stateMachineState?.name || null;
    const stateColor = state && /cancel|fail|refus|declin/i.test(state) ? "bad" : "ok";
    const paidState = Array.isArray(o.transactions) && o.transactions[0]?.stateMachineState;
    const paidName = paidState?.name || null;
    const paidTechnical = paidState?.technicalName || null;
    const isPaid = (paidTechnical ? paidTechnical === "paid" : /paid/i.test(paidName || "")) || false;

    const deliveryState = Array.isArray(o.deliveries) && o.deliveries[0]?.stateMachineState;
    const shippedName = deliveryState?.name || null;
    const shippedTechnical = deliveryState?.technicalName || null;
    const isShipped = (shippedTechnical ? /shipp?ed/.test(shippedTechnical) : /shipp?ed/i.test(shippedName || "")) || false;
    const items = Array.isArray(o.lineItems)
      ? o.lineItems.map((li) => ({
          id: li.id,
          label: li.label || li.product?.name || "",
          qty: li.quantity ?? null,
          total: li.totalPrice ?? (li.price && (li.price.totalPrice ?? li.price.unitPrice)) ?? null,
          img: li.product?.cover?.media?.url || null,
        }))
      : [];

    const out = {
      id: o.id,
      orderNumber: o.orderNumber,
      createdAt: o.createdAt,
      updatedAt: o.updatedAt,
      amountTotal: o.amountTotal,
      currency: o.currency?.isoCode || "EUR",
      customerEmail: o.orderCustomer?.email || null,
      customerId: o.orderCustomer?.customerId || null,
      state,
      stateColor,
      paid: isPaid,
      paidState: paidName || paidTechnical || null,
      shipped: isShipped,
      shippedState: shippedName || shippedTechnical || null,
      items,
    };
    res.set("Cache-Control", "no-store");
    res.json({ data: out });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/orders/:id", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Feature flags surfaced to frontend
app.get("/api/features", requireAuth, (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ invoiceActions: ENABLE_INVOICE_ACTIONS });
});

// Create an invoice (Rechnung) for an order and return latest invoice document info
app.post("/api/orders/:id/invoice", requireAuth, async (req, res) => {
  const id = req.params.id;
  try {
    if (!ENABLE_INVOICE_ACTIONS) {
      return res.status(501).json({ error: "Invoice actions disabled by server config" });
    }
    // 1) Create invoice document
    await shopwareFetch("/_action/order/document/invoice/create", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify([
        {
          orderId: id,
          type: "invoice",
          fileType: "pdf",
          static: false,
          config: {},
        },
      ]),
    });

    // 2) Fetch latest invoice document for this order
    const criteria = {
      page: 1,
      limit: 1,
      sort: [{ field: "createdAt", order: "DESC" }],
      associations: { documentType: {} },
      filter: [
        { type: "equals", field: "orderId", value: id },
        { type: "equals", field: "documentType.technicalName", value: "invoice" },
      ],
    };
    const sw = await shopwareFetch("/search/document", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(criteria),
    });
    const d = (sw.data || [])[0];
    if (!d) return res.json({ ok: true, created: true, document: null });

    res.json({
      ok: true,
      created: true,
      document: { id: d.id, deepLinkCode: d.deepLinkCode, number: d.documentNumber || null },
      downloadUrl: `/api/documents/${d.id}/download`,
    });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/orders/:id/invoice", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Proxy download of a document by id
app.get("/api/documents/:id/download", requireAuth, async (req, res) => {
  const docId = req.params.id;
  try {
    // Load document to get deepLinkCode (JSON:API may nest in attributes)
    const doc = await shopwareFetch(`/document/${docId}`, { method: "GET" });
    const code =
      doc?.data?.attributes?.deepLinkCode ||
      doc?.data?.deepLinkCode ||
      doc?.deepLinkCode;
    if (!code) return res.status(404).json({ error: "Dokument nicht gefunden" });

    // Prepare auth header for Admin API
    const token = await getShopwareToken();
    const authHeaders = {
      Accept: "application/octet-stream",
      Authorization: `Bearer ${token}`,
    };

    // Try direct deepLink download first (works in most setups)
    const url = `${adminBase}/_action/document/${docId}/${code}?download=1`;
    let upstream = await fetch(url, { headers: authHeaders });
    if (!upstream.ok) {
      // Fallback to bulk download endpoint
      const dlUrl = `${adminBase}/_action/order/document/download`;
      upstream = await fetch(dlUrl, {
        method: "POST",
        headers: { ...authHeaders, "Content-Type": "application/json" },
        body: JSON.stringify([docId]),
      });
      if (!upstream.ok) {
        const t = await upstream.text();
        return res.status(502).json({ error: `Upstream ${upstream.status}: ${t.slice(0, 500)}` });
      }
    }
    // Stream to client
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Cache-Control", "no-store");
    const n = (
      doc?.data?.attributes?.documentNumber ||
      doc?.data?.documentNumber ||
      doc?.documentNumber ||
      docId
    ).toString();
    res.setHeader("Content-Disposition", `attachment; filename="Rechnung-${n}.pdf"`);
    const ab = await upstream.arrayBuffer();
    res.end(Buffer.from(ab));
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/documents/:id/download", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Create an invoice and email it to the customer
app.post("/api/orders/:id/invoice-email", requireAuth, async (req, res) => {
  const id = req.params.id;
  try {
    if (!ENABLE_INVOICE_ACTIONS) {
      return res.status(501).json({ error: "Invoice actions disabled by server config" });
    }

    // Load order with associations to get email/name
    const orderCrit = {
      page: 1,
      limit: 1,
      associations: { orderCustomer: {} },
      filter: [{ type: "equals", field: "id", value: id }],
    };
    const swOrder = await shopwareFetch("/search/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(orderCrit),
    });
    const o = (swOrder.data || [])[0];
    if (!o) return res.status(404).json({ error: "Order not found" });
    const salesChannelId = o.salesChannelId;
    const orderLangId = o.languageId || null;
    const rcptEmail = o.orderCustomer?.email;
    const rcptName = [o.orderCustomer?.firstName, o.orderCustomer?.lastName].filter(Boolean).join(" ") || SHOP_NAME;
    if (!rcptEmail) return res.status(400).json({ error: "Order has no customer email" });

    // Create invoice document
    await shopwareFetch("/_action/order/document/invoice/create", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id, ...(orderLangId ? { "sw-language-id": orderLangId } : {}) },
      body: JSON.stringify([{ orderId: id, type: "invoice", fileType: "pdf", static: false, config: {} }]),
    });

    // Find newest invoice document
    const docCriteria = {
      page: 1,
      limit: 1,
      sort: [{ field: "createdAt", order: "DESC" }],
      filter: [
        { type: "equals", field: "orderId", value: id },
        { type: "equals", field: "documentType.technicalName", value: "invoice" },
      ],
    };
    const swDoc = await shopwareFetch("/search/document", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(docCriteria),
    });
    const d = (swDoc.data || [])[0];
    if (!d) return res.status(500).json({ error: "Rechnungsdokument nicht gefunden" });

    // Download PDF and attach via binAttachments
    const token = await getShopwareToken();
    // Load document to get deepLinkCode if not present
    let deepCode = d.deepLinkCode;
    if (!deepCode) {
      const docFull = await shopwareFetch(`/document/${d.id}`, { method: "GET" });
      deepCode = docFull?.data?.attributes?.deepLinkCode || docFull?.data?.deepLinkCode || docFull?.deepLinkCode || null;
    }
    const dlUrl = deepCode
      ? `${adminBase}/_action/document/${d.id}/${deepCode}?download=1`
      : `${adminBase}/_action/order/document/download`;
    let pdfBuf;
    if (deepCode) {
      const up = await fetch(dlUrl, { headers: { Authorization: `Bearer ${token}`, Accept: "application/octet-stream" } });
      if (!up.ok) return res.status(502).json({ error: `Dokument-Download fehlgeschlagen: ${up.status}` });
      const ab = await up.arrayBuffer();
      pdfBuf = Buffer.from(ab);
    } else {
      const up = await fetch(dlUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, Accept: "application/octet-stream", "Content-Type": "application/json" },
        body: JSON.stringify([d.id]),
      });
      if (!up.ok) return res.status(502).json({ error: `Dokument-Download fehlgeschlagen: ${up.status}` });
      const ab = await up.arrayBuffer();
      pdfBuf = Buffer.from(ab);
    }

    const docNum = d.documentNumber || o.orderNumber || id;
    const fileName = `Rechnung-${docNum}.pdf`;
    const contentHtml = `Hallo ${rcptName},<br/><br/>im Anhang finden Sie Ihre Rechnung ${docNum}.`;
    const contentPlain = `Hallo ${rcptName},\n\nim Anhang finden Sie Ihre Rechnung ${docNum}.`;

    const mailPayload = {
      recipients: { [rcptEmail]: rcptName },
      salesChannelId,
      subject: `Ihre Rechnung ${docNum}`,
      senderName: SHOP_NAME,
      contentHtml,
      contentPlain,
      binAttachments: [
        { fileName, mimeType: "application/pdf", content: pdfBuf.toString("base64") },
      ],
    };
    const mailResp = await fetch(`${adminBase}/_action/mail-template/send`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(orderLangId ? { "sw-language-id": orderLangId } : {}) },
      body: JSON.stringify(mailPayload),
    });
    if (!mailResp.ok) {
      const t = await mailResp.text();
      return res.status(502).json({ error: `E-Mail Versand fehlgeschlagen: ${mailResp.status}`, info: t.slice(0, 500) });
    }
    return res.json({ ok: true, sent: true });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/orders/:id/invoice-email", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

app.get("/api/customers", requireAuth, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const limit = Math.min(
    50,
    Math.max(1, parseInt(req.query.limit || "20", 10))
  );
  const q = (req.query.q || "").trim();

  const filters = [];
  if (q) {
    filters.push({
      type: "multi",
      operator: "or",
      queries: [
        { type: "contains", field: "firstName", value: q },
        { type: "contains", field: "lastName", value: q },
        { type: "contains", field: "email", value: q },
        { type: "contains", field: "customerNumber", value: q },
      ],
    });
  }

  const criteria = {
    page,
    limit,
    sort: [{ field: "createdAt", order: "DESC" }],
    associations: {},
    "total-count-mode": "exact",
    filter: filters,
  };

  try {
    const sw = await searchWithRetry("/search/customer", criteria, req.id);

    const items = (sw.data || []).map((c) => ({
      id: c.id,
      email: c.email,
      firstName: c.firstName,
      lastName: c.lastName,
      active: c.active,
      createdAt: c.createdAt,
      customerNumber: c.customerNumber,
    }));

    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || items.length, data: items });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/customers", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

app.get("/api/customers/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  const criteria = {
    page: 1,
    limit: 1,
    associations: {},
    filter: [{ type: "equals", field: "id", value: id }],
  };

  try {
    const sw = await shopwareFetch("/search/customer", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(criteria),
    });
    const c = (sw.data || [])[0];
    if (!c) return res.status(404).json({ error: "Customer not found" });

    const out = {
      id: c.id,
      email: c.email,
      firstName: c.firstName,
      lastName: c.lastName,
      active: c.active,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
      customerNumber: c.customerNumber,
    };
    res.set("Cache-Control", "no-store");
    res.json({ data: out });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/customers/:id", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

app.get("/api/customers/:id/orders", requireAuth, async (req, res) => {
  const id = req.params.id;
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || "20", 10)));

  const criteria = {
    page,
    limit,
    sort: [{ field: "createdAt", order: "DESC" }],
    associations: { stateMachineState: {}, currency: {}, orderCustomer: {} },
    "total-count-mode": "exact",
    filter: [{ type: "equals", field: "orderCustomer.customerId", value: id }],
  };

  try {
    const sw = await shopwareFetch("/search/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify(criteria),
    });

    const items = (sw.data || []).map((o) => {
      const state = o.stateMachineState?.name || null;
      const stateColor = state && /cancel|fail|refus|declin/i.test(state) ? "bad" : "ok";
      return {
        id: o.id,
        orderNumber: o.orderNumber,
        createdAt: o.createdAt,
        amountTotal: o.amountTotal,
        currency: o.currency?.isoCode || "EUR",
        customerEmail: o.orderCustomer?.email || null,
        state,
        stateColor,
      };
    });

    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || items.length, data: items });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/customers/:id/orders", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Payment methods list (for order creation UI)
app.get("/api/payment-methods", requireAuth, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || "50", 10)));
  const q = (req.query.q || "").trim();
  // Determine default sales channel
  async function getDefaultSalesChannel() {
    const r = await shopwareFetch("/search/sales-channel", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify({ page: 1, limit: 1, sort: [{ field: "createdAt", order: "ASC" }], filter: [{ type: "equals", field: "active", value: true }] }),
    });
    return (r && r.data && r.data[0]) || null;
  }
  try {
    const sc = await getDefaultSalesChannel();
    const baseFilters = [{ type: "equals", field: "active", value: true }];
    if (q) baseFilters.push({ type: "contains", field: "name", value: q });

    async function query(filters) {
      const criteria = {
        page,
        limit,
        sort: [{ field: "position", order: "ASC" }, { field: "name", order: "ASC" }],
        "total-count-mode": "exact",
        filter: filters,
      };
      return searchWithRetry("/search/payment-method", criteria, req.id);
    }

    // Try: active + assigned to default sales channel
    let sw = null;
    if (sc && sc.id) {
      sw = await query([...baseFilters, { type: "equals", field: "salesChannels.id", value: sc.id }]);
    }
    // Fallback: only active (across all channels)
    if (!sw || !Array.isArray(sw.data) || sw.data.length === 0) {
      sw = await query(baseFilters);
    }
    // Last resort: no filters (if backend mislabels active or associations)
    if (!sw || !Array.isArray(sw.data) || sw.data.length === 0) {
      sw = await query(q ? [{ type: "contains", field: "name", value: q }] : []);
    }

    const data = (sw.data || [])
      .filter((p) => p && p.id && p.active)
      .map((p) => ({ id: p.id, name: p.name, active: p.active }));
    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || data.length, data });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/payment-methods", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Countries list (for guest address input)
app.get("/api/countries", requireAuth, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const limit = Math.min(250, Math.max(1, parseInt(req.query.limit || "50", 10)));
  const q = (req.query.q || "").trim();
  const filters = [{ type: "equals", field: "active", value: true }];
  if (q) filters.push({ type: "contains", field: "name", value: q });
  const criteria = { page, limit, sort: [{ field: "name", order: "ASC" }], "total-count-mode": "exact", filter: filters };
  try {
    const sw = await searchWithRetry("/search/country", criteria, req.id);
    const data = (sw.data || []).map((c) => ({ id: c.id, name: c.name, iso: c.iso || c.iso3 || null }));
    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || data.length, data });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/countries", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Salutations list
app.get("/api/salutations", requireAuth, async (req, res) => {
  try {
    const sw = await searchWithRetry("/search/salutation", { page: 1, limit: 50, sort: [{ field: "displayName", order: "ASC" }] }, req.id);
    const data = (sw.data || []).map((s) => ({ id: s.id, key: s.salutationKey, name: s.displayName, letterName: s.letterName }));
    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || data.length, data });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/salutations", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// Shipping methods list (for order creation UI)
app.get("/api/shipping-methods", requireAuth, async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || "50", 10)));
  const q = (req.query.q || "").trim();
  async function getDefaultSalesChannel() {
    const r = await shopwareFetch("/search/sales-channel", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify({ page: 1, limit: 1, sort: [{ field: "createdAt", order: "ASC" }], filter: [{ type: "equals", field: "active", value: true }] }),
    });
    return (r && r.data && r.data[0]) || null;
  }
  try {
    const sc = await getDefaultSalesChannel();
    const filters = [{ type: "equals", field: "active", value: true }];
    if (sc && sc.id) filters.push({ type: "equals", field: "salesChannels.id", value: sc.id });
    if (q) filters.push({ type: "contains", field: "name", value: q });
    const criteria = { page, limit, sort: [{ field: "position", order: "ASC" }, { field: "name", order: "ASC" }], "total-count-mode": "exact", filter: filters };
    let sw = await searchWithRetry("/search/shipping-method", criteria, req.id);
    if (!sw || !Array.isArray(sw.data) || sw.data.length === 0) {
      sw = await searchWithRetry("/search/shipping-method", { page, limit }, req.id);
    }
    const data = (sw.data || []).filter((s) => s && s.id && s.active).map((s) => ({ id: s.id, name: s.name }));
    res.set("Cache-Control", "no-store");
    res.json({ total: sw.total || data.length, data });
  } catch (e) {
    log("error", "route.error", { reqId: req.id, route: "/api/shipping-methods", err: formatError(e) });
    res.status(500).json({ error: formatError(e) });
  }
});

// ----------- Diagnostics -----------
app.get("/api/_diag", async (req, res) => {
  const result = {
    baseUrl: SHOPWARE_BASE_URL,
    adminBase,
    health: null,
    oauth: null,
    searchProduct: null,
  };

  // Health check (no auth)
  try {
    const hcUrl = `${adminBase}/_info/health-check`;
    const started = Date.now();
    const r = await fetch(hcUrl);
    result.health = { ok: r.ok, status: r.status, durMs: Date.now() - started };
  } catch (e) {
    result.health = { ok: false, error: formatError(e) };
  }

  // OAuth
  try {
    const token = await getShopwareToken();
    result.oauth = { ok: true, hasToken: Boolean(token), expInMs: Math.max(0, tokenCache.exp - Date.now()) };
  } catch (e) {
    result.oauth = { ok: false, error: formatError(e) };
  }

  // Simple product search (auth)
  try {
    const started = Date.now();
    const sw = await shopwareFetch(`/search/product`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": req.id },
      body: JSON.stringify({ page: 1, limit: 1, filter: [], sort: [] }),
    });
    result.searchProduct = { ok: true, durMs: Date.now() - started, items: Array.isArray(sw.data) ? sw.data.length : 0 };
  } catch (e) {
    result.searchProduct = { ok: false, error: formatError(e) };
  }

  res.set("Cache-Control", "no-store");
  res.json(result);
});

// Central error handler (fallback)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const reqId = req && req.id;
  log("error", "uncaught", {
    reqId,
    err: formatError(err),
    stack: err && err.stack ? String(err.stack).split("\n").slice(0, 5).join(" | ") : undefined,
  });
  res.status(500).json({ error: "Internal Server Error" });
});

// ----------- Static frontend -----------
const pub = path.join(process.cwd(), "public");
app.use(express.static(pub, { extensions: ["html"] }));

// Fallback to index.html (SPA)
// Express 5 uses path-to-regexp v6, which doesn't allow bare "*" routes.
// Use a RegExp or a splat param instead (e.g., '/:path(*)').
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(pub, "index.html"));
});

app.listen(PORT, () => {
  console.log(`[Mobile Admin] running on http://localhost:${PORT}`);
});
