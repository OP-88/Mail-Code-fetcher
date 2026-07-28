/**
 * background.js — RAM Engine, Security & Lifecycle Controller
 *
 * Responsibilities:
 *  1. Receive PARSE_EMAIL_PAYLOAD from content scripts with strict origin validation.
 *  2. Run multi-pattern RegEx token isolation in RAM (never touches disk).
 *  3. Relay clipboard write to the active webmail content script (MV3 workaround).
 *  4. Fire OS notification with auto-wipe countdown.
 *  5. Schedule 60-second alarm; wipe clipboard on alarm via content script relay.
 *  6. Store ephemeral code in browser.storage.session (survives SW restart, clears on browser close).
 *  7. Manage LemonSqueezy license validation for multi-account unlock.
 *
 * Security Model:
 *  - Gate 1: sender.id === browser.runtime.id (internal extension only)
 *  - Gate 2: sender.tab.url must originate from AUTHORIZED_DOMAINS
 *  - Gate 3: Account limit check before processing any payload
 */

"use strict";

console.log("[MCF] background.js loaded — Mail Code Fetcher v1.0.0");

/* ═══════════════════════════════════════════════════════════════════════════
   CONSTANTS
══════════════════════════════════════════════════════════════════════════════ */

const AUTHORIZED_DOMAINS = [
  "https://mail.google.com/",
  "https://outlook.live.com/",
  "https://outlook.office.com/",
  "https://outlook.office365.com/",
];

const FREE_TIER_ACCOUNT_LIMIT = 1;
const SESSION_TTL_MS = 70000; // 70s — slightly longer than the 60s wipe alarm

/* ═══════════════════════════════════════════════════════════════════════════
   SESSION STORAGE SHIM
   browser.storage.session requires Firefox 109+. For older builds we
   fall back to storage.local with a manual TTL check.
══════════════════════════════════════════════════════════════════════════════ */

const session = {
  async set(obj) {
    try {
      await browser.storage.session.set(obj);
    } catch {
      // Fallback: store in local with a timestamp prefix so we can expire it
      const wrapped = {};
      for (const [k, v] of Object.entries(obj)) wrapped[`_sess_${k}`] = v;
      wrapped._sess_ts = Date.now();
      await browser.storage.local.set(wrapped);
    }
  },
  async get(keys) {
    try {
      return await browser.storage.session.get(keys);
    } catch {
      const prefixed = (Array.isArray(keys) ? keys : [keys]).map(k => `_sess_${k}`);
      const raw = await browser.storage.local.get([...prefixed, "_sess_ts"]);
      // Expire after TTL
      if (raw._sess_ts && Date.now() - raw._sess_ts > SESSION_TTL_MS) {
        await browser.storage.local.remove([...prefixed, "_sess_ts"]);
        return {};
      }
      const out = {};
      for (const k of (Array.isArray(keys) ? keys : [keys])) {
        if (`_sess_${k}` in raw) out[k] = raw[`_sess_${k}`];
      }
      return out;
    }
  },
  async remove(keys) {
    try {
      await browser.storage.session.remove(keys);
    } catch {
      const prefixed = (Array.isArray(keys) ? keys : [keys]).map(k => `_sess_${k}`);
      await browser.storage.local.remove(prefixed);
    }
  },
};


/* ═══════════════════════════════════════════════════════════════════════════
   LEMONSQUEEZY LICENSE VALIDATION
   Docs: https://docs.lemonsqueezy.com/api/licenses
   TODO: Create a product at https://app.lemonsqueezy.com and paste your
         Store ID / Variant ID into the purchase URL below.
══════════════════════════════════════════════════════════════════════════════ */

const LS_VALIDATE_URL = "https://api.lemonsqueezy.com/v1/licenses/validate";
const LS_ACTIVATE_URL = "https://api.lemonsqueezy.com/v1/licenses/activate";
const LS_INSTANCE_NAME = "air-gapped-mail-code-fetcher";

/**
 * Returns a stable, random UUID stored in local storage.
 * Used as the LemonSqueezy instance identifier for this browser install.
 */
async function getInstanceId() {
  const data = await browser.storage.local.get("instanceId");
  if (data.instanceId) return data.instanceId;
  const id = crypto.randomUUID();
  await browser.storage.local.set({ instanceId: id });
  return id;
}

/**
 * Activates a new license key against LemonSqueezy.
 * @param {string} licenseKey
 * @returns {{ valid: boolean, error?: string, activationsLeft?: number }}
 */
async function activateLicense(licenseKey) {
  if (!licenseKey?.trim()) return { valid: false, error: "Empty license key." };

  const instanceId = await getInstanceId();
  const body = new URLSearchParams({
    license_key: licenseKey.trim(),
    instance_name: `${LS_INSTANCE_NAME}-${instanceId.slice(0, 8)}`,
  });

  try {
    const res = await fetch(LS_ACTIVATE_URL, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const json = await res.json();
    const valid = json.activated === true;
    return {
      valid,
      activationsLeft: json.license_key?.activation_limit - json.license_key?.activation_usage,
      instanceId: json.instance?.id,
      error: valid ? null : (json.error || "Activation failed."),
    };
  } catch (err) {
    return { valid: false, error: `Network error: ${err.message}` };
  }
}

/**
 * Validates an already-activated license key.
 */
async function validateLicense(licenseKey) {
  if (!licenseKey?.trim()) return { valid: false };
  const instanceId = await getInstanceId();
  const body = new URLSearchParams({
    license_key: licenseKey.trim(),
    instance_id: instanceId,
  });

  try {
    const res = await fetch(LS_VALIDATE_URL, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const json = await res.json();
    return { valid: json.valid === true };
  } catch {
    return { valid: false };
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   ACCOUNT LIMIT CHECK
══════════════════════════════════════════════════════════════════════════════ */

async function checkAccountLimit() {
  const data = await browser.storage.local.get(["monitoredAccounts", "licenseValid"]);
  const accounts = data.monitoredAccounts || [];
  if (accounts.length <= FREE_TIER_ACCOUNT_LIMIT) return { allowed: true };
  return { allowed: data.licenseValid === true };
}

/* ═══════════════════════════════════════════════════════════════════════════
   TOKEN EXTRACTION ENGINE
   Four-pass RegEx, ordered by specificity. Captures 4-8 char alphanumeric codes.
══════════════════════════════════════════════════════════════════════════════ */

const CODE_PATTERNS = [
  // Pass 1 — Leading context: "Your code is 482910" / "OTP: 482910"
  /(?:code|verification|otp|auth(?:entication)?|pin|login|confirmation|security\s+code|one.time(?:\s+password)?)\s*(?:is|:)?\s*\b([A-Z0-9]{4,8})\b/i,

  // Pass 2 — Trailing context: "482910 is your verification code"
  /\b([A-Z0-9]{4,8})\b\s+(?:is\s+your|as\s+your)\s+(?:code|otp|verification|security|authentication)/i,

  // Pass 3 — Verb lookahead: "enter 482910 to verify"
  /\b(\d{4,8})\b(?=\s{0,30}(?:to\s+verify|to\s+confirm|to\s+log\s+in|to\s+sign\s+in|expires|is\s+valid))/i,

  // Pass 4 — Verb lookbehind: "enter / use / type 482910"
  /(?:enter|use|submit|type)\s+\b(\d{4,8})\b/i,
];

function extractToken(text) {
  for (const pattern of CODE_PATTERNS) {
    const match = text.match(pattern);
    if (match?.[1]) {
      const token = match[1].toUpperCase();
      // Real OTPs always contain at least one digit.
      // This prevents keyword words like "CODE", "AUTH", "LOGIN" being
      // captured as the token when they appear right after a keyword match.
      if (/\d/.test(token)) return token;
    }
  }
  return null;
}

/* ═══════════════════════════════════════════════════════════════════════════
   CODE PIPELINE
══════════════════════════════════════════════════════════════════════════════ */

function maskCode(code) {
  if (code.length <= 4) return "*".repeat(code.length - 2) + code.slice(-2);
  return "*".repeat(code.length - 4) + code.slice(-4);
}

async function executeCodePipeline(code, tabId) {
  console.log(`[MCF] executeCodePipeline — code: ${maskCode(code)}, tabId: ${tabId}`);

  // Persist ephemeral state via shim (works Firefox 109+ natively, falls back otherwise)
  await session.set({
    pendingCode: code,
    pendingMasked: maskCode(code),
    codeDetectedAt: Date.now(),
    codeTabId: tabId,
  });

  // Relay clipboard write to content script in the source tab (MV3 workaround)
  if (tabId !== null && tabId !== undefined) {
    try {
      await browser.tabs.sendMessage(tabId, { type: "WRITE_CLIPBOARD", text: code });
      console.log("[MCF] Clipboard write relayed to content script OK");
    } catch (err) {
      console.warn("[MCF] Clipboard relay to tab failed:", err.message);
    }
  } else {
    console.warn("[MCF] No tabId available for clipboard relay");
  }

  // OS Notification — masked code only
  await browser.notifications.create("CODE_NOTIFICATION", {
    type: "basic",
    iconUrl: browser.runtime.getURL("assets/icon-128.png"),
    title: "Security Code Copied",
    message: `Code [ ${maskCode(code)} ] is in your clipboard. Auto-erases in 60 seconds.`,
  });
  console.log("[MCF] Notification created");

  // Clear any previous alarm and schedule the 60-second wipe
  await browser.alarms.clear("EPHEMERAL_WIPE_ALARM");
  browser.alarms.create("EPHEMERAL_WIPE_ALARM", { delayInMinutes: 1.0 });
  console.log("[MCF] Wipe alarm set for 60s");
}

/* ═══════════════════════════════════════════════════════════════════════════
   IPC MESSAGE LISTENER
══════════════════════════════════════════════════════════════════════════════ */

browser.runtime.onMessage.addListener((message, sender) => {
  // ── PARSE_EMAIL_PAYLOAD (from content scripts) ──────────────────────────
  if (message.type === "PARSE_EMAIL_PAYLOAD") {
    // Security Gate 1: Must be from this extension
    if (sender.id !== browser.runtime.id) {
      console.warn("[MCF] Rejected message — wrong sender.id:", sender.id);
      return;
    }

    // Security Gate 2: Must originate from an authorised domain
    const senderUrl = sender.tab?.url || "";
    const isValidOrigin = AUTHORIZED_DOMAINS.some((d) => senderUrl.startsWith(d));
    if (!isValidOrigin) {
      console.warn("[MCF] Rejected message — invalid origin:", senderUrl);
      return;
    }

    console.log("[MCF] PARSE_EMAIL_PAYLOAD received from:", senderUrl);

    return (async () => {
      // Background-side active-code guard
      const existing = await session.get(["pendingCode", "codeDetectedAt"]);
      if (existing.pendingCode && existing.codeDetectedAt) {
        const elapsed = Date.now() - existing.codeDetectedAt;
        if (elapsed < 60000) {
          console.log(`[MCF] Active code still running (${Math.round(elapsed/1000)}s elapsed) — skipping`);
          return;
        }
      }

      // Security Gate 3: Account limit
      const limit = await checkAccountLimit();
      if (!limit.allowed) {
        console.log("[MCF] Account limit reached — prompting upgrade");
        await browser.notifications.create("UPGRADE_NOTIFICATION", {
          type: "basic",
          iconUrl: browser.runtime.getURL("assets/icon-128.png"),
          title: "Multi-Account Limit Reached",
          message: "Unlock monitoring for additional inboxes with a one-time upgrade.",
        });
        return;
      }

      const code = extractToken(message.payload.slice(0, 20000));
      console.log("[MCF] extractToken result:", code ? maskCode(code) : "null (no match)");
      if (code) await executeCodePipeline(code, sender.tab.id);
    })();
  }

  // ── SIMULATE_OTP (from popup test button — extension-internal only) ────
  if (message.type === "SIMULATE_OTP") {
    if (sender.tab) {
      console.warn("[MCF] SIMULATE_OTP rejected — came from a tab, not popup");
      return;
    }
    return (async () => {
      const tabs = await browser.tabs.query({
        url: [...AUTHORIZED_DOMAINS.map((d) => d + "*")],
      });
      const testCode = String(Math.floor(100000 + Math.random() * 900000));
      const tabId = tabs[0]?.id ?? null;
      console.log("[MCF] SIMULATE_OTP — code:", testCode, "tabId:", tabId);
      await executeCodePipeline(testCode, tabId);
      return { code: testCode };
    })();
  }

  // ── ACTIVATE_LICENSE (from popup) ───────────────────────────────────────
  if (message.type === "ACTIVATE_LICENSE") {
    return (async () => {
      const result = await activateLicense(message.licenseKey);
      if (result.valid) {
        await browser.storage.local.set({
          licenseKey: message.licenseKey.trim(),
          licenseValid: true,
          licenseInstanceId: result.instanceId,
        });
        console.log("[MCF] License activated and stored");
      }
      return result;
    })();
  }

  // ── GET_STATUS (from popup) ─────────────────────────────────────────────
  if (message.type === "GET_STATUS") {
    return (async () => {
      const sess = await session.get([
        "pendingCode",
        "pendingMasked",
        "codeDetectedAt",
        "codeTabId",
      ]);
      const local = await browser.storage.local.get([
        "monitoredAccounts",
        "licenseValid",
        "licenseKey",
      ]);

      const now = Date.now();
      const elapsed = sess.codeDetectedAt ? now - sess.codeDetectedAt : 60001;
      const remainingMs = Math.max(0, 60000 - elapsed);

      return {
        hasCode: !!sess.pendingCode && remainingMs > 0,
        maskedCode: sess.pendingMasked || null,
        detectedAt: sess.codeDetectedAt || null,
        remainingMs,
        codeTabId: sess.codeTabId || null,
        accounts: local.monitoredAccounts || [],
        licenseValid: local.licenseValid || false,
        hasLicenseKey: !!local.licenseKey,
      };
    })();
  }

  // ── COPY_AGAIN (from popup) ─────────────────────────────────────────────
  if (message.type === "COPY_AGAIN") {
    return (async () => {
      const sess = await session.get(["pendingCode", "codeTabId"]);
      if (!sess.pendingCode || !sess.codeTabId) return { ok: false };
      try {
        await browser.tabs.sendMessage(sess.codeTabId, {
          type: "WRITE_CLIPBOARD",
          text: sess.pendingCode,
        });
        return { ok: true };
      } catch {
        return { ok: false };
      }
    })();
  }

  // ── SAVE_ACCOUNTS (from popup) ──────────────────────────────────────────
  if (message.type === "SAVE_ACCOUNTS") {
    if (!Array.isArray(message.accounts)) return;
    const safe = message.accounts
      .filter((a) => typeof a === "string" && a.includes("@") && a.length < 254)
      .map((a) => a.trim().toLowerCase().slice(0, 253));
    return browser.storage.local.set({ monitoredAccounts: safe });
  }
});

/* ═══════════════════════════════════════════════════════════════════════════
   EPHEMERAL ALARM WIPE HANDLER
══════════════════════════════════════════════════════════════════════════════ */

browser.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "EPHEMERAL_WIPE_ALARM") return;
  console.log("[MCF] EPHEMERAL_WIPE_ALARM fired — wiping clipboard and session");

  const sess = await session.get(["codeTabId"]);
  if (sess.codeTabId) {
    try {
      await browser.tabs.sendMessage(sess.codeTabId, {
        type: "WRITE_CLIPBOARD",
        text: "",
      });
      console.log("[MCF] Clipboard wiped via content script");
    } catch {
      console.log("[MCF] Wipe relay skipped — tab likely closed");
    }
  }

  // Dereference all ephemeral data
  await session.remove(["pendingCode", "pendingMasked", "codeDetectedAt", "codeTabId"]);
  browser.action.setBadgeText({ text: "" }).catch(() => {});
  console.log("[MCF] Session cleared");
});
