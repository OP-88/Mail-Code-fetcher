/**
 * popup.js — Popup Controller
 *
 * Handles:
 *  - Status polling from background (GET_STATUS)
 *  - Live 60-second countdown ring animation
 *  - Account add/remove with storage sync
 *  - LemonSqueezy license key activation
 *  - OTP simulation (test button)
 *  - "Copy Again" relay via background
 */

"use strict";

/* ─── DOM Refs ─────────────────────────────────────────────────────────── */
const codeActiveState   = document.getElementById("code-active-state");
const codeIdleState     = document.getElementById("code-idle-state");
const countdownRing     = document.getElementById("countdown-ring");
const countdownSecs     = document.getElementById("countdown-secs");
const ringWrapper       = document.getElementById("ring-wrapper");
const maskedCode        = document.getElementById("masked-code");
const codeSource        = document.getElementById("code-source");
const copyAgainBtn      = document.getElementById("copy-again-btn");
const testBtn           = document.getElementById("test-btn");

const accountsList      = document.getElementById("accounts-list");
const accountInput      = document.getElementById("account-input");
const addAccountBtn     = document.getElementById("add-account-btn");
const accountTierBadge  = document.getElementById("account-tier-badge");
const multiAccountNote  = document.getElementById("multi-account-note");

const licenseKeyInput   = document.getElementById("license-key-input");
const activateBtn       = document.getElementById("activate-btn");
const licenseFeedback   = document.getElementById("license-feedback");
const licenseFreeState  = document.getElementById("license-free-state");
const licensePaidState  = document.getElementById("license-paid-state");
const licenseStatusBadge = document.getElementById("license-status-badge");
const buyLicenseBtn     = document.getElementById("buy-license-btn");

/* ─── Constants ────────────────────────────────────────────────────────── */
const RING_CIRCUMFERENCE = 314.16; // 2π × 50
const WIPE_DURATION_MS   = 60000;

/**
 * TODO: Replace this URL with your actual LemonSqueezy product checkout URL.
 * Get it from: app.lemonsqueezy.com → Products → [your product] → Share
 */
const LEMON_CHECKOUT_URL = "https://store.lemonsqueezy.com/buy/YOUR_PRODUCT_VARIANT_ID";

/* ─── State ─────────────────────────────────────────────────────────────── */
let countdownInterval = null;

/* ─── Countdown Ring ─────────────────────────────────────────────────────── */
function updateRing(remainingMs) {
  const remainingSecs = Math.ceil(remainingMs / 1000);
  const progress = Math.max(0, remainingMs / WIPE_DURATION_MS);
  const offset = RING_CIRCUMFERENCE * (1 - progress);

  countdownRing.style.strokeDashoffset = offset;
  countdownSecs.textContent = remainingSecs;

  // Colour state transitions
  ringWrapper.classList.remove("ring-amber", "ring-red");
  if (remainingSecs <= 5) {
    ringWrapper.classList.add("ring-red");
  } else if (remainingSecs <= 15) {
    ringWrapper.classList.add("ring-amber");
  }
}

function startCountdown(detectedAt) {
  clearInterval(countdownInterval);

  const tick = () => {
    const elapsed = Date.now() - detectedAt;
    const remaining = Math.max(0, WIPE_DURATION_MS - elapsed);
    updateRing(remaining);
    if (remaining <= 0) {
      clearInterval(countdownInterval);
      showIdleState();
    }
  };

  tick();
  countdownInterval = setInterval(tick, 500);
}

/* ─── State Rendering ─────────────────────────────────────────────────────── */
function showIdleState() {
  clearInterval(countdownInterval);
  codeActiveState.classList.add("hidden");
  codeIdleState.classList.remove("hidden");
}

function showActiveState(status) {
  codeIdleState.classList.add("hidden");
  codeActiveState.classList.remove("hidden");
  maskedCode.textContent = status.maskedCode || "──────";
  startCountdown(status.detectedAt);
}

function renderAccounts(accounts, licenseValid) {
  accountsList.innerHTML = "";

  accounts.forEach((email, index) => {
    const li = document.createElement("li");
    li.className = "account-item";
    li.setAttribute("role", "listitem");

    const dot = document.createElement("span");
    dot.className = "account-dot";
    dot.setAttribute("aria-hidden", "true");

    const label = document.createElement("span");
    label.textContent = email;
    label.title = email;

    const removeBtn = document.createElement("button");
    removeBtn.className = "account-remove-btn";
    removeBtn.setAttribute("aria-label", `Remove ${email}`);
    removeBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
    removeBtn.addEventListener("click", () => removeAccount(index));

    li.appendChild(dot);
    li.appendChild(label);
    li.appendChild(removeBtn);
    accountsList.appendChild(li);
  });

  // Tier badge
  const count = accounts.length;
  if (licenseValid) {
    accountTierBadge.textContent = `PRO · ${count} inbox${count !== 1 ? "es" : ""}`;
    accountTierBadge.className = "tier-badge paid";
    multiAccountNote.classList.add("hidden");
  } else {
    accountTierBadge.textContent = `FREE · 1 inbox`;
    accountTierBadge.className = "tier-badge free";
    multiAccountNote.classList.toggle("hidden", count <= 1);
  }
}

function renderLicensePanel(licenseValid) {
  if (licenseValid) {
    licenseFreeState.classList.add("hidden");
    licensePaidState.classList.remove("hidden");
    licenseStatusBadge.textContent = "ACTIVE";
    licenseStatusBadge.className = "tier-badge paid";
  } else {
    licenseFreeState.classList.remove("hidden");
    licensePaidState.classList.add("hidden");
    licenseStatusBadge.textContent = "FREE TIER";
    licenseStatusBadge.className = "tier-badge free";
    buyLicenseBtn.href = LEMON_CHECKOUT_URL;
  }
}

/* ─── Init ─────────────────────────────────────────────────────────────── */
async function init() {
  try {
    const status = await browser.runtime.sendMessage({ type: "GET_STATUS" });

    if (status.hasCode && status.detectedAt) {
      showActiveState(status);
    } else {
      showIdleState();
    }

    renderAccounts(status.accounts, status.licenseValid);
    renderLicensePanel(status.licenseValid);
  } catch (err) {
    console.error("[CodeFetcher Popup] Failed to get status:", err);
    showIdleState();
  }
}

/* ─── Account Management ─────────────────────────────────────────────────── */
async function getAccounts() {
  const data = await browser.storage.local.get("monitoredAccounts");
  return data.monitoredAccounts || [];
}

async function saveAccounts(accounts) {
  await browser.runtime.sendMessage({ type: "SAVE_ACCOUNTS", accounts });
}

async function addAccount() {
  const email = accountInput.value.trim().toLowerCase();
  if (!email || !email.includes("@")) return;

  const accounts = await getAccounts();
  if (accounts.includes(email)) {
    accountInput.value = "";
    return;
  }

  // Check license gate for > 1 account
  const data = await browser.storage.local.get("licenseValid");
  if (accounts.length >= 1 && !data.licenseValid) {
    multiAccountNote.classList.remove("hidden");
    accountInput.value = "";
    return;
  }

  accounts.push(email);
  await saveAccounts(accounts);
  renderAccounts(accounts, data.licenseValid || false);
  accountInput.value = "";
}

async function removeAccount(index) {
  const accounts = await getAccounts();
  accounts.splice(index, 1);
  const data = await browser.storage.local.get("licenseValid");
  await saveAccounts(accounts);
  renderAccounts(accounts, data.licenseValid || false);
}

/* ─── License Activation ──────────────────────────────────────────────────── */
async function activateLicense() {
  const key = licenseKeyInput.value.trim();
  if (!key) {
    setFeedback("Please enter a license key.", "error");
    return;
  }

  activateBtn.disabled = true;
  activateBtn.textContent = "Checking…";
  setFeedback("Validating with LemonSqueezy…", "loading");

  try {
    const result = await browser.runtime.sendMessage({
      type: "ACTIVATE_LICENSE",
      licenseKey: key,
    });

    if (result.valid) {
      setFeedback("✓ License activated successfully!", "success");
      setTimeout(() => {
        renderLicensePanel(true);
        // Refresh accounts panel to show paid tier
        getAccounts().then(accounts => renderAccounts(accounts, true));
      }, 1200);
    } else {
      setFeedback(result.error || "Invalid license key. Please check and retry.", "error");
      activateBtn.disabled = false;
      activateBtn.textContent = "Activate";
    }
  } catch (err) {
    setFeedback("Network error. Please try again.", "error");
    activateBtn.disabled = false;
    activateBtn.textContent = "Activate";
  }
}

function setFeedback(msg, type) {
  licenseFeedback.textContent = msg;
  licenseFeedback.className = `note ${type}`;
}

/* ─── Test / Simulate OTP ─────────────────────────────────────────────────── */
async function simulateOTP() {
  testBtn.disabled = true;
  testBtn.textContent = "Simulating…";

  try {
    const result = await browser.runtime.sendMessage({ type: "SIMULATE_OTP" });
    if (result?.code) {
      // Re-init popup to reflect the new code
      await init();
    }
  } catch (err) {
    console.warn("[CodeFetcher Popup] Simulate OTP failed:", err);
  } finally {
    testBtn.disabled = false;
    testBtn.textContent = "⚡ Simulate Detection";
  }
}

/* ─── Copy Again ──────────────────────────────────────────────────────────── */
async function copyAgain() {
  copyAgainBtn.disabled = true;
  const originalText = copyAgainBtn.innerHTML;
  copyAgainBtn.textContent = "Copied!";

  try {
    await browser.runtime.sendMessage({ type: "COPY_AGAIN" });
  } catch (err) {
    console.warn("[CodeFetcher Popup] Copy again failed:", err);
  }

  setTimeout(() => {
    copyAgainBtn.disabled = false;
    copyAgainBtn.innerHTML = originalText;
  }, 1500);
}

/* ─── Event Listeners ─────────────────────────────────────────────────────── */
copyAgainBtn.addEventListener("click", copyAgain);
testBtn.addEventListener("click", simulateOTP);
addAccountBtn.addEventListener("click", addAccount);
activateBtn.addEventListener("click", activateLicense);

accountInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addAccount();
});

licenseKeyInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") activateLicense();
});

// Auto-format license key input (insert dashes every 4 chars)
licenseKeyInput.addEventListener("input", (e) => {
  const raw = e.target.value.replace(/[-\s]/g, "").toUpperCase();
  const formatted = raw.match(/.{1,4}/g)?.join("-") || raw;
  if (formatted !== e.target.value) {
    const cursor = e.target.selectionStart;
    e.target.value = formatted;
    // Restore approximate cursor position
    e.target.setSelectionRange(cursor, cursor);
  }
});

/* ─── Boot ─────────────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", init);
