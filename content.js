/**
 * content.js — DOM Ingestion Engine
 *
 * Responsibilities:
 *  1. Monitor DOM insertions via MutationObserver for Gmail and Outlook webmail.
 *  2. Pre-filter nodes by keyword presence before sending to background.
 *  3. Deduplicate identical payloads within a 30-second window.
 *  4. Relay clipboard write/wipe instructions from the background script.
 *     (MV3 service workers lack user gesture context — content script acts as relay.)
 *
 * Security Rules:
 *  - Never use innerHTML or eval().
 *  - Use innerText only (strips hidden DOM / XSS vectors).
 *  - Does not store, log, or transmit raw email text beyond the background script.
 */

"use strict";

let lastSignature = "";
let lastTimestamp = 0;

/* --- Selector Sets -------------------------------------------------------- */
const GMAIL_SELECTORS = [
  ".a3s.aiL",   // Primary Gmail message body
  ".ii.gt",     // Fallback Gmail container
];

const OUTLOOK_SELECTORS = [
  '[aria-label="Message body"]',     // Primary Outlook Web
  ".ReadingPaneContent",             // Classic Outlook Web
  ".allowTextSelection",             // Legacy OWA
  '[data-testid="message-body"]',    // New Outlook Web (React)
  ".x_WordSection1",                 // Outlook HTML email wrapper
];

const ALL_SELECTORS = [...GMAIL_SELECTORS, ...OUTLOOK_SELECTORS].join(", ");

/* --- DOM Scanner ---------------------------------------------------------- */
function scanWebmailDOM() {
  const targetNodes = document.querySelectorAll(ALL_SELECTORS);

  targetNodes.forEach((node) => {
    const rawText = node.innerText || "";
    if (rawText.length < 4) return;

    // Fast keyword pre-filter — avoids sending non-2FA emails to background
    if (!/(?:code|verification|otp|auth|pin|confirmation|security|one.time|token)/i.test(rawText)) {
      return;
    }

    const now = Date.now();
    const signature = rawText.slice(0, 120); // Snapshot for deduplication

    // Deduplicate: same content within 30s is skipped
    if (signature === lastSignature && now - lastTimestamp < 30000) return;

    lastSignature = signature;
    lastTimestamp = now;

    // Forward sanitized text payload to background for RegEx processing
    browser.runtime.sendMessage({
      type: "PARSE_EMAIL_PAYLOAD",
      payload: rawText,
    });
  });
}

/* --- Clipboard Relay ------------------------------------------------------ */
// Background instructs us to write/wipe clipboard (MV3 workaround).
browser.runtime.onMessage.addListener((message) => {
  if (message.type === "WRITE_CLIPBOARD") {
    navigator.clipboard.writeText(message.text ?? "").catch((err) => {
      console.warn("[CodeFetcher] Clipboard relay write failed:", err);
    });
  }
});

/* --- MutationObserver ----------------------------------------------------- */
const observer = new MutationObserver(() => {
  scanWebmailDOM();
});

// Wait for body to be available
function startObserver() {
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
    scanWebmailDOM(); // Initial scan on load
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      observer.observe(document.body, { childList: true, subtree: true });
      scanWebmailDOM();
    });
  }
}

startObserver();
