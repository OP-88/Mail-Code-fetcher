# Air-Gapped Mail Code Fetcher

> **Zero-trust, auto-wiping 2FA code fetcher for Gmail & Outlook.**  
> Firefox Extension · Manifest V3 · Local-only execution · No remote data logging.

![Version](https://img.shields.io/badge/version-1.0.0-teal) ![MV3](https://img.shields.io/badge/Manifest-V3-blue) ![Firefox](https://img.shields.io/badge/Firefox-115%2B-orange)

---

## Overview

This extension monitors your Gmail and Outlook Web inboxes for incoming 2FA / OTP verification emails, automatically extracts the code, copies it to your clipboard, and **wipes the clipboard clean after 60 seconds** — no servers, no analytics, no remote code.

```
[ Gmail / Outlook Tab ]
       │  MutationObserver fires on new email
       ▼
[ content.js ]  ──(raw text)──>  [ background.js ]
                                      │
                                      ├─ RegEx token isolation (RAM only)
                                      ├─ Relay: WRITE_CLIPBOARD → content.js
                                      ├─ OS notification
                                      └─ Alarm: wipe clipboard @ 60s
```

---

## Directory Structure

```
mail-code-fetcher/
├── manifest.json          — MV3 extension manifest
├── background.js          — Service worker: regex engine, alarm, IPC
├── content.js             — DOM observer + clipboard relay
├── popup/
│   ├── popup.html         — Extension popup UI
│   ├── popup.css          — Dark glassmorphism styles
│   └── popup.js           — Popup controller
├── lib/
│   └── lemonsqueezy.js    — LemonSqueezy license API wrapper
└── assets/
    └── icon-128.png       — Extension icon
```

---

## Setup & Development

### Load as Temporary Extension (Firefox)

1. Open Firefox → `about:debugging`
2. Click **"This Firefox"** → **"Load Temporary Add-on…"**
3. Select `mail-code-fetcher/manifest.json`
4. The extension icon appears in your toolbar.

### Test OTP Detection

1. Click the extension icon → popup opens
2. Click **"⚡ Simulate Detection"** — a random 6-digit code is generated, copied, and the 60s countdown starts
3. Open Notepad / any text field → `Ctrl+V` — the code should paste
4. Wait 60 seconds → paste again — clipboard should be empty

### Test with a Real Email

1. Send yourself a 2FA email (trigger a login on GitHub, Slack, AWS, etc.)
2. Open Gmail or Outlook Web
3. Open the email — the extension auto-detects the code within ~1 second of the email loading
4. An OS notification confirms the code was copied

---

## Monetization Setup (LemonSqueezy)

### Step 1 — Create a Product

1. Log in to [app.lemonsqueezy.com](https://app.lemonsqueezy.com)
2. **Products → New Product**
   - Name: `Air-Gapped Mail Code Fetcher — Multi-Account Unlock`
   - Type: **License Key** (enables automatic key generation)
   - Price: `$4.00 USD` (one-time)
   - License key: **1 activation**, no expiry
3. Save → copy the **Variant ID** from the product URL

### Step 2 — Wire Up the Checkout URL

In `popup/popup.js`, replace the placeholder:

```js
// Line ~30
const LEMON_CHECKOUT_URL = "https://store.lemonsqueezy.com/buy/YOUR_PRODUCT_VARIANT_ID";
//                                                                 ^^^^^^^^^^^^^^^^^^^
//                                                    Paste your real variant ID here
```

### Step 3 — How License Activation Works

```
User clicks "Get Multi-Account Unlock ($4)"
  → Opens LemonSqueezy checkout in new tab
  → User pays → receives license key via email
  → User opens extension popup
  → Pastes key into "License Key" field → clicks Activate
  → Extension calls: POST https://api.lemonsqueezy.com/v1/licenses/activate
  → On success: licenseValid = true stored in browser.storage.local
  → Multi-account monitoring unlocked
```

---

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Content isolation | Content script uses `innerText` only — never `innerHTML` or `eval()` |
| IPC origin check | Background validates `sender.id === runtime.id` AND `sender.tab.url` domain |
| Clipboard write | Relayed to content script (page context) — background SW cannot write directly |
| Ephemeral storage | Pending code stored in `storage.session` — cleared on browser close |
| Clipboard wipe | Overwritten with empty string after exactly 60 seconds |
| No remote logging | Zero analytics, zero telemetry — all processing is client-side |
| License key only | LemonSqueezy API called only on explicit user action |

---

## Supported Email Patterns (RegEx Engine)

The 4-pass regex engine covers:

| Pattern Type | Example |
|---|---|
| Context-leading | `"Your verification code is 482910"` |
| Label-prefixed | `"OTP: 482910"` / `"Code: G7H2K1"` |
| Trailing context | `"482910 is your security code"` |
| Verb-lookahead | `"Enter 482910 to verify your account"` |

Tested formats: GitHub, Slack, AWS, Google, Microsoft, bank OTPs, Stripe, Twilio.

---

## AMO Submission Checklist

- [x] No remote script loading (`script-src 'self'` only)
- [x] Strict CSP (`connect-src` limited to `api.lemonsqueezy.com`)
- [x] No `eval()` or `innerHTML`
- [x] No tracking or analytics code
- [x] Minimal permissions (only what's needed)
- [x] Privacy disclosure: zero remote data collection

---

## License

MIT — See LICENSE file.
