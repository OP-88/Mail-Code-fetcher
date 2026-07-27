/**
 * lib/lemonsqueezy.js
 *
 * Thin client-side wrapper for LemonSqueezy License Key API.
 * Used by background.js for license activation and validation.
 *
 * Docs: https://docs.lemonsqueezy.com/api/licenses
 *
 * This file is intentionally standalone (no imports) for
 * compatibility with Firefox MV3 non-module background scripts.
 */

// NOTE: This file is imported by background.js via concatenation at runtime.
// Functions defined here are available in background.js global scope
// because background.scripts loads them sequentially.
// (background.json: "scripts": ["lib/lemonsqueezy.js", "background.js"])
