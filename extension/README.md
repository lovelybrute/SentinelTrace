# SentinelTrace Browser Guardian

Manifest V3 extension for Chrome and Microsoft Edge. It checks only the current
page's normalized domain, combines transparent local lookalike/punycode signals
with the SentinelTrace `/guardian/check` reputation verdict, caches results for
15 minutes, and shows a warning interstitial only above the configured threshold.

## Load unpacked

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select this `extension` directory.
4. Open Guardian settings and confirm the backend is
   `https://sentineltrace-backend.onrender.com`.

The extension requests access to HTTP/HTTPS pages so its background worker can
observe top-level domain navigations. It does not inject page scripts, inspect
page content, read forms, collect cookies, or transmit full URLs/history.

## Verify

```bash
node extension/tests/core.test.cjs
```

Use only controlled test domains. Never deliberately browse a live malicious
site to demonstrate the warning page.
