importScripts("lib/core.js");

const DEFAULTS = {
  enabled: true,
  apiBaseUrl: "https://sentineltrace-backend.onrender.com",
  warningThreshold: 75,
  cacheMinutes: 15,
};
const MAX_CACHE_ENTRIES = 500;

async function settings() {
  return { ...DEFAULTS, ...(await chrome.storage.sync.get(DEFAULTS)) };
}

async function cached(domain, ttlMinutes) {
  const { guardianCache = {} } = await chrome.storage.local.get("guardianCache");
  const item = guardianCache[domain];
  if (item && Date.now() - item.savedAt < ttlMinutes * 60_000) return item.value;
  return null;
}

async function saveCache(domain, value) {
  const { guardianCache = {} } = await chrome.storage.local.get("guardianCache");
  guardianCache[domain] = { value, savedAt: Date.now() };
  const ordered = Object.entries(guardianCache).sort((a, b) => b[1].savedAt - a[1].savedAt);
  await chrome.storage.local.set({ guardianCache: Object.fromEntries(ordered.slice(0, MAX_CACHE_ENTRIES)) });
}

async function remoteCheck(domain, apiBaseUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6500);
  try {
    const endpoint = `${apiBaseUrl.replace(/\/$/, "")}/guardian/check?domain=${encodeURIComponent(domain)}`;
    const response = await fetch(endpoint, { signal: controller.signal, credentials: "omit" });
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function assessUrl(rawUrl, force = false) {
  const config = await settings();
  if (!config.enabled && !force) return { skipped: true, reason: "Protection is paused." };
  let url;
  try { url = new URL(rawUrl); } catch { return { skipped: true, reason: "Unsupported URL." }; }
  if (!/^https?:$/.test(url.protocol)) return { skipped: true, reason: "Unsupported protocol." };
  const local = GuardianCore.localAssessment(url.hostname);
  if (local.skipped) return { skipped: true, reason: "Local/private address is not submitted.", domain: local.domain };

  if (!force) {
    const hit = await cached(local.domain, config.cacheMinutes);
    if (hit) return { ...hit, cache: "hit" };
  }
  let remote = null;
  try { remote = await remoteCheck(local.domain, config.apiBaseUrl); } catch { /* local result remains usable */ }
  const result = { ...GuardianCore.mergeAssessment(local, remote), cache: "miss" };
  await saveCache(local.domain, result);
  return result;
}

async function isBypassed(domain) {
  const key = `bypass:${domain}`;
  const value = (await chrome.storage.session.get(key))[key];
  if (value && value > Date.now()) return true;
  if (value) await chrome.storage.session.remove(key);
  return false;
}

function badge(tabId, result) {
  if (!tabId || tabId < 0) return;
  const map = { dangerous: ["!", "#ef4444"], suspicious: ["!", "#f97316"], caution: ["?", "#f59e0b"], low_risk: ["✓", "#10b981"], unknown: ["?", "#64748b"] };
  const [text, color] = map[result.verdict] || ["", "#64748b"];
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

async function inspect(tabId, url, allowRedirect = true, force = false) {
  const result = await assessUrl(url, force);
  await chrome.storage.session.set({ [`tab:${tabId}`]: result });
  if (result.skipped) return result;
  badge(tabId, result);
  const config = await settings();
  if (allowRedirect && result.riskScore >= config.warningThreshold && !(await isBypassed(result.domain))) {
    const warningKey = `warning:${tabId}`;
    await chrome.storage.session.set({ [warningKey]: { result, originalUrl: url } });
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`warning/warning.html?tab=${tabId}`) });
  }
  return result;
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) inspect(details.tabId, details.url).catch(() => undefined);
});

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.sync.get(Object.keys(DEFAULTS));
  const missing = Object.fromEntries(Object.entries(DEFAULTS).filter(([key]) => existing[key] === undefined));
  if (Object.keys(missing).length) await chrome.storage.sync.set(missing);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message.type === "SCAN_TAB") return inspect(message.tabId, message.url, false, true);
    if (message.type === "GET_TAB_STATUS") return (await chrome.storage.session.get(`tab:${message.tabId}`))[`tab:${message.tabId}`] || null;
    if (message.type === "GET_WARNING") return (await chrome.storage.session.get(`warning:${message.tabId}`))[`warning:${message.tabId}`] || null;
    if (message.type === "BYPASS") {
      await chrome.storage.session.set({ [`bypass:${message.domain}`]: Date.now() + 10 * 60_000 });
      return { ok: true };
    }
    return null;
  })().then(sendResponse).catch((error) => sendResponse({ error: error.message }));
  return true;
});
