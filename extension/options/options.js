const DEFAULTS = { enabled: true, apiBaseUrl: "https://sentineltrace-backend.onrender.com", warningThreshold: 75, cacheMinutes: 15 };
const $ = (id) => document.getElementById(id);
(async () => {
  const value = { ...DEFAULTS, ...(await chrome.storage.sync.get(DEFAULTS)) };
  $("enabled").checked = value.enabled; $("api").value = value.apiBaseUrl;
  $("threshold").value = value.warningThreshold; $("thresholdValue").value = value.warningThreshold;
  $("cache").value = value.cacheMinutes;
})();
$("threshold").addEventListener("input", () => $("thresholdValue").value = $("threshold").value);
$("save").addEventListener("click", async () => {
  const apiBaseUrl = $("api").value.trim().replace(/\/$/, "");
  if (!/^https:\/\//.test(apiBaseUrl)) { $("saved").textContent = "Use an HTTPS backend URL."; return; }
  await chrome.storage.sync.set({ enabled: $("enabled").checked, apiBaseUrl, warningThreshold: Number($("threshold").value), cacheMinutes: Number($("cache").value) });
  await chrome.storage.local.remove("guardianCache");
  $("saved").textContent = "Saved. Cached verdicts were cleared.";
});
