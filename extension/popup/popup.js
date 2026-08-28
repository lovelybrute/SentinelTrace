const $ = (id) => document.getElementById(id);
let tab;

function paint(result) {
  if (!result || result.skipped) {
    $("verdict").textContent = result?.reason || "Not checked";
    return;
  }
  const labels = { dangerous: "Dangerous", suspicious: "Suspicious", caution: "Use caution", low_risk: "No current flags", unknown: "Unknown reputation" };
  $("status").className = `status ${result.verdict}`;
  $("symbol").textContent = result.verdict === "low_risk" ? "✓" : result.verdict === "dangerous" ? "!" : "?";
  $("verdict").textContent = `${labels[result.verdict] || result.verdict} · ${result.riskScore}/100`;
  $("domain").textContent = result.domain;
  $("meter").style.width = `${result.riskScore}%`;
  $("reason").textContent = result.reasons?.[0] || result.privacy;
}

(async () => {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  paint(await chrome.runtime.sendMessage({ type: "GET_TAB_STATUS", tabId: tab.id }));
})();

$("scan").addEventListener("click", async () => {
  $("verdict").textContent = "Scanning…";
  paint(await chrome.runtime.sendMessage({ type: "SCAN_TAB", tabId: tab.id, url: tab.url }));
});
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
