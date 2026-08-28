const params = new URLSearchParams(location.search);
const tabId = Number(params.get("tab"));
let warning;

(async () => {
  warning = await chrome.runtime.sendMessage({ type: "GET_WARNING", tabId });
  if (!warning) return;
  document.getElementById("domain").textContent = warning.result.domain;
  document.getElementById("risk").textContent = `${warning.result.riskScore}/100`;
  const list = document.getElementById("reasons");
  warning.result.reasons.forEach((reason) => {
    const item = document.createElement("li"); item.textContent = reason; list.appendChild(item);
  });
})();

document.getElementById("back").addEventListener("click", () => location.replace("https://sentinel-trace.vercel.app"));
document.getElementById("proceed").addEventListener("click", async () => {
  if (!warning || !/^https?:\/\//.test(warning.originalUrl)) return;
  await chrome.runtime.sendMessage({ type: "BYPASS", domain: warning.result.domain });
  location.replace(warning.originalUrl);
});
