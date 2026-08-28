const assert = require("node:assert/strict");
const core = require("../lib/core.js");

assert.equal(core.normalizeDomain(" PayPal.COM. "), "paypal.com");
assert.equal(core.isPrivateHost("192.168.1.5"), true);
assert.equal(core.localAssessment("8.8.8.8").skipped, true);
assert.equal(core.localAssessment("paypal.com").score, 0);
assert.ok(core.localAssessment("paypa1-security.example").score >= 55);
assert.ok(core.localAssessment("sb1.co.in").score >= 55);
assert.ok(core.localAssessment("xn--pple-43d.example").score >= 45);

const merged = core.mergeAssessment(core.localAssessment("bad.example"), {
  verdict: "dangerous", risk_score: 85, confidence: "high", reasons: ["Provider evidence"],
});
assert.equal(merged.verdict, "dangerous");
assert.equal(merged.riskScore, 85);
console.log("Browser Guardian core tests: OK");
