(function (root) {
  "use strict";

  const OFFICIAL_DOMAINS = {
    paypal: ["paypal.com"],
    microsoft: ["microsoft.com", "live.com", "office.com"],
    google: ["google.com", "gmail.com"],
    amazon: ["amazon.com", "amazon.in"],
    apple: ["apple.com", "icloud.com"],
    sbi: ["sbi.co.in", "onlinesbi.sbi"],
    hdfc: ["hdfcbank.com"],
    icici: ["icicibank.com"],
    paytm: ["paytm.com"],
  };

  function normalizeDomain(value) {
    return String(value || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  }

  function isPrivateHost(domain) {
    return domain === "localhost" || domain.endsWith(".local") ||
      /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(domain) ||
      domain === "::1" || domain.startsWith("[::1]");
  }

  function isIpLiteral(domain) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain) || domain.includes(":");
  }

  function levenshtein(a, b) {
    const row = Array.from({ length: b.length + 1 }, (_, index) => index);
    for (let i = 1; i <= a.length; i += 1) {
      let previous = row[0];
      row[0] = i;
      for (let j = 1; j <= b.length; j += 1) {
        const saved = row[j];
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
        previous = saved;
      }
    }
    return row[b.length];
  }

  function localAssessment(input) {
    const domain = normalizeDomain(input);
    let score = 0;
    const reasons = [];
    if (!domain || isPrivateHost(domain) || isIpLiteral(domain)) return { domain, score, reasons, skipped: true };

    if (domain.includes("xn--")) {
      score += 45;
      reasons.push("Internationalized punycode domain may conceal lookalike characters.");
    }
    const labels = domain.split(".");
    if (labels.length > 5) {
      score += 12;
      reasons.push("Unusually deep subdomain chain.");
    }
    if ((domain.match(/-/g) || []).length >= 3) {
      score += 10;
      reasons.push("Unusually high number of hyphens.");
    }

    const commonSecondLevel = new Set(["co.in", "co.uk", "com.au", "co.jp", "com.br"]);
    const suffix = labels.slice(-2).join(".");
    const nameIndex = commonSecondLevel.has(suffix) && labels.length >= 3 ? labels.length - 3 : labels.length - 2;
    const rawName = labels[nameIndex] || labels[0];
    const candidates = [rawName.replace(/[^a-z0-9]/g, ""), ...rawName.split("-").map((part) => part.replace(/[^a-z0-9]/g, ""))];
    for (const [brand, official] of Object.entries(OFFICIAL_DOMAINS)) {
      const isOfficial = official.some((item) => domain === item || domain.endsWith(`.${item}`));
      const maxDistance = brand.length <= 3 ? 1 : 2;
      const resemblesBrand = candidates.some((candidate) => candidate.length >= 3 && levenshtein(candidate, brand) <= maxDistance);
      if (!isOfficial && resemblesBrand) {
        score = Math.max(60, score + 35);
        reasons.push(`Domain closely resembles ${brand} but is not an official ${brand} domain.`);
        break;
      }
    }
    return { domain, score: Math.min(score, 100), reasons, skipped: false };
  }

  function mergeAssessment(local, remote) {
    const remoteScore = Number(remote && remote.risk_score) || 0;
    const score = Math.max(local.score, remoteScore);
    const reasons = [...local.reasons, ...((remote && remote.reasons) || [])];
    let verdict = "low_risk";
    if (score >= 75) verdict = "dangerous";
    else if (score >= 55) verdict = "suspicious";
    else if (score >= 30) verdict = "caution";
    else if (remote && remote.verdict === "unknown") verdict = "unknown";
    return {
      domain: local.domain,
      verdict,
      riskScore: score,
      reasons: [...new Set(reasons)],
      confidence: remote ? remote.confidence : "local-only",
      checkedAt: Date.now(),
      privacy: "Only the domain is checked. Paths, queries, page content, cookies and browsing history are not sent.",
      remoteAvailable: Boolean(remote),
    };
  }

  const api = { normalizeDomain, isPrivateHost, isIpLiteral, levenshtein, localAssessment, mergeAssessment };
  root.GuardianCore = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : globalThis);
