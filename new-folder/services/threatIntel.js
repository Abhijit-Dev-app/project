// services/threatIntel.js
// Component 1: Threat Intelligence Engine
// Enriches alerts with IP reputation, threat classification, and risk scoring

const KNOWN_MALICIOUS_IPS = [
  "192.168.1.100", "10.0.0.55", "185.220.101.1",
  "45.33.32.156", "198.199.100.1"
];

const THREAT_CATEGORIES = {
  "brute force":        { category: "Credential Attack",   riskScore: 85 },
  "unauthorized access":{ category: "Intrusion Attempt",   riskScore: 90 },
  "malware":            { category: "Malware Infection",   riskScore: 95 },
  "ransomware":         { category: "Ransomware",          riskScore: 99 },
  "port scan":          { category: "Reconnaissance",      riskScore: 60 },
  "reconnaissance":     { category: "Reconnaissance",      riskScore: 65 },
  "suspicious":         { category: "Suspicious Activity", riskScore: 50 },
  "default":            { category: "Unknown Threat",      riskScore: 40 }
};

// Simulate IP reputation lookup
const checkIPReputation = (message) => {
  const ipRegex = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  const ipsFound = message.match(ipRegex) || [];

  const results = ipsFound.map(ip => ({
    ip,
    malicious: KNOWN_MALICIOUS_IPS.includes(ip),
    reputation: KNOWN_MALICIOUS_IPS.includes(ip) ? "MALICIOUS" : "UNKNOWN"
  }));

  return results;
};

// Classify threat and calculate risk score
const classifyThreat = (type) => {
  const typeLower = (type || "").toLowerCase();
  for (const [keyword, data] of Object.entries(THREAT_CATEGORIES)) {
    if (typeLower.includes(keyword)) return data;
  }
  return THREAT_CATEGORIES["default"];
};

// Main enrichment function
const enrichAlert = (alert) => {
  const ipReputation  = checkIPReputation(alert.message || "");
  const threatInfo    = classifyThreat(alert.type);
  const hasMaliciousIP = ipReputation.some(r => r.malicious);

  // Boost risk score if malicious IP found
  const finalRiskScore = hasMaliciousIP
    ? Math.min(threatInfo.riskScore + 10, 100)
    : threatInfo.riskScore;

  const enriched = {
    originalAlert  : alert,
    threatCategory : threatInfo.category,
    riskScore      : finalRiskScore,
    ipReputation   : ipReputation,
    hasMaliciousIP : hasMaliciousIP,
    recommendation : getRecommendation(finalRiskScore),
    enrichedAt     : new Date().toISOString()
  };

  console.log(`[Threat Intel] Alert enriched → Category: ${enriched.threatCategory} | Risk Score: ${enriched.riskScore}`);
  return enriched;
};

const getRecommendation = (riskScore) => {
  if (riskScore >= 90) return "IMMEDIATE ACTION REQUIRED — Isolate affected systems";
  if (riskScore >= 70) return "HIGH PRIORITY — Investigate and contain within 1 hour";
  if (riskScore >= 50) return "MEDIUM PRIORITY — Review and monitor closely";
  return "LOW PRIORITY — Log and monitor";
};

module.exports = { enrichAlert, checkIPReputation, classifyThreat };
