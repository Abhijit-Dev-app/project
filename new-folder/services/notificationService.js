// services/notificationService.js
// Component 2: Notification & Escalation System
// Handles alert notifications, escalation rules, and notification logging

const db = require("../db");

// Notification channels config
const NOTIFICATION_CONFIG = {
  console : true,   // Always log to console
  database: true,   // Log notifications to DB
  webhook : false,  // Set true + add webhookUrl to enable
  webhookUrl: "http://your-webhook-url/notify"
};

// Escalation rules — who gets notified based on severity
const ESCALATION_RULES = {
  CRITICAL: {
    notifyRoles : ["ADMIN", "SOC_LEAD", "INCIDENT_RESPONSE"],
    escalateAfter: 5,    // minutes before auto-escalation
    channels    : ["console", "database", "webhook"]
  },
  HIGH: {
    notifyRoles : ["ADMIN", "SOC_ANALYST"],
    escalateAfter: 15,
    channels    : ["console", "database"]
  },
  MEDIUM: {
    notifyRoles : ["SOC_ANALYST"],
    escalateAfter: 60,
    channels    : ["console", "database"]
  },
  LOW: {
    notifyRoles : ["SOC_ANALYST"],
    escalateAfter: null, // No escalation
    channels    : ["console"]
  }
};

// Send notification based on severity
const sendNotification = (alert, enrichmentData = null) => {
  const severity = (alert.severity || "LOW").toUpperCase();
  const rule     = ESCALATION_RULES[severity] || ESCALATION_RULES["LOW"];

  const notification = {
    alertId      : alert.id || "N/A",
    severity     : severity,
    type         : alert.type,
    source       : alert.source,
    notifyRoles  : rule.notifyRoles,
    riskScore    : enrichmentData ? enrichmentData.riskScore : "N/A",
    recommendation: enrichmentData ? enrichmentData.recommendation : "Review alert",
    escalateAfter: rule.escalateAfter ? `${rule.escalateAfter} minutes` : "No escalation",
    timestamp    : new Date().toISOString()
  };

  // Console notification
  if (rule.channels.includes("console")) {
    logToConsole(notification);
  }

  // Database notification log
  if (rule.channels.includes("database") && NOTIFICATION_CONFIG.database) {
    logToDatabase(notification);
  }

  return notification;
};

// Console logging
const logToConsole = (notification) => {
  const icons = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" };
  const icon  = icons[notification.severity] || "⚪";

  console.log(`\n${icon} [NOTIFICATION] ─────────────────────────`);
  console.log(`   Alert ID    : #${notification.alertId}`);
  console.log(`   Severity    : ${notification.severity}`);
  console.log(`   Type        : ${notification.type}`);
  console.log(`   Risk Score  : ${notification.riskScore}`);
  console.log(`   Notify      : ${notification.notifyRoles.join(", ")}`);
  console.log(`   Action      : ${notification.recommendation}`);
  console.log(`   Escalate In : ${notification.escalateAfter}`);
  console.log(`────────────────────────────────────────────\n`);
};

// Log notification to database
const logToDatabase = (notification) => {
  const sql = `
    INSERT INTO notification_log 
    (alert_id, severity, type, notify_roles, risk_score, recommendation, created_at)
    VALUES (?, ?, ?, ?, ?, ?, NOW())
  `;

  db.query(sql, [
    notification.alertId,
    notification.severity,
    notification.type,
    notification.notifyRoles.join(", "),
    notification.riskScore,
    notification.recommendation
  ], (err) => {
    if (err) console.error("[Notification] DB log error:", err.message);
    else console.log(`[Notification] Logged to DB for Alert #${notification.alertId}`);
  });
};

module.exports = { sendNotification, ESCALATION_RULES };
