const express = require("express");
const router  = express.Router();
const db      = require("../db");

const { runPlaybook }      = require("../playbookEngine");
const { enrichAlert }      = require("../services/threatIntel");
const { sendNotification } = require("../services/notificationService");

router.post("/ingest", (req, res) => {
    const { source, type, severity, message } = req.body;

    if (!source || !type || !severity) {
        return res.status(400).json({ error: "Missing required fields: source, type, severity" });
    }

    const allowedSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    if (!allowedSeverities.includes(severity.toUpperCase())) {
        return res.status(400).json({ error: `Invalid severity. Use: ${allowedSeverities.join(", ")}` });
    }

    const alertData = { source, type, severity: severity.toUpperCase(), message: message || "No message" };

    console.log("\n[Pipeline] Step 1: Threat Intelligence enrichment...");
    const enrichment = enrichAlert(alertData);

    console.log("[Pipeline] Step 2: Running Playbook Engine...");
    const automatedActions = runPlaybook(alertData);

    console.log("[Pipeline] Step 3: Saving to database...");
    const enrichedMessage = `${alertData.message} | ThreatCategory: ${enrichment.threatCategory} | RiskScore: ${enrichment.riskScore}`;
    const sql = "INSERT INTO alerts (source, type, severity, message, status) VALUES (?, ?, ?, ?, 'OPEN')";

    db.query(sql, [source, type, severity.toUpperCase(), enrichedMessage], (err, result) => {
        if (err) {
            console.error("Database Error:", err);
            return res.status(500).json({ error: "Database insert failed" });
        }

        const alertId = result.insertId;

        const intelSql = `INSERT INTO threat_intel_log (alert_id, threat_category, risk_score, has_malicious_ip, ip_reputation, recommendation) VALUES (?, ?, ?, ?, ?, ?)`;
        db.query(intelSql, [alertId, enrichment.threatCategory, enrichment.riskScore, enrichment.hasMaliciousIP ? 1 : 0, JSON.stringify(enrichment.ipReputation), enrichment.recommendation], (err) => {
            if (err) console.error("[ThreatIntel] Log error:", err.message);
        });

        console.log("[Pipeline] Step 4: Sending notifications...");
        const notification = sendNotification({ ...alertData, id: alertId }, enrichment);

        console.log(`[Pipeline] Complete for Alert #${alertId}\n`);
        res.json({
            status: "Success",
            alertId,
            actions: automatedActions,
            threatIntel: {
                category: enrichment.threatCategory,
                riskScore: enrichment.riskScore,
                hasMaliciousIP: enrichment.hasMaliciousIP,
                recommendation: enrichment.recommendation
            },
            notification: {
                notifiedRoles: notification.notifyRoles,
                escalateAfter: notification.escalateAfter
            }
        });
    });
});

router.get("/", (req, res) => {
    const { severity, status, limit = 100 } = req.query;
    let sql = "SELECT * FROM alerts";
    const params = [], conditions = [];
    if (severity) { conditions.push("severity = ?"); params.push(severity.toUpperCase()); }
    if (status)   { conditions.push("status = ?");   params.push(status.toUpperCase()); }
    if (conditions.length > 0) sql += " WHERE " + conditions.join(" AND ");
    sql += " ORDER BY created_at DESC LIMIT ?";
    params.push(parseInt(limit));
    db.query(sql, params, (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to fetch alerts" });
        res.json(results);
    });
});

router.get("/intel", (req, res) => {
    db.query("SELECT * FROM threat_intel_log ORDER BY created_at DESC LIMIT 50", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to fetch intel" });
        res.json(results);
    });
});

router.get("/notifications", (req, res) => {
    db.query("SELECT * FROM notification_log ORDER BY created_at DESC LIMIT 50", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to fetch notifications" });
        res.json(results);
    });
});

router.patch("/:id/status", (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const allowedStatuses = ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"];
    if (!allowedStatuses.includes(status?.toUpperCase())) {
        return res.status(400).json({ error: `Invalid status. Use: ${allowedStatuses.join(", ")}` });
    }
    db.query("UPDATE alerts SET status = ? WHERE id = ?", [status.toUpperCase(), id], (err, result) => {
        if (err) return res.status(500).json({ error: "Update failed" });
        if (result.affectedRows === 0) return res.status(404).json({ error: "Alert not found" });
        res.json({ status: "Updated", alertId: id, newStatus: status.toUpperCase() });
    });
});

router.get("/stats/summary", (req, res) => {
    const sql = `SELECT COUNT(*) as total, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high, SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) as medium, SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) as open_alerts, SUM(CASE WHEN status='RESOLVED' THEN 1 ELSE 0 END) as resolved FROM alerts`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Stats query failed" });
        res.json(results[0]);
    });
});

router.get("/report", (req, res) => {
    db.query("SELECT * FROM alerts ORDER BY created_at DESC", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to generate report" });
        const critical = results.filter(a => a.severity === "CRITICAL").length;
        const high     = results.filter(a => a.severity === "HIGH").length;
        const open     = results.filter(a => a.status === "OPEN").length;
        let report = `==========================================\n         SOAR INCIDENT REPORT\n         Generated: ${new Date().toLocaleString()}\n==========================================\n\nSUMMARY\n--------\nTotal   : ${results.length}\nCritical: ${critical}\nHigh    : ${high}\nOpen    : ${open}\n\nDETAILED INCIDENTS\n------------------\n\n`;
        results.forEach(alert => {
            report += `[ALERT #${alert.id}]\n  Severity  : ${alert.severity}\n  Type      : ${alert.type}\n  Source    : ${alert.source}\n  Status    : ${alert.status}\n  Timestamp : ${alert.created_at}\n  Message   : ${alert.message}\n------------------------------------------\n`;
        });
        res.setHeader("Content-Type", "text/plain");
        res.setHeader("Content-Disposition", "attachment; filename=SOAR_Report.txt");
        res.send(report);
    });
});

module.exports = router;

