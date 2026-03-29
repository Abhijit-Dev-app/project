const express = require("express");
const router  = express.Router();
const db      = require("../db");

const { runPlaybook }      = require("../playbookEngine");
const { enrichAlert }      = require("../services/threatIntel");
const { sendNotification } = require("../services/notificationService");

// ─────────────────────────────────────────────────────────
// POST /api/alerts/ingest
// ─────────────────────────────────────────────────────────
router.post("/ingest", async (req, res) => {
    const { source, type, severity, message } = req.body;

    if (!source || !type || !severity) {
        return res.status(400).json({ error: "Missing required fields: source, type, severity" });
    }

    const allowedSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    if (!allowedSeverities.includes(severity.toUpperCase())) {
        return res.status(400).json({ error: `Invalid severity. Use: ${allowedSeverities.join(", ")}` });
    }

    const alertData = { source, type, severity: severity.toUpperCase(), message: message || "No message" };

    // Step 1: Threat Intelligence enrichment
    console.log("\n[Pipeline] Step 1: Threat Intelligence enrichment...");
    const enrichment = enrichAlert(alertData);

    // Step 2: Save to database first (need alertId for playbook)
    console.log("[Pipeline] Step 2: Saving to database...");
    const enrichedMessage = `${alertData.message} | ThreatCategory: ${enrichment.threatCategory} | RiskScore: ${enrichment.riskScore}`;
    const sql = "INSERT INTO alerts (source, type, severity, message, status) VALUES (?, ?, ?, ?, 'OPEN')";

    db.query(sql, [source, type, severity.toUpperCase(), enrichedMessage], async (err, result) => {
        if (err) {
            console.error("Database Error:", err);
            return res.status(500).json({ error: "Database insert failed" });
        }

        const alertId = result.insertId;

        // Step 3: Log threat intel
        const intelSql = `INSERT INTO threat_intel_log (alert_id, threat_category, risk_score, has_malicious_ip, ip_reputation, recommendation) VALUES (?, ?, ?, ?, ?, ?)`;
        db.query(intelSql, [
            alertId,
            enrichment.threatCategory,
            enrichment.riskScore,
            enrichment.hasMaliciousIP ? 1 : 0,
            JSON.stringify(enrichment.ipReputation),
            enrichment.recommendation
        ], (err) => {
            if (err) console.error("[ThreatIntel] Log error:", err.message);
        });

        // Step 4: Run Playbook Engine (async — reads from DB)
        console.log("[Pipeline] Step 3: Running Playbook Engine...");
        const automatedActions = await runPlaybook(alertData, alertId);

        // Step 5: Send notifications
        console.log("[Pipeline] Step 4: Sending notifications...");
        const notification = sendNotification({ ...alertData, id: alertId }, enrichment);

        console.log(`[Pipeline] ✅ Complete for Alert #${alertId}\n`);
        res.json({
            status: "Success",
            alertId,
            actions: automatedActions,
            threatIntel: {
                category       : enrichment.threatCategory,
                riskScore      : enrichment.riskScore,
                hasMaliciousIP : enrichment.hasMaliciousIP,
                recommendation : enrichment.recommendation
            },
            notification: {
                notifiedRoles : notification.notifyRoles,
                escalateAfter : notification.escalateAfter
            }
        });
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/alerts/stats/summary
// ─────────────────────────────────────────────────────────
router.get("/stats/summary", (req, res) => {
    const sql = `
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'HIGH'     THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'MEDIUM'   THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN status   = 'OPEN'     THEN 1 ELSE 0 END) as open_alerts,
            SUM(CASE WHEN status   = 'RESOLVED' THEN 1 ELSE 0 END) as resolved
        FROM alerts
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: "Stats query failed" });
        res.json(results[0]);
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/alerts/intel
// ─────────────────────────────────────────────────────────
router.get("/intel", (req, res) => {
    db.query("SELECT * FROM threat_intel_log ORDER BY created_at DESC LIMIT 50", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to fetch intel" });
        res.json(results);
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/alerts/notifications
// ─────────────────────────────────────────────────────────
router.get("/notifications", (req, res) => {
    db.query("SELECT * FROM notification_log ORDER BY created_at DESC LIMIT 50", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to fetch notifications" });
        res.json(results);
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/alerts/report — Download incident report
// ─────────────────────────────────────────────────────────
router.get("/report", (req, res) => {
    db.query("SELECT * FROM alerts ORDER BY created_at DESC", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to generate report" });

        const critical = results.filter(a => a.severity === "CRITICAL").length;
        const high     = results.filter(a => a.severity === "HIGH").length;
        const open     = results.filter(a => a.status === "OPEN").length;

        let report = `==========================================\n`;
        report += `         SOAR INCIDENT REPORT\n`;
        report += `         Generated: ${new Date().toLocaleString()}\n`;
        report += `==========================================\n\n`;
        report += `SUMMARY\n--------\n`;
        report += `Total   : ${results.length}\n`;
        report += `Critical: ${critical}\n`;
        report += `High    : ${high}\n`;
        report += `Open    : ${open}\n\n`;
        report += `DETAILED INCIDENTS\n------------------\n\n`;

        results.forEach(alert => {
            report += `[ALERT #${alert.id}]\n`;
            report += `  Severity    : ${alert.severity}\n`;
            report += `  Type        : ${alert.type}\n`;
            report += `  Source      : ${alert.source}\n`;
            report += `  Status      : ${alert.status}\n`;
            report += `  Assigned To : ${alert.assigned_to || 'Unassigned'}\n`;
            report += `  Timestamp   : ${alert.created_at}\n`;
            report += `  Message     : ${alert.message}\n`;
            report += `------------------------------------------\n`;
        });

        res.setHeader("Content-Type", "text/plain");
        res.setHeader("Content-Disposition", "attachment; filename=SOAR_Report.txt");
        res.send(report);
    });
});
// ADD THIS ROUTE in routes/alerts.js
// Place it BEFORE the GET "/" route (after /report route)

// ─────────────────────────────────────────────────────────
// GET /api/alerts/:id/details — Full alert details
// Returns alert + threat intel + playbook executions + linked ticket
// ─────────────────────────────────────────────────────────
router.get("/:id/details", (req, res) => {
    const { id } = req.params;

    // Get the alert
    db.query("SELECT * FROM alerts WHERE id = ?", [id], (err, alerts) => {
        if (err) return res.status(500).json({ error: "DB error" });
        if (!alerts.length) return res.status(404).json({ error: "Alert not found" });

        const alert = alerts[0];

        // Get threat intel
        db.query(
            "SELECT * FROM threat_intel_log WHERE alert_id = ? LIMIT 1",
            [id],
            (err, intel) => {
                if (err) intel = [];

                // Get playbook executions
                db.query(
                    "SELECT * FROM playbook_executions WHERE alert_id = ? ORDER BY executed_at DESC",
                    [id],
                    (err, executions) => {
                        if (err) executions = [];

                        // Parse actions_taken JSON
                        executions = executions.map(e => ({
                            ...e,
                            actions_taken: (() => {
                                try { return JSON.parse(e.actions_taken) }
                                catch(e) { return [] }
                            })()
                        }));

                        // Get linked ticket
                        db.query(
                            "SELECT * FROM tickets WHERE alert_id = ? LIMIT 1",
                            [id],
                            (err, tickets) => {
                                if (err) tickets = [];

                                // Get notification log
                                db.query(
                                    "SELECT * FROM notification_log WHERE alert_id = ? LIMIT 1",
                                    [id],
                                    (err, notifications) => {
                                        if (err) notifications = [];

                                        res.json({
                                            alert,
                                            threatIntel   : intel[0] || null,
                                            executions,
                                            ticket        : tickets[0] || null,
                                            notification  : notifications[0] || null,
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/alerts/my/:username — Alerts assigned to user
// ─────────────────────────────────────────────────────────
router.get("/my/:username", (req, res) => {
    db.query(
        "SELECT * FROM alerts WHERE assigned_to = ? ORDER BY created_at DESC",
        [req.params.username],
        (err, results) => {
            if (err) return res.status(500).json({ error: "Failed to fetch" });
            res.json(results);
        }
    );
});

// ─────────────────────────────────────────────────────────
// GET /api/alerts — Get all alerts with filters
// ─────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────
// PATCH /api/alerts/:id/assign — Assign alert to analyst
// ─────────────────────────────────────────────────────────
router.patch("/:id/assign", (req, res) => {
    const { id }          = req.params;
    const { assigned_to } = req.body;

    if (!assigned_to) {
        return res.status(400).json({ error: "assigned_to is required" });
    }

    db.query(
        "UPDATE alerts SET assigned_to = ?, assigned_at = NOW() WHERE id = ?",
        [assigned_to, id],
        (err, result) => {
            if (err) return res.status(500).json({ error: "Assign failed" });
            if (!result.affectedRows) return res.status(404).json({ error: "Alert not found" });
            res.json({ status: "Assigned", alertId: id, assigned_to });
        }
    );
});

// ─────────────────────────────────────────────────────────
// PATCH /api/alerts/:id/status — Update alert status
// ─────────────────────────────────────────────────────────
router.patch("/:id/status", (req, res) => {
    const { id }     = req.params;
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

module.exports = router;
