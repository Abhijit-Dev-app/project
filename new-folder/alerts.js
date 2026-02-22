const express = require("express");
const router = express.Router();
const db = require("../db");
const { runPlaybook } = require("../playbookEngine");

// 1. Ingestion Route (unchanged)
router.post("/ingest", (req, res) => {
    const { source, type, severity, message } = req.body;
    const sql = "INSERT INTO alerts (source, type, severity, message, status) VALUES (?, ?, ?, ?, 'OPEN')";

    db.query(sql, [source, type, severity, message], (err, result) => {
        if (err) {
            console.error("Database Error:", err);
            return res.status(500).json({ error: "DB Failure" });
        }
        const automatedActions = runPlaybook({ type, severity });
        res.json({ status: "Success", alertId: result.insertId, actions: automatedActions });
    });
});

// 2. Dashboard Data Route (unchanged)
router.get("/", (req, res) => {
    db.query("SELECT * FROM alerts ORDER BY created_at DESC", (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

// 3. NEW: Incident Report Generation Route
router.get("/report", (req, res) => {
    db.query("SELECT * FROM alerts ORDER BY created_at DESC", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to generate report" });

        let report = `==========================================\n`;
        report += `       SOAR INCIDENT REPORT\n`;
        report += `       Generated: ${new Date().toLocaleString()}\n`;
        report += `==========================================\n\n`;

        if (results.length === 0) {
            report += "No incidents found in database.\n";
        } else {
            results.forEach((alert, index) => {
                report += `ID: ${alert.id} | SEVERITY: ${alert.severity}\n`;
                report += `TYPE: ${alert.type}\n`;
                report += `SOURCE: ${alert.source}\n`;
                report += `STATUS: ${alert.status}\n`;
                report += `TIMESTAMP: ${alert.created_at}\n`;
                report += `MESSAGE: ${alert.message}\n`;
                report += `------------------------------------------\n`;
            });
        }

        // Set headers to trigger a file download in the browser
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', 'attachment; filename=SOAR_Report.txt');
        res.send(report);
    });
});

module.exports = router;
