// routes/webhooks.js
const express = require("express");
const router = express.Router();
const db = require("../db");

router.post("/sentinel", (req, res) => {
  const alert = req.body;

  const sql = `
    INSERT INTO alerts (source, type, severity, message)
    VALUES (?, ?, ?, ?)
  `;

  db.query(sql, [
    "Microsoft Sentinel",
    alert.alertType || "Unknown",
    alert.severity || "MEDIUM",
    alert.description || "No description"
  ]);

  res.status(200).json({ message: "Sentinel alert received" });
});

module.exports = router;
