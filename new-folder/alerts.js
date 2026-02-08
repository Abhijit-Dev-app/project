const express = require("express");
const router = express.Router();
const db = require("../db");

router.get("/", (req, res) => {
  db.query("SELECT * FROM alerts ORDER BY created_at DESC", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

router.post("/ingest", (req, res) => {
  const { source, type, severity, message } = req.body;
  const sql = "INSERT INTO alerts (source, type, severity, message, status) VALUES (?, ?, ?, ?, 'OPEN')";
  
  db.query(sql, [source, type, severity, message], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ success: true, id: result.insertId });
  });
});

module.exports = router;
