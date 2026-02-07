const express = require("express");
const router = express.Router();
const db = require("../db");

router.post("/ingest", (req, res) => {
  const { source, type, severity, message } = req.body;

  const sql = `
    INSERT INTO alerts (source, type, severity, message)
    VALUES (?, ?, ?, ?)
  `;

  db.query(sql, [source, type, severity, message], (err) => {
    if (err) {
      return res.status(500).json({ error: err });
    }
    res.json({ message: "Alert ingested successfully" });
  });
});

router.get("/", (req, res) => {
  db.query(
    "SELECT * FROM alerts ORDER BY created_at DESC",
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err });
      }
      res.json(results);
    }
  );
});

module.exports = router;
