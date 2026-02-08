const mysql = require("mysql2");

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "pass123",
  database: "SOAR1"
});

db.connect(err => {
  if (err) console.error("MySQL Connection Error:", err);
  else console.log("Connected to MySQL: SOAR1");
});

module.exports = db;