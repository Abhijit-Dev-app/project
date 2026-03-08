const mysql = require("mysql2");

// Using a pool instead of single connection for reliability
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "pass123",
  database: process.env.DB_NAME || "SOAR1",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test connection on startup
db.getConnection((err, connection) => {
  if (err) {
    console.error("❌ MySQL Connection Error:", err.message);
    console.error("Make sure MySQL is running and database SOAR1 exists.");
  } else {
    console.log("✅ Connected to MySQL: SOAR1");
    connection.release();
  }
});

module.exports = db;

