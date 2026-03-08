const express = require("express");
const cors    = require("cors");
const path    = require("path");

const alertRoutes = require("./routes/alerts");
const authRoutes  = require("./routes/auth");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/alerts", alertRoutes);
app.use("/api/auth",   authRoutes);

app.get("/health", (req, res) => {
    res.json({ status: "SOAR Backend running", timestamp: new Date().toISOString() });
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n🚀 SOAR Backend running on http://0.0.0.0:${PORT}`);
    console.log(`🔐 Login:     http://localhost:${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`🔍 Health:    http://localhost:${PORT}/health\n`);
});
