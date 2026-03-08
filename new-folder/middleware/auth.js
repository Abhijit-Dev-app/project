// middleware/auth.js
// JWT Authentication + Role-Based Access Control (RBAC)

const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "soar_secret_key_2024";

// ── Role Hierarchy ─────────────────────────────────────────
// ADMIN         → full access to everything
// SOC_MANAGER   → view all, generate reports, manage analysts
// INCIDENT_RESPONSE → execute playbooks, update alert status
// SOC_ANALYST   → view alerts, filter, update status only

const ROLE_PERMISSIONS = {
    ADMIN: [
        "view_alerts", "ingest_alerts", "update_status",
        "view_intel", "view_notifications", "generate_report",
        "manage_users", "view_audit_log", "execute_playbook"
    ],
    SOC_MANAGER: [
        "view_alerts", "update_status", "view_intel",
        "view_notifications", "generate_report", "view_audit_log"
    ],
    INCIDENT_RESPONSE: [
        "view_alerts", "update_status", "execute_playbook",
        "view_intel", "view_notifications"
    ],
    SOC_ANALYST: [
        "view_alerts", "update_status", "view_intel", "view_notifications"
    ]
};

// ── Verify JWT Token ───────────────────────────────────────
const verifyToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

    if (!token) {
        return res.status(401).json({ error: "Access denied. No token provided." });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid or expired token. Please login again." });
    }
};

// ── Check Permission ───────────────────────────────────────
const requirePermission = (permission) => {
    return (req, res, next) => {
        const role = req.user?.role;
        const permissions = ROLE_PERMISSIONS[role] || [];

        if (!permissions.includes(permission)) {
            return res.status(403).json({
                error: `Access denied. Your role (${role}) does not have permission: ${permission}`
            });
        }
        next();
    };
};

// ── Require Specific Role ──────────────────────────────────
const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user?.role)) {
            return res.status(403).json({
                error: `Access denied. Required role: ${roles.join(" or ")}`
            });
        }
        next();
    };
};

module.exports = { verifyToken, requirePermission, requireRole, ROLE_PERMISSIONS, JWT_SECRET };
