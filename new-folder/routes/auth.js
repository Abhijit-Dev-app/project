// routes/auth.js
// Login, Register, Logout, User Management

const express   = require("express");
const router    = express.Router();
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const db        = require("../db");
const { verifyToken, requireRole, requirePermission, ROLE_PERMISSIONS, JWT_SECRET } = require("../middleware/auth");

// ── Helper: Log audit event ────────────────────────────────
const logAudit = (userId, username, action, details, ip) => {
    db.query(
        "INSERT INTO audit_log (user_id, username, action, details, ip_address) VALUES (?,?,?,?,?)",
        [userId, username, action, details, ip],
        (err) => { if (err) console.error("[Audit] Log error:", err.message); }
    );
};

// ─────────────────────────────────────────────────────────
// POST /api/auth/register  (ADMIN only after first user)
// ─────────────────────────────────────────────────────────
router.post("/register", async (req, res) => {
    const { username, password, role, full_name, email } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
    }

    const allowedRoles = ["ADMIN","SOC_MANAGER","SOC_ANALYST","INCIDENT_RESPONSE"];
    const userRole = role && allowedRoles.includes(role.toUpperCase()) ? role.toUpperCase() : "SOC_ANALYST";

    try {
        // Check if any users exist (first user becomes ADMIN automatically)
        db.query("SELECT COUNT(*) as count FROM users", async (err, results) => {
            if (err) return res.status(500).json({ error: "DB error" });

            const isFirstUser = results[0].count === 0;
            const finalRole   = isFirstUser ? "ADMIN" : userRole;

            // Hash password
            const hash = await bcrypt.hash(password, 12);

            db.query(
                "INSERT INTO users (username, password_hash, role, full_name, email) VALUES (?,?,?,?,?)",
                [username, hash, finalRole, full_name || username, email || ""],
                (err, result) => {
                    if (err) {
                        if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Username already exists" });
                        return res.status(500).json({ error: "Registration failed" });
                    }
                    console.log(`✅ User registered: ${username} (${finalRole})`);
                    res.json({
                        status  : "Success",
                        message : isFirstUser ? "First user created as ADMIN" : "User registered",
                        userId  : result.insertId,
                        role    : finalRole
                    });
                }
            );
        });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

// ─────────────────────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────────────────────
router.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
    }

    db.query("SELECT * FROM users WHERE username = ? AND is_active = 1", [username], async (err, results) => {
        if (err) return res.status(500).json({ error: "DB error" });
        if (results.length === 0) return res.status(401).json({ error: "Invalid username or password" });

        const user = results[0];

        // Compare password
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
            logAudit(user.id, username, "FAILED_LOGIN", "Wrong password", req.ip);
            return res.status(401).json({ error: "Invalid username or password" });
        }

        // Generate JWT token (expires in 8 hours)
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
            JWT_SECRET,
            { expiresIn: "8h" }
        );

        // Update last login
        db.query("UPDATE users SET last_login = NOW() WHERE id = ?", [user.id]);

        // Audit log
        logAudit(user.id, username, "LOGIN", "Successful login", req.ip);

        console.log(`✅ Login: ${username} (${user.role})`);
        res.json({
            status     : "Success",
            token      : token,
            user: {
                id        : user.id,
                username  : user.username,
                role      : user.role,
                full_name : user.full_name,
                email     : user.email,
                permissions: ROLE_PERMISSIONS[user.role] || []
            }
        });
    });
});

// ─────────────────────────────────────────────────────────
// POST /api/auth/logout
// ─────────────────────────────────────────────────────────
router.post("/logout", verifyToken, (req, res) => {
    logAudit(req.user.id, req.user.username, "LOGOUT", "User logged out", req.ip);
    res.json({ status: "Success", message: "Logged out successfully" });
});

// ─────────────────────────────────────────────────────────
// GET /api/auth/me — Get current user info
// ─────────────────────────────────────────────────────────
router.get("/me", verifyToken, (req, res) => {
    db.query("SELECT id, username, role, full_name, email, last_login, created_at FROM users WHERE id = ?",
        [req.user.id], (err, results) => {
            if (err || results.length === 0) return res.status(404).json({ error: "User not found" });
            res.json({ ...results[0], permissions: ROLE_PERMISSIONS[results[0].role] || [] });
        }
    );
});

// ─────────────────────────────────────────────────────────
// GET /api/auth/users — List all users (ADMIN only)
// ─────────────────────────────────────────────────────────
router.get("/users", verifyToken, requireRole("ADMIN"), (req, res) => {
    db.query("SELECT id, username, role, full_name, email, is_active, last_login, created_at FROM users ORDER BY created_at DESC",
        (err, results) => {
            if (err) return res.status(500).json({ error: "Failed to fetch users" });
            res.json(results);
        }
    );
});

// ─────────────────────────────────────────────────────────
// PATCH /api/auth/users/:id — Update user role (ADMIN only)
// ─────────────────────────────────────────────────────────
router.patch("/users/:id", verifyToken, requireRole("ADMIN"), (req, res) => {
    const { role, is_active } = req.body;
    const { id } = req.params;

    const allowedRoles = ["ADMIN","SOC_MANAGER","SOC_ANALYST","INCIDENT_RESPONSE"];
    if (role && !allowedRoles.includes(role.toUpperCase())) {
        return res.status(400).json({ error: "Invalid role" });
    }

    const updates = [];
    const params  = [];
    if (role)       { updates.push("role = ?");      params.push(role.toUpperCase()); }
    if (is_active !== undefined) { updates.push("is_active = ?"); params.push(is_active ? 1 : 0); }

    if (updates.length === 0) return res.status(400).json({ error: "Nothing to update" });
    params.push(id);

    db.query(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`, params, (err, result) => {
        if (err) return res.status(500).json({ error: "Update failed" });
        logAudit(req.user.id, req.user.username, "UPDATE_USER", `Updated user #${id}: ${JSON.stringify(req.body)}`, req.ip);
        res.json({ status: "Updated", userId: id });
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/auth/audit — Audit log (ADMIN + SOC_MANAGER)
// ─────────────────────────────────────────────────────────
router.get("/audit", verifyToken, requireRole("ADMIN", "SOC_MANAGER"), (req, res) => {
    db.query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100", (err, results) => {
        if (err) return res.status(500).json({ error: "Failed to fetch audit log" });
        res.json(results);
    });
});

module.exports = router;

