// routes/tickets.js
const express = require('express');
const router  = express.Router();
const db      = require('../db');
const { verifyToken, requireRole } = require('../middleware/auth');

// ── Helper: Generate ticket reference TKT-0001 ────────────
const generateTicketRef = (callback) => {
    db.query('UPDATE ticket_counter SET counter = counter + 1', (err) => {
        if (err) return callback('TKT-0000');
        db.query('SELECT counter FROM ticket_counter LIMIT 1', (err, results) => {
            if (err) return callback('TKT-0000');
            const num = String(results[0].counter).padStart(4, '0');
            callback(`TKT-${num}`);
        });
    });
};

// ── Helper: Log timeline event ────────────────────────────
const logTimeline = (ticketId, action, detail, performedBy) => {
    db.query(
        'INSERT INTO ticket_timeline (ticket_id, action, detail, performed_by) VALUES (?,?,?,?)',
        [ticketId, action, detail, performedBy],
        (err) => { if (err) console.error('[Ticket] Timeline error:', err.message); }
    );
};

// ─────────────────────────────────────────────────────────
// GET /api/tickets — List all tickets
// ─────────────────────────────────────────────────────────
router.get('/', verifyToken, (req, res) => {
    const { status, priority, assigned_to } = req.query;
    let sql = 'SELECT * FROM tickets';
    const params = [], conditions = [];

    if (status)      { conditions.push('status = ?');      params.push(status.toUpperCase()); }
    if (priority)    { conditions.push('priority = ?');    params.push(priority.toUpperCase()); }
    if (assigned_to) { conditions.push('assigned_to = ?'); params.push(assigned_to); }

    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY created_at DESC';

    db.query(sql, params, (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch tickets' });
        res.json(results);
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/tickets/stats — Ticket summary stats
// ─────────────────────────────────────────────────────────
router.get('/stats', verifyToken, (req, res) => {
    const sql = `
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'OPEN'        THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN status = 'IN_PROGRESS' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'RESOLVED'    THEN 1 ELSE 0 END) as resolved,
            SUM(CASE WHEN status = 'CLOSED'      THEN 1 ELSE 0 END) as closed,
            SUM(CASE WHEN priority = 'CRITICAL'  THEN 1 ELSE 0 END) as critical
        FROM tickets
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: 'Stats failed' });
        res.json(results[0]);
    });
});

// ─────────────────────────────────────────────────────────
// GET /api/tickets/:id — Get single ticket with timeline + comments
// ─────────────────────────────────────────────────────────
router.get('/:id', verifyToken, (req, res) => {
    db.query('SELECT * FROM tickets WHERE id = ?', [req.params.id], (err, tickets) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        if (!tickets.length) return res.status(404).json({ error: 'Ticket not found' });

        const ticket = tickets[0];

        // Fetch timeline
        db.query('SELECT * FROM ticket_timeline WHERE ticket_id = ? ORDER BY created_at ASC', [ticket.id], (err, timeline) => {
            if (err) timeline = [];

            // Fetch comments
            db.query('SELECT * FROM ticket_comments WHERE ticket_id = ? ORDER BY created_at ASC', [ticket.id], (err, comments) => {
                if (err) comments = [];
                res.json({ ...ticket, timeline, comments });
            });
        });
    });
});

// ─────────────────────────────────────────────────────────
// POST /api/tickets — Create new ticket
// ─────────────────────────────────────────────────────────
router.post('/', verifyToken, (req, res) => {
    const { alert_id, title, description, priority, assigned_to } = req.body;

    if (!title) return res.status(400).json({ error: 'Title is required' });

    generateTicketRef((ticket_ref) => {
        const sql = `INSERT INTO tickets (ticket_ref, alert_id, title, description, priority, assigned_to, created_by) VALUES (?,?,?,?,?,?,?)`;
        db.query(sql, [
            ticket_ref,
            alert_id || null,
            title,
            description || '',
            (priority || 'MEDIUM').toUpperCase(),
            assigned_to || null,
            req.user.username
        ], (err, result) => {
            if (err) return res.status(500).json({ error: 'Failed to create ticket' });

            const ticketId = result.insertId;

            // Log creation in timeline
            logTimeline(ticketId, 'CREATED', `Ticket created by ${req.user.username}`, req.user.username);
            if (assigned_to) logTimeline(ticketId, 'ASSIGNED', `Assigned to ${assigned_to}`, req.user.username);

            console.log(`✅ Ticket ${ticket_ref} created by ${req.user.username}`);
            res.json({ status: 'Created', ticketId, ticket_ref });
        });
    });
});

// ─────────────────────────────────────────────────────────
// PATCH /api/tickets/:id/status — Update ticket status
// ─────────────────────────────────────────────────────────
router.patch('/:id/status', verifyToken, (req, res) => {
    const { status } = req.body;
    const { id }     = req.params;
    const allowed    = ['OPEN','IN_PROGRESS','PENDING','RESOLVED','CLOSED'];

    if (!allowed.includes(status?.toUpperCase())) {
        return res.status(400).json({ error: `Invalid status. Use: ${allowed.join(', ')}` });
    }

    const resolved_at = status.toUpperCase() === 'RESOLVED' ? new Date() : null;
    const sql = resolved_at
        ? 'UPDATE tickets SET status = ?, resolved_at = ? WHERE id = ?'
        : 'UPDATE tickets SET status = ? WHERE id = ?';
    const params = resolved_at ? [status.toUpperCase(), resolved_at, id] : [status.toUpperCase(), id];

    db.query(sql, params, (err, result) => {
        if (err) return res.status(500).json({ error: 'Update failed' });
        if (!result.affectedRows) return res.status(404).json({ error: 'Ticket not found' });

        logTimeline(id, 'STATUS_CHANGE', `Status changed to ${status.toUpperCase()}`, req.user.username);
        res.json({ status: 'Updated', newStatus: status.toUpperCase() });
    });
});

// ─────────────────────────────────────────────────────────
// PATCH /api/tickets/:id/assign — Assign ticket to analyst
// ─────────────────────────────────────────────────────────
router.patch('/:id/assign', verifyToken, (req, res) => {
    const { assigned_to } = req.body;
    const { id }          = req.params;

    db.query('UPDATE tickets SET assigned_to = ? WHERE id = ?', [assigned_to, id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Assign failed' });
        if (!result.affectedRows) return res.status(404).json({ error: 'Ticket not found' });

        logTimeline(id, 'ASSIGNED', `Assigned to ${assigned_to}`, req.user.username);
        res.json({ status: 'Assigned', assigned_to });
    });
});

// ─────────────────────────────────────────────────────────
// POST /api/tickets/:id/comments — Add comment
// ─────────────────────────────────────────────────────────
router.post('/:id/comments', verifyToken, (req, res) => {
    const { comment } = req.body;
    const { id }      = req.params;

    if (!comment?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });

    db.query(
        'INSERT INTO ticket_comments (ticket_id, comment, author) VALUES (?,?,?)',
        [id, comment.trim(), req.user.username],
        (err, result) => {
            if (err) return res.status(500).json({ error: 'Failed to add comment' });
            logTimeline(id, 'COMMENT', `${req.user.username} added a comment`, req.user.username);
            res.json({ status: 'Added', commentId: result.insertId });
        }
    );
});

// ─────────────────────────────────────────────────────────
// DELETE /api/tickets/:id — Delete ticket (ADMIN only)
// ─────────────────────────────────────────────────────────
router.delete('/:id', verifyToken, requireRole('ADMIN'), (req, res) => {
    db.query('DELETE FROM tickets WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Delete failed' });
        if (!result.affectedRows) return res.status(404).json({ error: 'Ticket not found' });
        res.json({ status: 'Deleted' });
    });
});

module.exports = router;
