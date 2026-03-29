// routes/playbooks.js
const express = require('express');
const router  = express.Router();
const db      = require('../db');
const { verifyToken, requireRole } = require('../middleware/auth');

const AVAILABLE_ACTIONS = [
    'BLOCK_IP', 'ISOLATE_HOST', 'NOTIFY_ADMIN',
    'NOTIFY_ANALYST', 'CREATE_TICKET', 'LOG_ONLY',
    'DISABLE_ACCOUNT', 'QUARANTINE_FILE', 'RESET_PASSWORD'
];

// GET all playbooks
router.get('/', verifyToken, (req, res) => {
    db.query('SELECT * FROM playbooks ORDER BY severity, created_at DESC', (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch playbooks' });
        const parsed = results.map(p => ({ ...p, actions: JSON.parse(p.actions || '[]') }));
        res.json(parsed);
    });
});

// GET available actions list
router.get('/actions', verifyToken, (req, res) => {
    res.json(AVAILABLE_ACTIONS);
});

// GET execution log
router.get('/executions/log', verifyToken, (req, res) => {
    db.query('SELECT * FROM playbook_executions ORDER BY executed_at DESC LIMIT 100', (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch execution log' });
        const parsed = results.map(e => ({ ...e, actions_taken: JSON.parse(e.actions_taken || '[]') }));
        res.json(parsed);
    });
});

// GET single playbook
router.get('/:id', verifyToken, (req, res) => {
    db.query('SELECT * FROM playbooks WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        if (!results.length) return res.status(404).json({ error: 'Playbook not found' });
        const p = results[0];
        res.json({ ...p, actions: JSON.parse(p.actions || '[]') });
    });
});

// POST create playbook
router.post('/', verifyToken, requireRole('ADMIN', 'SOC_MANAGER', 'INCIDENT_RESPONSE'), (req, res) => {
    const { name, description, severity, trigger_type, actions, is_active } = req.body;

    if (!name || !actions || !actions.length) {
        return res.status(400).json({ error: 'Name and at least one action are required' });
    }

    const allowedSev = ['CRITICAL','HIGH','MEDIUM','LOW','ANY'];
    if (!allowedSev.includes((severity||'').toUpperCase())) {
        return res.status(400).json({ error: 'Invalid severity' });
    }

    const invalidActions = actions.filter(a => !AVAILABLE_ACTIONS.includes(a));
    if (invalidActions.length) {
        return res.status(400).json({ error: `Invalid actions: ${invalidActions.join(', ')}` });
    }

    const sql = `INSERT INTO playbooks (name, description, severity, trigger_type, actions, is_active, created_by) VALUES (?,?,?,?,?,?,?)`;
    db.query(sql, [
        name,
        description || '',
        severity.toUpperCase(),
        trigger_type || '',
        JSON.stringify(actions),
        is_active !== false ? 1 : 0,
        req.user.username
    ], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to create playbook' });
        console.log(`✅ Playbook created: "${name}" by ${req.user.username}`);
        res.json({ status: 'Created', playbookId: result.insertId });
    });
});

// PUT update playbook
router.put('/:id', verifyToken, requireRole('ADMIN', 'SOC_MANAGER', 'INCIDENT_RESPONSE'), (req, res) => {
    const { name, description, severity, trigger_type, actions, is_active } = req.body;
    const { id } = req.params;

    if (!name || !actions || !actions.length) {
        return res.status(400).json({ error: 'Name and at least one action are required' });
    }

    const invalidActions = actions.filter(a => !AVAILABLE_ACTIONS.includes(a));
    if (invalidActions.length) {
        return res.status(400).json({ error: `Invalid actions: ${invalidActions.join(', ')}` });
    }

    const sql = `UPDATE playbooks SET name=?, description=?, severity=?, trigger_type=?, actions=?, is_active=?, updated_by=? WHERE id=?`;
    db.query(sql, [
        name,
        description || '',
        (severity || 'ANY').toUpperCase(),
        trigger_type || '',
        JSON.stringify(actions),
        is_active !== false ? 1 : 0,
        req.user.username,
        id
    ], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to update playbook' });
        if (!result.affectedRows) return res.status(404).json({ error: 'Playbook not found' });
        console.log(`✅ Playbook #${id} updated by ${req.user.username}`);
        res.json({ status: 'Updated', playbookId: id });
    });
});

// DELETE playbook
router.delete('/:id', verifyToken, requireRole('ADMIN', 'SOC_MANAGER'), (req, res) => {
    db.query('DELETE FROM playbooks WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Failed to delete playbook' });
        if (!result.affectedRows) return res.status(404).json({ error: 'Playbook not found' });
        console.log(`🗑️ Playbook #${req.params.id} deleted by ${req.user.username}`);
        res.json({ status: 'Deleted' });
    });
});

module.exports = router;
