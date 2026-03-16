// Dynamic Playbook Engine — reads rules from MySQL instead of hardcoded rules

const db = require('./db');

// ── Run playbook against an alert ─────────────────────────
const runPlaybook = (alert, alertId = null) => {
    return new Promise((resolve) => {
        console.log(`[Playbook Engine] Analyzing: "${alert.type}" | Severity: ${alert.severity}`);

        const severity = (alert.severity || '').toUpperCase();
        const type     = (alert.type || '').toLowerCase();

        // Fetch matching playbooks from DB
        // Match: same severity OR 'ANY', AND trigger_type matches or is empty
        const sql = `
            SELECT * FROM playbooks 
            WHERE is_active = 1 
            AND (severity = ? OR severity = 'ANY')
            ORDER BY 
                CASE WHEN severity = ? THEN 0 ELSE 1 END,
                CASE WHEN trigger_type != '' THEN 0 ELSE 1 END
        `;

        db.query(sql, [severity, severity], (err, playbooks) => {
            if (err) {
                console.error('[Playbook Engine] DB error:', err.message);
                // Fallback to basic action
                return resolve(['LOG_ONLY']);
            }

            if (playbooks.length === 0) {
                console.log('[Playbook Engine] No matching playbooks found. Using LOG_ONLY.');
                return resolve(['LOG_ONLY']);
            }

            // Find best matching playbook
            // Priority: specific trigger_type match > generic (empty trigger_type)
            let matched = null;

            // First try to match by trigger_type keyword
            for (const pb of playbooks) {
                if (pb.trigger_type && type.includes(pb.trigger_type.toLowerCase())) {
                    matched = pb;
                    break;
                }
            }

            // If no specific match, use first generic one (empty trigger_type)
            if (!matched) {
                matched = playbooks.find(pb => !pb.trigger_type || pb.trigger_type === '');
            }

            if (!matched) {
                return resolve(['LOG_ONLY']);
            }

            // Parse actions from JSON
            let actions = [];
            try {
                actions = JSON.parse(matched.actions);
            } catch(e) {
                actions = ['LOG_ONLY'];
            }

            console.log(`[Playbook Engine] Matched: "${matched.name}" → Actions: ${actions.join(', ')}`);

            // Log execution to DB
            if (alertId) {
                const execSql = `
                    INSERT INTO playbook_executions 
                    (playbook_id, playbook_name, alert_id, alert_type, severity, actions_taken, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'SUCCESS')
                `;
                db.query(execSql, [
                    matched.id,
                    matched.name,
                    alertId,
                    alert.type,
                    severity,
                    JSON.stringify(actions)
                ], (err) => {
                    if (err) console.error('[Playbook Engine] Execution log error:', err.message);
                });
            }

            resolve(actions);
        });
    });
};

module.exports = { runPlaybook };
