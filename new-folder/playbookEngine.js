/**
 * Playbook Engine Component
 * Logic: Analyzes incoming threats and executes a response.
 */
const triggerAction = (alert) => {
    console.log(`\n--- [PLAYBOOK ENGINE] Processing Alert ID: ${alert.id} ---`);

    if (alert.severity === 'CRITICAL') {
        console.log(`[ACTION] 🚨 BLOCKING IP: Automated firewall rule created for: ${alert.type}`);
    } else if (alert.severity === 'HIGH') {
        console.log(`[ACTION] 📧 NOTIFY: Sending high-priority alert to SOC Slack channel.`);
    } else {
        console.log(`[ACTION] ✅ LOG: Alert recorded for weekly audit.`);
    }
};

module.exports = { triggerAction };
