// services/playbookEngine.js

const runPlaybook = (alert) => {
    console.log(`[Playbook Engine] Analyzing alert: ${alert.type} (${alert.severity})`);

    let actions = [];

    // Logic for Critical Unauthorized Access
    if (alert.severity === 'CRITICAL' && alert.type === 'Unauthorized Access') {
        actions.push('BLOCK_IP');
        actions.push('NOTIFY_ADMIN');
    } 
    // Logic for suspicious activity
    else if (alert.severity === 'HIGH') {
        actions.push('ISOLATE_HOST');
    } 
    else {
        actions.push('LOG_ONLY');
    }

    return actions;
};

module.exports = { runPlaybook };