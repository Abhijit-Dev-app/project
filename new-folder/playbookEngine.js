// services/playbookEngine.js

const runPlaybook = (alert) => {
    console.log(`[Playbook Engine] Analyzing: "${alert.type}" | Severity: ${alert.severity}`);

    let actions = [];

    const type = (alert.type || "").toLowerCase();
    const severity = (alert.severity || "").toUpperCase();

    // --- CRITICAL Rules ---
    if (severity === "CRITICAL") {
        if (type.includes("unauthorized access") || type.includes("brute force")) {
            actions.push("BLOCK_IP");
            actions.push("NOTIFY_ADMIN");
            actions.push("CREATE_TICKET");
        } else if (type.includes("malware") || type.includes("ransomware")) {
            actions.push("ISOLATE_HOST");
            actions.push("NOTIFY_ADMIN");
            actions.push("CREATE_TICKET");
        } else {
            // Generic critical fallback
            actions.push("NOTIFY_ADMIN");
            actions.push("CREATE_TICKET");
        }
    }

    // --- HIGH Rules ---
    else if (severity === "HIGH") {
        if (type.includes("port scan") || type.includes("reconnaissance")) {
            actions.push("BLOCK_IP");
            actions.push("LOG_ONLY");
        } else {
            actions.push("ISOLATE_HOST");
            actions.push("LOG_ONLY");
        }
    }

    // --- MEDIUM / LOW Rules ---
    else if (severity === "MEDIUM") {
        actions.push("LOG_ONLY");
        actions.push("NOTIFY_ANALYST");
    }

    // --- Default / Unknown ---
    else {
        actions.push("LOG_ONLY");
    }

    console.log(`[Playbook Engine] Actions triggered: ${actions.join(", ")}`);
    return actions;
};

module.exports = { runPlaybook };

