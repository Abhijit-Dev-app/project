#!/usr/bin/env python3
"""
wazuh_to_soar.py
Wazuh Active Response Script — forwards alerts to your SOAR backend.
Place this in: /var/ossec/active-response/bin/
"""

import sys
import json
import requests
import logging
import os

# ── Logging Setup ──────────────────────────────────────────
LOG_FILE = "/var/ossec/logs/soar_forward.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ── SOAR Backend URL ───────────────────────────────────────
# Change this to your actual SOAR server IP
SOAR_URL = os.getenv("SOAR_URL", "http://10.255.255.254:5000/api/alerts/ingest")

# ── Severity Mapping from Wazuh rule level ─────────────────
def map_severity(level: int) -> str:
    if level >= 13:
        return "CRITICAL"
    elif level >= 10:
        return "HIGH"
    elif level >= 7:
        return "MEDIUM"
    else:
        return "LOW"

# ── Main ───────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        logging.error("No alert file path provided as argument.")
        sys.exit(1)

    alert_file_path = sys.argv[1]

    # Read Wazuh alert JSON
    try:
        with open(alert_file_path) as f:
            wazuh_alert = json.load(f)
    except FileNotFoundError:
        logging.error(f"Alert file not found: {alert_file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in alert file: {e}")
        sys.exit(1)

    # Extract fields safely
    rule = wazuh_alert.get("rule", {})
    rule_level = int(rule.get("level", 0))
    rule_desc = rule.get("description", "Unknown Security Event")
    agent = wazuh_alert.get("agent", {})
    agent_name = agent.get("name", "Unknown Agent")
    agent_ip = agent.get("ip", "Unknown IP")
    full_log = wazuh_alert.get("full_log", "No log data available")

    # Build SOAR payload
    soar_payload = {
        "source": f"Wazuh | Agent: {agent_name} ({agent_ip})",
        "type": rule_desc,
        "severity": map_severity(rule_level),
        "message": f"[Rule Level {rule_level}] {full_log[:500]}"  # Limit message size
    }

    logging.info(f"Forwarding alert: {rule_desc} | Level: {rule_level} | Severity: {soar_payload['severity']}")

    # Send to SOAR
    try:
        response = requests.post(
            SOAR_URL,
            json=soar_payload,
            timeout=10
        )
        response.raise_for_status()
        logging.info(f"✅ Alert sent successfully. SOAR Response: {response.status_code} | {response.text}")
        print(f"Alert forwarded to SOAR. Status: {response.status_code}")

    except requests.exceptions.ConnectionError:
        logging.error(f"❌ Could not connect to SOAR at {SOAR_URL}. Is the server running?")
    except requests.exceptions.Timeout:
        logging.error("❌ SOAR request timed out.")
    except requests.exceptions.HTTPError as e:
        logging.error(f"❌ SOAR returned error: {e}")
    except Exception as e:
        logging.error(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()

