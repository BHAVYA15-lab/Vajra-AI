"""
MITRE ATT&CK Mapping & Actionable Remediation Guidance Module
Maps injected cybersecurity attack categories to official MITRE ATT&CK framework technique IDs,
tactics, descriptions, and structured SOC remediation recommendations.
"""

MITRE_ATTACK_MAP = {
    "brute_force": {
        "technique_id": "T1110.001 / T1110.003",
        "technique_name": "Brute Force: Password Guessing / Password Spraying",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries attempt to gain access by systematically guessing passwords or spraying common passwords across multiple accounts.",
        "recommended_actions": [
            "🔒 Enforce immediate account lockout for targeted entity.",
            "📲 Require out-of-band Step-Up MFA authentication.",
            "🛡️ Rate-limit and block offending source IP at perimeter firewall."
        ]
    },
    "credential_stuffing": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries test stolen username/password pairs across multiple user endpoints from a high fan-out IP address.",
        "recommended_actions": [
            "🔑 Trigger mandatory password resets across all targeted accounts.",
            "🤖 Deploy IP-based CAPTCHA rate-limiting across API Gateway.",
            "🔍 Audit active session tokens originating from offending IP."
        ]
    },
    "device_spoofing": {
        "technique_id": "T1036.005",
        "technique_name": "Masquerading: Match Legitimate Name or Location",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "description": "Adversaries impersonate trusted host OS, MAC address, or protocol signatures to bypass network access controls.",
        "recommended_actions": [
            "🚫 Revoke active session token immediately.",
            "📜 Verify hardware MAC enrollment & re-issue mTLS client certificate.",
            "☣️ Quarantine device endpoint from internal network segments."
        ]
    },
    "impossible_travel": {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "tactic_id": "TA0001 / TA0003",
        "tactic_name": "Initial Access / Persistence",
        "description": "Adversaries use stolen credentials to authenticate from geographically impossible locations within short timeframes.",
        "recommended_actions": [
            "⚡ Terminate concurrent active sessions across all locations.",
            "📱 Challenge user with Step-Up MFA and out-of-band push notification.",
            "🌐 Verify VPN egress node velocities and check for proxy/Tor exit nodes."
        ]
    },
    "lateral_movement": {
        "technique_id": "T1021.001 / T1021.004",
        "technique_name": "Remote Services: RDP / SSH Remote Services",
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "description": "Adversaries access internal administrative resources and sensitive vaults outside an entity's job function scope.",
        "recommended_actions": [
            "🛑 Terminate privileged session immediately.",
            "💻 Isolate host endpoint from internal network segments.",
            "📋 Audit active shell execution logs and revoke elevated IAM roles."
        ]
    },
    "low_slow_exfiltration": {
        "technique_id": "T1041 / T1567",
        "technique_name": "Exfiltration Over C2 Channel / Web Service",
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "description": "Adversaries execute slow, long-duration data transfers of sensitive database/S3 records to external endpoints.",
        "recommended_actions": [
            "📊 Inspect outbound network egress traffic and external bucket connections.",
            "💾 Pause database/S3 export privileges for targeted entity.",
            "🔬 Initiate SOC forensic capture on active process memory."
        ]
    },
    "insider_drift": {
        "technique_id": "N/A",
        "technique_name": "Benign Organizational / Role Drift (Diagnostic)",
        "tactic_id": "BENIGN",
        "tactic_name": "Non-Malicious Diagnostic",
        "description": "Organizational or job role evolution. Benign behavior monitored for baseline profile updating.",
        "recommended_actions": [
            "👀 Monitor activity over 14-day baseline window.",
            "👥 Verify role transition with line manager if resource access persists."
        ]
    }
}

def get_mitre_info(attack_type):
    """
    Returns MITRE ATT&CK mapping info dictionary for a given attack category string.
    If unknown, returns default structure.
    """
    clean_type = str(attack_type).lower().strip()
    if clean_type in MITRE_ATTACK_MAP:
        return MITRE_ATTACK_MAP[clean_type]
    
    return {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (Generic Anomaly)",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "description": "Uncategorized baseline behavioral deviation.",
        "recommended_actions": [
            "🔍 Inspect session logs for baseline deviation drivers.",
            "🔑 Monitor entity credentials for suspicious activity."
        ]
    }
