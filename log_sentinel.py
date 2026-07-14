import re
import json
import urllib.request
from datetime import datetime

# 1. Simulated Server Logs (representing network traffic/SSH login attempts)
MOCK_LOGS = """
2026-07-14 10:30:15 - SUCCESSFUL login from IP: 192.168.1.50 - User: admin
2026-07-14 10:31:02 - FAILED login from IP: 185.220.101.5 - User: root
2026-07-14 10:31:05 - FAILED login from IP: 185.220.101.5 - User: root
2026-07-14 10:31:08 - FAILED login from IP: 185.220.101.5 - User: admin
2026-07-14 10:31:12 - FAILED login from IP: 185.220.101.5 - User: support
2026-07-14 10:32:00 - SUCCESSFUL login from IP: 192.168.1.12 - User: user1
"""

# Threshold for brute-force detection (e.g., more than 3 failed attempts)
FAILED_THRESHOLD = 3

def analyze_logs():
    print("[*] LogSentinel: Initiating Security Log Analysis...")
    
    # Track failed logins per IP
    failed_attempts = {}
    
    # Parse logs line by line using Regex to extract IP addresses
    for line in MOCK_LOGS.strip().split('\n'):
        if "FAILED" in line:
            # Extract IP address using Regular Expressions
            ip_match = re.search(r'IP:\s*([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # Check if any IP crossed the malicious threshold
    for ip, count in failed_attempts.items():
        if count >= FAILED_THRESHOLD:
            print(f"\n[!] ALERT: Potential Brute-Force attack detected from IP: {ip} ({count} failed attempts)!")
            query_threat_intelligence(ip)

def query_threat_intelligence(ip_address):
    """
    Simulating Threat Intelligence Lookup.
    In production, this queries a public API like AbuseIPDB to see if the IP is blacklisted.
    """
    print(f"[*] Querying Threat Intelligence API for reputation of IP: {ip_address}...")
    
    # Mocking API JSON response for demonstration
    # (Shows recruiters you understand how to process JSON & APIs)
    mock_api_response = {
        "ipAddress": ip_address,
        "isPublic": True,
        "abuseScore": 85,  # 85% chance of being a known malicious actor
        "countryCode": "NL",
        "usageType": "Tor Exit Node"
    }
    
    generate_incident_report(mock_api_response)

def generate_incident_report(threat_data):
    """
    Automated Incident Response: Writes a structured security report to a JSON file.
    """
    report_filename = f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    report_data = {
        "incident_type": "Brute-Force Attack & Threat Intel Match",
        "timestamp": str(datetime.now()),
        "attacker_ip": threat_data["ipAddress"],
        "threat_score": f"{threat_data['abuseScore']}%",
        "attacker_location": threat_data["countryCode"],
        "connection_type": threat_data["usageType"],
        "recommended_action": "BLOCK IP immediately on corporate edge firewall (iptables/UFW)."
    }
    
    with open(report_filename, 'w') as f:
        json.dump(report_data, f, indent=4)
        
    print(f"[+] SUCCESS: Automated Incident Report generated: {report_filename}")
    print(f"Recommended Analyst Action: {report_data['recommended_action']}\n")

if __name__ == "__main__":
    analyze_logs()