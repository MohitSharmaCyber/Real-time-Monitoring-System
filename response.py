from datetime import datetime
from config import ALERT_FILE, BLACKLIST_FILE

blocked_ips = set()

def save_alert(attack_type, ip, severity, mitre):
    timestamp = datetime.now()
    alert_line = f"{timestamp} | {attack_type} | {ip} | {severity} | {mitre}\n"

    with open(ALERT_FILE, "a") as f:
        f.write(alert_line)


def block_ip(ip):
    if ip not in blocked_ips:
        blocked_ips.add(ip)

        with open(BLACKLIST_FILE, "a") as f:
            f.write(ip + "\n")

        print(f"🔥 IP {ip} BLOCKED")


def send_email(ip, attack_type):
    print(f"📧 EMAIL ALERT SENT for {ip} ({attack_type})")