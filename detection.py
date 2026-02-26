from datetime import datetime
from config import TIME_WINDOW, BRUTE_FORCE_THRESHOLD, PORT_SCAN_THRESHOLD

failed_attempts = {}
port_activity = {}

def detect_bruteforce(ip):
    now = datetime.now()
    failed_attempts.setdefault(ip, [])
    failed_attempts[ip].append(now)

    failed_attempts[ip] = [
        t for t in failed_attempts[ip]
        if (now - t).seconds <= TIME_WINDOW
    ]

    return len(failed_attempts[ip]) >= BRUTE_FORCE_THRESHOLD


def detect_portscan(ip, port):
    port_activity.setdefault(ip, set())
    port_activity[ip].add(port)

    return len(port_activity[ip]) >= PORT_SCAN_THRESHOLD