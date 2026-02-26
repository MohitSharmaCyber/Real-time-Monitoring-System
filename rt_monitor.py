import time
import re
from config import LOG_FILE
from detection import detect_bruteforce, detect_portscan
from response import save_alert, block_ip, send_email


def monitor():
    print("==== Real-Time SOC Monitor Started ====")
    print(f"Monitoring file: {LOG_FILE}\n")

    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            # =========================
            # BRUTE FORCE DETECTION
            # =========================
            if "Failed password" in line:
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

                if ip_match:
                    ip = ip_match.group(1)

                    print(f"[INFO] Failed password from {ip}")

                    if detect_bruteforce(ip):
                        print(f"🚨 BRUTE FORCE DETECTED from {ip}")

                        save_alert("BRUTE FORCE", ip, "HIGH", "T1110")
                        block_ip(ip)
                        send_email(ip, "BRUTE FORCE")

            # =========================
            # PORT SCAN DETECTION
            # =========================
            if "Port scan detected" in line:
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                port_match = re.search(r"port (\d+)", line)

                if ip_match and port_match:
                    ip = ip_match.group(1)
                    port = port_match.group(1)

                    print(f"[INFO] Port scan from {ip} on port {port}")

                    if detect_portscan(ip, port):
                        print(f"🚨 PORT SCAN DETECTED from {ip}")

                        save_alert("PORT SCAN", ip, "MEDIUM", "T1046")
                        block_ip(ip)
                        send_email(ip, "PORT SCAN")


if __name__ == "__main__":
    monitor()