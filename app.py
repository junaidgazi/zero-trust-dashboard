"""
Zero-Trust Network Access Dashboard
-------------------------------------
Builds on the same scanning idea as Project 1 (ping sweep + threading),
but adds the core idea behind ZERO TRUST: don't assume a device belongs
on your network just because it's connected. Every device must be on
an explicit "allow list" (identified by MAC address) to be trusted.

KEY CONCEPT - MAC vs IP:
An IP address (like 192.168.1.42) can change every time a device
reconnects (this is called DHCP). A MAC address is a hardware ID
burned into the device's network chip - it doesn't change. That's
why real access control systems use MAC addresses, not IPs, to
recognize a specific device over time.

HOW THIS WORKS:
1. Same ping sweep as Project 1 finds who's online right now
2. For each online device, we look up its MAC address using the
   `arp` command (every OS keeps a table mapping IPs it has talked
   to onto their MAC addresses - we just read that table)
3. We check that MAC against allowed_devices.json - a file YOU edit
   to say which devices you trust
4. Anything online but NOT on that list gets flagged "unauthorized"
"""

import json
import os
import re
import socket
import sqlite3
import subprocess
import platform
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, jsonify, render_template

app = Flask(__name__)

DB_PATH = "network.db"
ALLOWED_DEVICES_PATH = "allowed_devices.json"
SCAN_INTERVAL_SECONDS = 30
PING_TIMEOUT_SECONDS = 1
MAX_WORKERS = 50


# ---------- Allow list ----------
# This is the actual "zero trust policy" - a simple JSON file mapping
# MAC address -> friendly name. Anything not in here is untrusted.

def load_allowed_devices():
    if not os.path.exists(ALLOWED_DEVICES_PATH):
        # Create a starter file with instructions baked in as an example
        starter = {
            "_instructions": "Add your trusted devices below as \"MAC_ADDRESS\": \"Device Name\". Delete this _instructions line, it's just a comment.",
            "aa:bb:cc:dd:ee:ff": "Example - My Laptop"
        }
        with open(ALLOWED_DEVICES_PATH, "w") as f:
            json.dump(starter, f, indent=2)
        return starter
    with open(ALLOWED_DEVICES_PATH) as f:
        return json.load(f)


# ---------- Database ----------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            status TEXT,
            authorized INTEGER,
            device_name TEXT,
            last_seen TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            mac TEXT,
            status TEXT,
            authorized INTEGER,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()


# ---------- Network scanning ----------

def get_local_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    subnet_prefix = ".".join(local_ip.split(".")[:3])
    return subnet_prefix, local_ip


def ping(ip):
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    timeout_value = str(PING_TIMEOUT_SECONDS * 1000) if is_windows else str(PING_TIMEOUT_SECONDS)
    command = ["ping", count_flag, "1", timeout_flag, timeout_value, ip]
    try:
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=PING_TIMEOUT_SECONDS + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_mac_address(ip):
    """Reads the system's ARP table to find the MAC address for an IP.
    Works on both Mac and Windows, just with slightly different command
    output formatting, so we parse both.
    """
    try:
        result = subprocess.run(
            ["arp", "-n", ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, text=True
        )
        output = result.stdout
        # Mac/Linux format:  ? (192.168.1.5) at a1:b2:c3:d4:e5:f6 on en0 ...
        # Windows format:    192.168.1.5    a1-b2-c3-d4-e5-f6   dynamic
        match = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", output)
        if match:
            return match.group(0).lower().replace("-", ":")
    except Exception:
        pass
    return None


def scan_network():
    subnet_prefix, local_ip = get_local_subnet()
    addresses = [f"{subnet_prefix}.{i}" for i in range(1, 255)]

    online_ips = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(ping, ip): ip for ip in addresses}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                online_ips.append(ip)

    save_scan_results(addresses, online_ips)
    return online_ips


def save_scan_results(all_addresses, online_ips):
    allowed = load_allowed_devices()
    # Build a lookup that ignores the _instructions comment key
    allowed_macs = {k.lower(): v for k, v in allowed.items() if k != "_instructions"}

    conn = sqlite3.connect(DB_PATH)
    now = datetime.now().isoformat()
    online_set = set(online_ips)

    for ip in all_addresses:
        status = "online" if ip in online_set else "offline"
        cur = conn.execute("SELECT ip FROM devices WHERE ip = ?", (ip,))
        exists = cur.fetchone() is not None

        if status == "online" or exists:
            mac = get_mac_address(ip) if status == "online" else None
            hostname = get_hostname(ip) if status == "online" else None

            authorized = 0
            device_name = None
            if mac and mac in allowed_macs:
                authorized = 1
                device_name = allowed_macs[mac]
            elif status == "online":
                authorized = 0  # online but not recognized = flagged

            conn.execute(
                """INSERT INTO devices (ip, mac, hostname, status, authorized, device_name, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                     mac=COALESCE(excluded.mac, devices.mac),
                     status=excluded.status,
                     authorized=excluded.authorized,
                     device_name=COALESCE(excluded.device_name, devices.device_name),
                     last_seen=CASE WHEN excluded.status='online' THEN excluded.last_seen ELSE devices.last_seen END,
                     hostname=COALESCE(excluded.hostname, devices.hostname)
                """,
                (ip, mac, hostname, status, authorized, device_name, now),
            )
            conn.execute(
                "INSERT INTO history (ip, mac, status, authorized, timestamp) VALUES (?, ?, ?, ?, ?)",
                (ip, mac, status, authorized, now),
            )

    conn.commit()
    conn.close()


def background_scanner():
    while True:
        try:
            scan_network()
        except Exception as e:
            print(f"Scan error: {e}")
        time.sleep(SCAN_INTERVAL_SECONDS)


# ---------- API routes ----------

@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ip, mac, hostname, status, authorized, device_name, last_seen FROM devices ORDER BY authorized ASC, status DESC, ip"
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route("/api/summary")
def api_summary():
    conn = sqlite3.connect(DB_PATH)
    total_online = conn.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
    authorized_online = conn.execute("SELECT COUNT(*) FROM devices WHERE status='online' AND authorized=1").fetchone()[0]
    unauthorized_online = conn.execute("SELECT COUNT(*) FROM devices WHERE status='online' AND authorized=0").fetchone()[0]
    conn.close()
    _, local_ip = get_local_subnet()
    return jsonify({
        "total_online": total_online,
        "authorized_online": authorized_online,
        "unauthorized_online": unauthorized_online,
        "your_ip": local_ip,
    })


if __name__ == "__main__":
    init_db()
    load_allowed_devices()  # creates the starter file if missing
    threading.Thread(target=scan_network, daemon=True).start()
    threading.Thread(target=background_scanner, daemon=True).start()
    app.run(debug=True, port=5001)
