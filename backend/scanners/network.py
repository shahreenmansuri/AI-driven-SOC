# network.py — Watches all internet connections your computer is making RIGHT NOW
# FIXED for Windows — no more 'invalid attr name connections' error

import psutil
from datetime import datetime

# List of ports that are commonly used by malware or suspicious software
SUSPICIOUS_PORTS = {
    4444: "Metasploit default backdoor port",
    1337: "Common hacker/backdoor port",
    31337: "Classic backdoor port (Elite)",
    6667: "IRC - often used by botnets",
    6666: "Backdoor/botnet communication",
    9001: "Tor relay port",
    9050: "Tor SOCKS proxy",
    23: "Telnet - unencrypted, old and insecure",
    513: "Rlogin - old insecure remote login",
}

def get_active_connections():
    """
    Gets ALL network connections your computer is making right now.
    This is REAL-TIME — not a snapshot. Every time this runs, it reads
    live data from your operating system.

    FIX: On Windows, psutil.net_connections(kind='inet') can fail with
    'invalid attr name' error. We now loop through each process individually
    using proc.net_connections() which works correctly on Windows.
    """
    connections = []

    try:
        # Loop through every running process and get its network connections
        # This is the Windows-safe way to get all connections with process names
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # Get all network connections for this specific process
                proc_conns = proc.net_connections()

                for conn in proc_conns:
                    # Skip if no remote address (means it's just listening, not connected)
                    if not conn.raddr:
                        continue

                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port if conn.laddr else 0
                    status = conn.status
                    process_name = proc.info['name'] or "Unknown"
                    process_pid = proc.info['pid']

                    # Check if this connection looks suspicious
                    threat_level = "safe"
                    threat_reason = ""

                    # Check 1: Is remote port a known malicious port?
                    if remote_port in SUSPICIOUS_PORTS:
                        threat_level = "danger"
                        threat_reason = SUSPICIOUS_PORTS[remote_port]

                    # Check 2: Port range commonly used by remote access tools
                    elif remote_port in range(4444, 4450):
                        threat_level = "warning"
                        threat_reason = "Port range commonly used by remote access tools"

                    # Check 3: Is a command shell making an internet connection?
                    elif status == "ESTABLISHED" and not remote_ip.startswith("10."):
                        if process_name.lower() in ["cmd.exe", "powershell.exe", "bash", "sh"]:
                            threat_level = "danger"
                            threat_reason = "Command shell making internet connection — very suspicious!"

                    connections.append({
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "status": status,
                        "process": process_name,
                        "pid": process_pid,
                        "threat_level": threat_level,
                        "threat_reason": threat_reason,
                        "timestamp": datetime.now().isoformat()
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Some system processes we can't read — that's normal, skip them
                continue

    except Exception as e:
        print(f"Network scan error: {e}")

    return connections


def get_network_stats():
    """
    Gets how much data your computer is sending/receiving right now.
    Useful for detecting if something is secretly uploading your files.
    """
    try:
        stats = psutil.net_io_counters()
        return {
            "bytes_sent": stats.bytes_sent,
            "bytes_received": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_received": stats.packets_recv,
        }
    except Exception as e:
        print(f"Network stats error: {e}")
        return {
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_received": 0,
        }