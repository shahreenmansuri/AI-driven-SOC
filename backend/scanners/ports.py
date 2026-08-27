# ports.py — Checks which doors (ports) on your computer are open to the internet

import psutil
import socket
from datetime import datetime

# Ports that should NEVER be open on a normal home/office computer
DANGEROUS_OPEN_PORTS = {
    21: ("FTP", "danger", "Unencrypted file transfer — password travels in plain text"),
    22: ("SSH", "warning", "Remote access port — make sure you know it's open intentionally"),
    23: ("Telnet", "danger", "Very old insecure remote access — should not be open"),
    25: ("SMTP", "warning", "Email sending port — could be used by spam malware"),
    135: ("RPC", "warning", "Windows remote procedure — has many known vulnerabilities"),
    137: ("NetBIOS", "warning", "Windows file sharing — should not be exposed to internet"),
    139: ("NetBIOS", "warning", "Windows file sharing — common attack target"),
    445: ("SMB", "danger", "Windows file sharing — used by WannaCry and other ransomware!"),
    1433: ("MSSQL", "warning", "Database port — should never be open to internet"),
    3306: ("MySQL", "warning", "Database port — should never be open to internet"),
    3389: ("RDP", "danger", "Windows remote desktop — major attack target, many vulnerabilities"),
    4444: ("Metasploit", "danger", "Default backdoor port — very suspicious!"),
    5900: ("VNC", "danger", "Remote desktop — often targeted by attackers"),
    6667: ("IRC", "warning", "Chat protocol often used by botnets"),
    8080: ("HTTP Alt", "info", "Web server on alternate port"),
    27017: ("MongoDB", "danger", "Database with NO authentication by default — dangerous if open!"),
}

def scan_open_ports():
    """
    Scans which ports are currently open and listening on YOUR computer.
    Uses psutil to read from the OS — real-time data, no simulation.
    """
    open_ports = []
    
    try:
        # Get all network connections that are in LISTEN state
        # LISTEN means: "waiting for incoming connections on this port"
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                port = conn.laddr.port
                
                # Find which program is listening on this port
                process_name = "Unknown"
                try:
                    if conn.pid:
                        process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                # Look up our threat database for this port
                if port in DANGEROUS_OPEN_PORTS:
                    service, threat_level, description = DANGEROUS_OPEN_PORTS[port]
                else:
                    service = "Unknown Service"
                    threat_level = "info"
                    description = "Port is open but not in our known-dangerous list"
                
                open_ports.append({
                    "port": port,
                    "service": service,
                    "process": process_name,
                    "pid": conn.pid,
                    "threat_level": threat_level,
                    "description": description,
                    "address": conn.laddr.ip,
                    "timestamp": datetime.now().isoformat()
                })
    
    except Exception as e:
        print(f"Port scan error: {e}")
    
    return open_ports