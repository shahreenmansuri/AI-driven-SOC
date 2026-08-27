# processes.py — FIXED for Windows

import psutil
import os
from datetime import datetime

HIGH_RISK_PROCESS_NAMES = [
    "mimikatz", "lazagne", "pwdump", "fgdump",
    "netcat", "nc.exe", "ncat",
    "msfconsole", "meterpreter",
    "keylogger", "keygrabber",
    "cryptominer", "xmrig", "minergate",
]

MEDIUM_RISK_PROCESS_NAMES = [
    "powershell", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32",
    "certutil", "bitsadmin",
]

def get_running_processes():
    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline',
                                      'cpu_percent', 'memory_percent', 'username']):
        try:
            info = proc.info
            name_lower = (info['name'] or "").lower()

            threat_level = "safe"
            threat_reasons = []

            for bad_name in HIGH_RISK_PROCESS_NAMES:
                if bad_name in name_lower:
                    threat_level = "danger"
                    threat_reasons.append(f"Known malicious tool: {bad_name}")

            for medium_name in MEDIUM_RISK_PROCESS_NAMES:
                if medium_name in name_lower and threat_level == "safe":
                    threat_level = "warning"
                    threat_reasons.append("Powerful system tool that can be misused")

            cpu = info.get('cpu_percent', 0) or 0
            if cpu > 80:
                if threat_level == "safe":
                    threat_level = "warning"
                threat_reasons.append(f"Very high CPU usage ({cpu}%) — possible crypto miner")

            exe_path = info.get('exe', '') or ''
            suspicious_paths = ['\\temp\\', '/tmp/', '\\appdata\\local\\temp\\',
                                 '\\downloads\\', '/downloads/']
            for sus_path in suspicious_paths:
                if sus_path.lower() in exe_path.lower():
                    if threat_level == "safe":
                        threat_level = "warning"
                    threat_reasons.append(f"Running from suspicious location: {exe_path}")
                    break

            cmdline = info.get('cmdline', []) or []
            cmdline_str = ' '.join(cmdline)
            if any(tool in name_lower for tool in ['powershell', 'wscript', 'cscript']):
                if len(cmdline_str) > 500:
                    threat_level = "danger"
                    threat_reasons.append("Script running very long obfuscated command")
                if '-enc' in cmdline_str.lower() or '-encodedcommand' in cmdline_str.lower():
                    threat_level = "danger"
                    threat_reasons.append("PowerShell running ENCODED (hidden) command — red flag!")

            processes.append({
                "pid": info['pid'],
                "name": info['name'] or "Unknown",
                "exe": exe_path,
                "cpu_percent": cpu,
                "memory_percent": round(info.get('memory_percent', 0) or 0, 2),
                "username": info.get('username', 'unknown') or 'unknown',
                "threat_level": threat_level,
                "threat_reasons": threat_reasons,
                "timestamp": datetime.now().isoformat()
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes