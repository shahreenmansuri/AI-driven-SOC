# auto_fixer.py — Automatically fixes security threats for the user
# Each fix function does the actual repair on the real system

import subprocess
import psutil
import os
import sys
import ctypes
import platform
from datetime import datetime

def is_admin():
    """Check if running as administrator — some fixes need admin rights."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def fix_open_port(port: int) -> dict:
    """
    Closes a dangerous open port by adding a Windows Firewall rule.
    This is like locking a specific door in your house.
    """
    try:
        port_names = {
            445: "SMB File Sharing",
            135: "RPC",
            139: "NetBIOS",
            3389: "Remote Desktop",
            23: "Telnet",
            21: "FTP",
            5900: "VNC",
        }
        port_name = port_names.get(port, f"Port {port}")

        # Add Windows Firewall rule to BLOCK this port
        # netsh is a built-in Windows command to manage firewall
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=SecurityAgent_Block_{port}",
            "dir=in",
            "action=block",
            f"protocol=TCP",
            f"localport={port}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            return {
                "success": True,
                "action": f"Blocked port {port} ({port_name})",
                "message": f"✅ Port {port} has been blocked in Windows Firewall. Hackers can no longer use this door to enter your computer.",
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "success": False,
                "action": f"Failed to block port {port}",
                "message": f"❌ Could not block port {port}. Try running as Administrator.\nError: {result.stderr}",
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        return {
            "success": False,
            "action": f"Error blocking port {port}",
            "message": f"❌ Error: {str(e)}. Please run as Administrator.",
            "timestamp": datetime.now().isoformat()
        }


def kill_suspicious_process(pid: int, name: str) -> dict:
    """
    Terminates a suspicious process.
    Like asking a suspicious person to leave your house.
    """
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()

        # Safety check — never kill critical system processes
        protected = [
            "system", "smss.exe", "csrss.exe", "wininit.exe",
            "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe",
            "explorer.exe", "taskmgr.exe", "python.exe", "pythonw.exe"
        ]
        if proc_name.lower() in protected:
            return {
                "success": False,
                "action": f"Refused to kill {proc_name}",
                "message": f"⚠️ '{proc_name}' is a protected system process. Killing it could crash your computer. Skipped for safety.",
                "timestamp": datetime.now().isoformat()
            }

        proc.terminate()  # Gentle termination first
        proc.wait(timeout=3)

        return {
            "success": True,
            "action": f"Terminated process {proc_name} (PID {pid})",
            "message": f"✅ The suspicious program '{proc_name}' has been stopped. It is no longer running on your computer.",
            "timestamp": datetime.now().isoformat()
        }

    except psutil.NoSuchProcess:
        return {
            "success": True,
            "action": f"Process {name} already stopped",
            "message": f"✅ The process '{name}' is no longer running (it may have stopped on its own).",
            "timestamp": datetime.now().isoformat()
        }
    except psutil.AccessDenied:
        return {
            "success": False,
            "action": f"Access denied killing {name}",
            "message": f"❌ Cannot stop '{name}' — it's protected by Windows. Try running as Administrator.",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "action": f"Error killing {name}",
            "message": f"❌ Error stopping '{name}': {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


def delete_suspicious_file(file_path: str) -> dict:
    """
    Deletes a suspicious file.
    Like throwing away something dangerous you found in your house.
    """
    try:
        # Safety check — never delete system files
        protected_dirs = [
            "c:\\windows\\system32",
            "c:\\windows\\syswow64",
            "c:\\program files",
        ]
        for protected in protected_dirs:
            if file_path.lower().startswith(protected):
                return {
                    "success": False,
                    "action": f"Refused to delete system file",
                    "message": f"⚠️ This file is in a protected system folder. Deleting it could break Windows. Skipped for safety.",
                    "timestamp": datetime.now().isoformat()
                }

        if os.path.exists(file_path):
            os.remove(file_path)
            # Clear the alert from the file watcher
            try:
                from scanners.filesystem import clear_filesystem_alert
                clear_filesystem_alert(file_path)
            except:
                pass
            return {
                "success": True,
                "action": f"Deleted file: {os.path.basename(file_path)}",
                "message": f"✅ The suspicious file '{os.path.basename(file_path)}' has been deleted from your computer.",
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "success": True,
                "action": f"File already gone",
                "message": f"✅ The file no longer exists (it may have been removed already).",
                "timestamp": datetime.now().isoformat()
            }
    except PermissionError:
        return {
            "success": False,
            "action": f"Permission denied",
            "message": f"❌ Cannot delete this file — it may be in use. Try running as Administrator.",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "action": f"Error deleting file",
            "message": f"❌ Error: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


def disable_telnet() -> dict:
    """Disables the Telnet service which is old and insecure."""
    try:
        result = subprocess.run(
            ["sc", "config", "TlntSvr", "start=", "disabled"],
            capture_output=True, text=True, timeout=10
        )
        subprocess.run(["sc", "stop", "TlntSvr"], capture_output=True, timeout=10)
        return {
            "success": True,
            "action": "Disabled Telnet service",
            "message": "✅ Telnet has been disabled. This old insecure service can no longer be used by attackers.",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "action": "Failed to disable Telnet",
            "message": f"❌ Error: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


def run_windows_defender_scan() -> dict:
    """Triggers a Windows Defender quick scan."""
    try:
        defender_path = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
        if os.path.exists(defender_path):
            subprocess.Popen([defender_path, "-Scan", "-ScanType", "1"])
            return {
                "success": True,
                "action": "Started Windows Defender scan",
                "message": "✅ Windows Defender antivirus scan has been started! It will scan your computer for viruses in the background. Check the system tray for progress.",
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "success": False,
                "action": "Windows Defender not found",
                "message": "❌ Windows Defender not found at expected location.",
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        return {
            "success": False,
            "action": "Failed to start scan",
            "message": f"❌ Error: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }


def fix_all_threats(scan_results: dict) -> list:
    """
    Master fix function — automatically fixes ALL detected threats.
    Returns a list of fix results.
    """
    results = []

    # Fix 1: Block dangerous open ports
    for port_info in scan_results.get("open_ports", []):
        if port_info["threat_level"] == "danger":
            result = fix_open_port(port_info["port"])
            result["threat_type"] = "open_port"
            result["port"] = port_info["port"]
            results.append(result)

    # Fix 2: Kill dangerous processes
    for proc in scan_results.get("processes", []):
        if proc["threat_level"] == "danger":
            result = kill_suspicious_process(proc["pid"], proc["name"])
            result["threat_type"] = "process"
            result["process_name"] = proc["name"]
            results.append(result)

    # Fix 3: Run antivirus scan
    av_result = run_windows_defender_scan()
    av_result["threat_type"] = "antivirus_scan"
    results.append(av_result)

    return results