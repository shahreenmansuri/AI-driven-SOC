# usb.py — Watches for USB devices being plugged in (BadUSB attacks are real!)

import psutil
import os
import platform
from datetime import datetime

# Keep track of what drives were connected before
_known_drives = set()

def get_connected_drives():
    """
    Gets a list of ALL connected drives (USB, external HDD, etc.) right now.
    Uses psutil to read disk partitions — real-time from the OS.
    """
    drives = []
    
    try:
        for partition in psutil.disk_partitions(all=False):
            drive_info = {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype,
                "opts": partition.opts,
                "timestamp": datetime.now().isoformat()
            }
            
            # Try to get disk usage info
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                drive_info["total_gb"] = round(usage.total / (1024**3), 2)
                drive_info["used_gb"] = round(usage.used / (1024**3), 2)
                drive_info["free_gb"] = round(usage.free / (1024**3), 2)
            except (PermissionError, OSError):
                drive_info["total_gb"] = 0
            
            drives.append(drive_info)
    
    except Exception as e:
        print(f"Drive scan error: {e}")
    
    return drives

def check_for_new_usb_devices():
    """
    Detects when a NEW USB device is plugged in since last check.
    This is how we catch BadUSB attacks (malicious USB drives disguised as normal ones).
    """
    global _known_drives
    
    current_drives = set()
    for partition in psutil.disk_partitions(all=False):
        current_drives.add(partition.device)
    
    # Find drives that weren't there before
    new_drives = current_drives - _known_drives
    removed_drives = _known_drives - current_drives
    
    alerts = []
    
    for drive in new_drives:
        alerts.append({
            "type": "new_device",
            "device": drive,
            "threat_level": "warning",
            "message": (
                f"New storage device connected: {drive}. "
                "If you didn't plug in a USB drive, this could be a BadUSB attack!"
            ),
            "timestamp": datetime.now().isoformat()
        })
    
    # Update our known drives list
    _known_drives = current_drives
    
    return alerts, list(new_drives), list(removed_drives)

# Initialize known drives on first run
_known_drives = set(p.device for p in psutil.disk_partitions(all=False))