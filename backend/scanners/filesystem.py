# filesystem.py — Watches files for suspicious changes IN REAL TIME
# FIXED: Now properly flags suspicious files as WARNING/DANGER

import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from collections import deque

# These extensions are suspicious — malware often uses them
SUSPICIOUS_EXTENSIONS = [
    '.bat', '.cmd', '.vbs', '.ps1', '.js', '.jar',
    '.exe', '.msi', '.scr', '.pif', '.com',
    # Ransomware encrypted extensions
    '.encrypted', '.locked', '.crypt', '.crypto',
    '.wncry', '.wcry', '.locky', '.cerber', '.zepto',
    '.zzzzz', '.cerber3', '.osiris', '.wallet',
]

# Files with these words in their name are suspicious
SUSPICIOUS_KEYWORDS = [
    'keylogger', 'cryptominer', 'miner', 'ransom',
    'backdoor', 'trojan', 'virus', 'malware', 'spyware',
    'hack', 'exploit', 'payload', 'stealer', 'password_steal',
    'rat_', 'botnet', 'rootkit', 'worm',
]

# Important files targeted by ransomware
RANSOMWARE_TARGET_EXTENSIONS = [
    '.docx', '.xlsx', '.pdf', '.jpg', '.jpeg', '.png',
    '.mp4', '.mov', '.zip', '.rar', '.db', '.sql',
    '.psd', '.ai', '.key', '.pptx', '.txt',
]

# Ransomware speed threshold — if more than this many files
# change in 60 seconds, it is likely ransomware
RANSOMWARE_SPEED_THRESHOLD = 15


class SecurityFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.recent_events = deque(maxlen=1000)
        self.alerts = []
        self._lock = threading.Lock()

    def on_any_event(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path).lower()
        file_ext  = os.path.splitext(file_path)[1].lower()
        event_type = event.event_type  # created, modified, deleted, moved

        threat_level  = "info"
        threat_reason = ""

        # ── Check 1: Suspicious extension ──────────────────
        if file_ext in SUSPICIOUS_EXTENSIONS:
            # Ransomware extensions = DANGER
            ransomware_exts = [
                '.encrypted', '.locked', '.crypt', '.wncry',
                '.locky', '.cerber', '.zepto', '.zzzzz', '.osiris', '.wallet'
            ]
            if file_ext in ransomware_exts:
                threat_level  = "danger"
                threat_reason = f"RANSOMWARE ALERT: File has ransomware extension '{file_ext}' — your files may be being encrypted!"
            else:
                threat_level  = "warning"
                threat_reason = f"Suspicious file extension '{file_ext}' — this type of file can execute malicious code"

        # ── Check 2: Suspicious keywords in filename ────────
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in file_name:
                threat_level  = "danger"
                threat_reason = f"Suspicious filename contains '{keyword}' — this looks like malware!"
                break

        # ── Check 3: Ransomware speed detection ─────────────
        if file_ext in RANSOMWARE_TARGET_EXTENSIONS:
            with self._lock:
                now = time.time()
                recent_changes = sum(
                    1 for e in self.recent_events
                    if e.get('is_target') and (now - e.get('time', 0)) < 60
                )
                if recent_changes > RANSOMWARE_SPEED_THRESHOLD:
                    threat_level  = "danger"
                    threat_reason = (
                        f"RANSOMWARE WARNING: {recent_changes} important files "
                        f"changed in 60 seconds! This matches ransomware behavior."
                    )

        # ── Check 4: File renamed to suspicious extension ───
        if event_type == 'moved' and hasattr(event, 'dest_path'):
            dest_ext = os.path.splitext(event.dest_path)[1].lower()
            if dest_ext in ['.encrypted', '.locked', '.crypt', '.wncry', '.locky']:
                threat_level  = "danger"
                threat_reason = f"File renamed to ransomware extension '{dest_ext}' — RANSOMWARE ACTIVE!"
            dest_name = os.path.basename(event.dest_path).lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in dest_name:
                    threat_level  = "warning"
                    threat_reason = f"File renamed to suspicious name containing '{keyword}'"
                    break

        event_data = {
            "file":         file_path,
            "event_type":   event_type,
            "extension":    file_ext,
            "threat_level": threat_level,
            "threat_reason": threat_reason,
            "is_target":    file_ext in RANSOMWARE_TARGET_EXTENSIONS,
            "time":         time.time(),
            "timestamp":    datetime.now().isoformat()
        }

        with self._lock:
            self.recent_events.append(event_data)
            # Store warnings and dangers as alerts
            if threat_level in ["warning", "danger"]:
                # Avoid duplicate alerts for the same file
                already = any(a['file'] == file_path for a in self.alerts)
                if not already:
                    self.alerts.append(event_data)

    def get_recent_alerts(self):
        with self._lock:
            # Return alerts but DON'T clear them
            # They persist until manually dismissed
            return list(self.alerts)

    def clear_alert(self, file_path):
        """Remove a specific alert after it's been fixed."""
        with self._lock:
            self.alerts = [a for a in self.alerts if a['file'] != file_path]

    def get_recent_events(self, limit=50):
        with self._lock:
            return list(self.recent_events)[-limit:]


# Global handler and observer
_handler  = SecurityFileHandler()
_observer = None


def start_filesystem_watcher(paths_to_watch=None):
    global _observer

    if paths_to_watch is None:
        home = os.path.expanduser("~")
        paths_to_watch = [
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
        ]

    _observer = Observer()
    for path in paths_to_watch:
        if os.path.exists(path):
            _observer.schedule(_handler, path, recursive=True)
            print(f"Watching: {path}")

    _observer.start()
    print("File system watcher started (real-time, event-driven)")
    return _observer


def get_filesystem_alerts():
    """Returns alerts — stays persistent until files are fixed."""
    return _handler.get_recent_alerts()


def clear_filesystem_alert(file_path):
    """Call this after a file is deleted to remove its alert."""
    _handler.clear_alert(file_path)


def get_filesystem_events():
    return _handler.get_recent_events()


def stop_filesystem_watcher():
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()