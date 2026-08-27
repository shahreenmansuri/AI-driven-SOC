# demo_threat.py — SAFE DEMO FILE for showing professor
# This file SIMULATES a threat — it does NOT harm your computer
# It creates fake suspicious files and activity that the scanner detects
# Run this WHILE the security agent is running to see it get detected

import os
import time
import socket
import threading

print("=" * 55)
print("  DEMO THREAT SIMULATOR")
print("  This is SAFE — only for demonstration purposes")
print("  Run the Security Agent dashboard to see detections")
print("=" * 55)
print()

# ── Demo 1: Create suspicious files in Downloads ──────
def create_suspicious_files():
    home = os.path.expanduser("~")
    downloads = os.path.join(home, "Downloads")
    
    suspicious_files = [
        ("keylogger_demo.exe.txt",   "DEMO: fake keylogger file"),
        ("cryptominer_demo.bat.txt", "DEMO: fake crypto miner"),
        ("ransom_note_demo.txt",     "DEMO: fake ransomware note — YOUR FILES ARE DEMO ENCRYPTED"),
        ("suspicious_script.vbs.txt","DEMO: fake VBScript malware"),
    ]
    
    created = []
    for filename, content in suspicious_files:
        path = os.path.join(downloads, filename)
        with open(path, "w") as f:
            f.write(content + "\n")
            f.write("This is a DEMO file created by demo_threat.py\n")
            f.write("It is completely safe and can be deleted.\n")
        created.append(path)
        print(f"[DEMO] Created suspicious file: {filename}")
        time.sleep(0.5)  # Small delay so file watcher catches each one
    
    return created

# ── Demo 2: Rapidly modify files (ransomware pattern) ─
def simulate_ransomware_pattern():
    home = os.path.expanduser("~")
    downloads = os.path.join(home, "Downloads")
    demo_files = []
    
    print("\n[DEMO] Simulating ransomware file modification pattern...")
    print("[DEMO] Creating and modifying 25 files rapidly...")
    
    # Create 25 fake document files and modify them rapidly
    # This triggers the ransomware detection (>20 files/min)
    for i in range(25):
        path = os.path.join(downloads, f"demo_document_{i}.txt")
        with open(path, "w") as f:
            f.write(f"DEMO document {i} - simulating ransomware pattern\n")
        demo_files.append(path)
    
    print(f"[DEMO] Modified 25 files rapidly — scanner should detect ransomware pattern!")
    return demo_files

# ── Demo 3: Open a local port (simulates backdoor) ────
def simulate_open_port():
    print("\n[DEMO] Opening a local port to simulate network threat...")
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('127.0.0.1', 9999))
        server.listen(1)
        print("[DEMO] Opened port 9999 — scanner will detect this as suspicious activity")
        print("[DEMO] Port will auto-close in 60 seconds...")
        server.settimeout(60)
        try:
            server.accept()
        except:
            pass
        server.close()
        print("[DEMO] Port 9999 closed")
    except Exception as e:
        print(f"[DEMO] Could not open port: {e}")

# ── Demo 4: Cleanup function ──────────────────────────
def cleanup(files):
    print("\n[DEMO] Cleaning up demo files...")
    for f in files:
        try:
            if os.path.exists(f):
                os.remove(f)
                print(f"[DEMO] Deleted: {os.path.basename(f)}")
        except:
            pass
    print("[DEMO] Cleanup complete!")

# ── Run the demo ──────────────────────────────────────
print("Starting demo in 3 seconds...")
print("Make sure your Security Agent dashboard is open!\n")
time.sleep(3)

print("STEP 1 — Creating suspicious files in Downloads folder...")
created_files = create_suspicious_files()
print(f"✅ Created {len(created_files)} suspicious files")
print("👉 Check the FILE SYSTEM panel in your dashboard!\n")
time.sleep(3)

print("STEP 2 — Simulating ransomware file modification pattern...")
ransomware_files = simulate_ransomware_pattern()
created_files.extend(ransomware_files)
print("✅ Ransomware pattern triggered")
print("👉 Check the FILE SYSTEM panel for RANSOMWARE WARNING!\n")
time.sleep(3)

print("STEP 3 — Opening suspicious port...")
port_thread = threading.Thread(target=simulate_open_port, daemon=True)
port_thread.start()
print("✅ Suspicious port opened")
print("👉 Check the NETWORK CONNECTIONS panel!\n")

print("=" * 55)
print("  ALL DEMO THREATS ARE NOW ACTIVE!")
print("  Look at your Security Agent dashboard:")
print("  - File System panel shows suspicious files")
print("  - Ransomware warning should appear")
print("  - AI advisor will explain the threats")
print("  - Click 'Auto-Fix' to cure everything!")
print("=" * 55)
print()
print("Waiting 30 seconds then cleaning up automatically...")
print("(Or press Ctrl+C to clean up now)")

try:
    time.sleep(30)
except KeyboardInterrupt:
    print("\n[DEMO] Interrupted by user")

cleanup(created_files)
print("\n[DEMO] Demo complete! All fake threats removed.")
print("[DEMO] Your computer was never in any real danger.")