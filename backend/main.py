# main.py — Complete final version with Auto-Fix endpoints

import asyncio
from dotenv import load_dotenv
load_dotenv()
import os
import time
import webbrowser
import threading
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn

from scanners.network import get_active_connections, get_network_stats
from scanners.processes import get_running_processes
from scanners.filesystem import start_filesystem_watcher, get_filesystem_alerts, get_filesystem_events
from scanners.ports import scan_open_ports
from scanners.usb import check_for_new_usb_devices, get_connected_drives
from ai_analyzer import analyze_threats_with_ai
from auto_fixer import fix_open_port, kill_suspicious_process, delete_suspicious_file, run_windows_defender_scan, fix_all_threats

app = FastAPI(title="AI Security Agent", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connected_clients = []

# Stores the last scan so fix/all can use it
_last_scan_data = {}

print("Starting real-time file system watcher...")
start_filesystem_watcher()


def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://localhost:8001")


async def run_all_scanners():
    start_time = time.time()
    loop = asyncio.get_event_loop()

    try:
        connections = await loop.run_in_executor(None, get_active_connections)
    except Exception as e:
        print(f"[ERROR] network scanner: {e}")
        connections = []

    try:
        processes = await loop.run_in_executor(None, get_running_processes)
    except Exception as e:
        print(f"[ERROR] process scanner: {e}")
        processes = []

    try:
        open_ports = await loop.run_in_executor(None, scan_open_ports)
    except Exception as e:
        print(f"[ERROR] port scanner: {e}")
        open_ports = []

    try:
        net_stats = await loop.run_in_executor(None, get_network_stats)
    except Exception as e:
        print(f"[ERROR] net stats: {e}")
        net_stats = {}

    try:
        fs_alerts = get_filesystem_alerts()
        fs_events = get_filesystem_events()
    except Exception as e:
        print(f"[ERROR] filesystem scanner: {e}")
        fs_alerts = []
        fs_events = []

    try:
        usb_alerts, new_drives, removed_drives = await loop.run_in_executor(
            None, check_for_new_usb_devices
        )
        connected_drives = await loop.run_in_executor(None, get_connected_drives)
    except Exception as e:
        print(f"[ERROR] USB scanner: {e}")
        usb_alerts = []
        connected_drives = []

    return {
        "connections": connections,
        "processes": processes,
        "open_ports": open_ports,
        "net_stats": net_stats,
        "filesystem_alerts": fs_alerts,
        "filesystem_events": fs_events[-20:],
        "usb_alerts": usb_alerts,
        "connected_drives": connected_drives,
        "scan_duration_seconds": round(time.time() - start_time, 2),
        "scan_timestamp": datetime.now().isoformat()
    }


_last_ai_analysis = None
_last_ai_time = 0
AI_ANALYSIS_INTERVAL = 60


async def get_full_security_report():
    global _last_ai_analysis, _last_ai_time, _last_scan_data

    scan_data = await run_all_scanners()
    _last_scan_data = scan_data

    current_time = time.time()
    time_since_last = current_time - _last_ai_time

    should_update = (
        _last_ai_analysis is None or
        time_since_last > AI_ANALYSIS_INTERVAL
    )

    if should_update:
        print("Requesting AI analysis...")
        loop = asyncio.get_event_loop()

        new_analysis = await loop.run_in_executor(
            None, analyze_threats_with_ai, scan_data
        )

        if new_analysis is not None:
            _last_ai_analysis = new_analysis
            print("✅ AI analysis updated — threats changed!")
        else:
            print("⏭ Threats unchanged — using cached AI analysis")

        _last_ai_time = current_time

    return {
        "scan_data": scan_data,
        "ai_analysis": _last_ai_analysis,
        "next_ai_update_in": int(
            AI_ANALYSIS_INTERVAL - (current_time - _last_ai_time)
        )
    }


# ── WebSocket ──────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)

    print(f"Client connected. Total clients: {len(connected_clients)}")

    try:
        while True:
            report = await get_full_security_report()
            await websocket.send_json(report)
            await asyncio.sleep(5)

    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

        print(
            f"Client disconnected. Total clients: "
            f"{len(connected_clients)}"
        )

    except Exception as e:
        print(f"WebSocket error: {e}")

        if websocket in connected_clients:
            connected_clients.remove(websocket)


# ── Frontend ───────────────────────────────────────────
@app.get("/")
async def serve_frontend():
    relative_path = "../frontend/index.html"

    absolute_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "frontend",
        "index.html"
    )

    if os.path.exists(relative_path):
        return FileResponse(relative_path)

    elif os.path.exists(absolute_path):
        return FileResponse(absolute_path)

    else:
        return {
            "error": f"index.html not found. "
                     f"Looked in: {absolute_path}"
        }


@app.get("/health")
async def health_check():
    return {
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }


# ── Auto-Fix Endpoints ─────────────────────────────────

@app.post("/fix/port/{port}")
async def fix_port(port: int):
    """Block a dangerous open port using Windows Firewall."""

    loop = asyncio.get_event_loop()

    result = await loop.run_in_executor(
        None,
        fix_open_port,
        port
    )

    print(
        f"Fix port {port}: "
        f"{result['success']} — {result['action']}"
    )

    return result


@app.post("/fix/process/{pid}")
async def fix_process(pid: int, name: str = "unknown"):
    """Terminate a suspicious process."""

    loop = asyncio.get_event_loop()

    result = await loop.run_in_executor(
        None,
        kill_suspicious_process,
        pid,
        name
    )

    print(
        f"Fix process {name} ({pid}): "
        f"{result['success']} — {result['action']}"
    )

    return result


@app.post("/fix/file")
async def fix_file(data: dict = Body(...)):
    """Delete a suspicious file."""

    file_path = data.get("path", "")

    loop = asyncio.get_event_loop()

    result = await loop.run_in_executor(
        None,
        delete_suspicious_file,
        file_path
    )

    print(
        f"Fix file {file_path}: "
        f"{result['success']} — {result['action']}"
    )

    return result


@app.post("/fix/scan")
async def fix_scan():
    """Run Windows Defender antivirus scan."""

    loop = asyncio.get_event_loop()

    result = await loop.run_in_executor(
        None,
        run_windows_defender_scan
    )

    print(
        f"Fix scan: "
        f"{result['success']} — {result['action']}"
    )

    return result


@app.post("/fix/all")
async def fix_all():
    """Fix ALL detected threats using the last scan data."""

    global _last_scan_data

    loop = asyncio.get_event_loop()

    results = await loop.run_in_executor(
        None,
        fix_all_threats,
        _last_scan_data
    )

    success_count = sum(
        1 for r in results if r.get("success")
    )

    print(
        f"Fix all: "
        f"{success_count}/{len(results)} successful"
    )

    return {
        "results": results,
        "total": len(results),
        "success_count": success_count
    }


# ── Start ──────────────────────────────────────────────
if __name__ == "__main__":

    print("\n" + "=" * 50)
    print("  AI Security Agent v2.0")
    print("  Browser will open automatically in 1.5s")
    print("  Or open manually: http://localhost:8001")
    print("=" * 50 + "\n")

    browser_thread = threading.Thread(
        target=open_browser
    )

    browser_thread.daemon = True
    browser_thread.start()

    # CHANGED: 8000 → 8001
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        log_level="info"
    )