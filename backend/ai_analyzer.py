# ai_analyzer.py — Uses Groq AI
# UPDATED: Smarter threat-specific analysis + instant updates on new threats

import json
import os
import hashlib
from dotenv import load_dotenv
from groq import Groq

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

API_KEY = os.getenv("GROQ_API_KEY")
if not API_KEY:
    print("❌ ERROR: GROQ_API_KEY not found in .env file!")
else:
    print(f"✅ Groq API key loaded: {API_KEY[:10]}...")

client = Groq(api_key=API_KEY)

# Remember last threat fingerprint so we only call AI when threats CHANGE
_last_threat_hash = None


def _build_threat_summary(scan_results: dict):
    """
    Collects all threats from all scanners and returns:
    - danger_count, warning_count
    - categorized threat details
    - a hash to detect if threats changed
    """
    danger_count  = 0
    warning_count = 0

    # Separate buckets per threat type
    port_threats     = []
    process_threats  = []
    network_threats  = []
    file_threats     = []
    usb_threats      = []

    # ── Ports ──────────────────────────────────────────
    for port in scan_results.get("open_ports", []):
        if port["threat_level"] == "danger":
            danger_count += 1
            port_threats.append(f"DANGER — Port {port['port']} ({port['service']}): {port['description']}")
        elif port["threat_level"] == "warning":
            warning_count += 1
            port_threats.append(f"WARNING — Port {port['port']} ({port['service']}): {port['description']}")

    # ── Processes ──────────────────────────────────────
    for proc in scan_results.get("processes", []):
        if proc["threat_level"] == "danger":
            danger_count += 1
            process_threats.append(f"DANGER — Process '{proc['name']}': {', '.join(proc.get('threat_reasons', []))}")
        elif proc["threat_level"] == "warning":
            warning_count += 1
            process_threats.append(f"WARNING — Process '{proc['name']}': {', '.join(proc.get('threat_reasons', []))}")

    # ── Network ────────────────────────────────────────
    for conn in scan_results.get("connections", []):
        if conn["threat_level"] == "danger":
            danger_count += 1
            network_threats.append(f"DANGER — {conn['process']} connecting to port {conn['remote_port']}: {conn.get('threat_reason','')}")
        elif conn["threat_level"] == "warning":
            warning_count += 1
            network_threats.append(f"WARNING — {conn['process']}: {conn.get('threat_reason','')}")

    # ── Files ──────────────────────────────────────────
    for alert in scan_results.get("filesystem_alerts", []):
        fname = os.path.basename(alert.get("file", "unknown"))
        if alert["threat_level"] == "danger":
            danger_count += 1
            file_threats.append(f"DANGER — File '{fname}': {alert.get('threat_reason','')}")
        elif alert["threat_level"] == "warning":
            warning_count += 1
            file_threats.append(f"WARNING — File '{fname}': {alert.get('threat_reason','')}")

    # ── USB ────────────────────────────────────────────
    for alert in scan_results.get("usb_alerts", []):
        warning_count += 1
        usb_threats.append(f"WARNING — USB: {alert.get('message','')}")

    # Build fingerprint hash — changes only when threats change
    all_threats = port_threats + process_threats + network_threats + file_threats + usb_threats
    threat_hash = hashlib.md5(
        json.dumps(sorted(all_threats)).encode()
    ).hexdigest()

    return {
        "danger_count":    danger_count,
        "warning_count":   warning_count,
        "port_threats":    port_threats,
        "process_threats": process_threats,
        "network_threats": network_threats,
        "file_threats":    file_threats,
        "usb_threats":     usb_threats,
        "all_threats":     all_threats,
        "threat_hash":     threat_hash,
    }


def analyze_threats_with_ai(scan_results: dict) -> dict:
    """
    Analyzes scan results and returns plain-English explanation.
    Only calls AI when threats actually CHANGE — saves API quota.
    """
    global _last_threat_hash

    summary = _build_threat_summary(scan_results)
    danger_count  = summary["danger_count"]
    warning_count = summary["warning_count"]
    threat_hash   = summary["threat_hash"]

    # ── No threats ─────────────────────────────────────
    if danger_count == 0 and warning_count == 0:
        _last_threat_hash = threat_hash
        return {
            "overall_status":   "safe",
            "danger_count":     0,
            "warning_count":    0,
            "simple_explanation": "✅ Your computer looks completely safe right now!",
            "what_is_happening":  "All programs, files, and network connections on your computer appear normal. No suspicious activity detected.",
            "what_to_do":         "1. Keep your antivirus updated\n2. Avoid clicking suspicious links\n3. You're good for now!",
            "technical_summary":  "No threats detected in current scan.",
            "priority_actions":   []
        }

    # ── Threats unchanged — return cached result ───────
    if threat_hash == _last_threat_hash:
        return None  # Signal to main.py to use cached AI result

    # ── Threats changed — call AI ──────────────────────
    _last_threat_hash = threat_hash

    # Build a detailed prompt with categorized threats
    sections = []
    if summary["file_threats"]:
        sections.append("SUSPICIOUS FILES FOUND:\n" + "\n".join(f"  • {t}" for t in summary["file_threats"]))
    if summary["port_threats"]:
        sections.append("DANGEROUS OPEN PORTS:\n" + "\n".join(f"  • {t}" for t in summary["port_threats"]))
    if summary["process_threats"]:
        sections.append("SUSPICIOUS PROCESSES RUNNING:\n" + "\n".join(f"  • {t}" for t in summary["process_threats"]))
    if summary["network_threats"]:
        sections.append("SUSPICIOUS NETWORK ACTIVITY:\n" + "\n".join(f"  • {t}" for t in summary["network_threats"]))
    if summary["usb_threats"]:
        sections.append("USB DEVICE ALERTS:\n" + "\n".join(f"  • {t}" for t in summary["usb_threats"]))

    threat_text = "\n\n".join(sections)

    prompt = f"""You are a friendly cybersecurity expert explaining computer threats to someone with ZERO technical knowledge.
Be specific about WHAT was found — mention the actual file names, port numbers, and process names.
Use simple everyday analogies. Be calm but clear about urgency.

WHAT WAS FOUND ON THIS COMPUTER:
{threat_text}

COUNTS: {danger_count} critical threats, {warning_count} warnings

Respond ONLY with a valid JSON object, no markdown:
{{
  "overall_status": "danger" or "warning" or "safe",
  "simple_explanation": "1 sentence summary for a grandparent. Mention what specific things were found.",
  "what_is_happening": "3-4 sentences. Explain what each type of threat means using everyday analogies. Be specific about what was found (mention file names, port numbers). Example: 'A file called keylogger.bat was found in your Downloads folder - this is like finding a suspicious note hidden in your house.'",
  "what_to_do": "1. First specific action\\n2. Second specific action\\n3. Third specific action\\n4. Fourth action if needed",
  "technical_summary": "1-2 sentences for technical users summarizing findings",
  "priority_actions": ["most urgent action", "second action", "third action"],
  "danger_count": {danger_count},
  "warning_count": {warning_count}
}}"""

    try:
        print("Calling Groq API — threats changed, getting fresh analysis...")
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Always respond with valid JSON only. No markdown formatting."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )
        response_text = response.choices[0].message.content.strip()
        print("✅ Groq response received!")

        # Clean markdown if present
        if "```" in response_text:
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        response_text = response_text.strip()

        result = json.loads(response_text)
        return result

    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}")
        # Build a meaningful fallback based on what was found
        what = []
        if summary["file_threats"]:   what.append(f"{len(summary['file_threats'])} suspicious file(s)")
        if summary["port_threats"]:   what.append(f"{len(summary['port_threats'])} dangerous port(s)")
        if summary["process_threats"]:what.append(f"{len(summary['process_threats'])} suspicious process(es)")

        return {
            "overall_status":   "danger" if danger_count > 0 else "warning",
            "danger_count":     danger_count,
            "warning_count":    warning_count,
            "simple_explanation": f"Found {', '.join(what)} on your computer.",
            "what_is_happening":  "\n".join(summary["all_threats"][:5]),
            "what_to_do":         "1. Click Fix Threats button\n2. Select all threats\n3. Click Fix Selected\n4. Run antivirus scan",
            "technical_summary":  "\n".join(summary["all_threats"]),
            "priority_actions":   ["Fix detected threats", "Run antivirus", "Restart computer"]
        }

    except Exception as e:
        print(f"Groq AI error: {e}")
        return {
            "overall_status":   "danger" if danger_count > 0 else "warning",
            "danger_count":     danger_count,
            "warning_count":    warning_count,
            "simple_explanation": f"{danger_count} critical threats and {warning_count} warnings detected.",
            "what_is_happening":  "Threats detected. Click Fix Threats button to resolve them.",
            "what_to_do":         "1. Click Fix Threats button\n2. Select threats to fix\n3. Click Fix Selected",
            "technical_summary":  str(e),
            "priority_actions":   ["Fix threats now", "Run antivirus scan"]
        }