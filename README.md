# 🛡️ AI-Driven Security Operations Center (SOC)

An AI-driven Security Operations Center (SOC) system designed to detect, analyze, and respond to potential security threats across a system.

The project combines automated security scanning with AI-based threat analysis and automated remediation to provide a centralized approach to security monitoring.

---

## 📌 Overview

Traditional security monitoring often requires analysts to manually inspect multiple types of security events.

This project aims to automate important parts of the SOC workflow by:

- Scanning the system for potential security threats
- Monitoring network activity
- Detecting suspicious processes
- Checking open ports
- Monitoring connected USB devices
- Scanning the filesystem
- Using AI-based analysis for detected threats
- Providing automated remediation capabilities

The goal is to reduce manual effort and help security analysts identify and respond to threats more efficiently.

---

## 🚀 Key Features

### 🔍 Multi-Layer Security Scanning

The system includes multiple security scanners:

- **Filesystem Scanner** – Identifies potentially suspicious files and filesystem activity.
- **Network Scanner** – Analyzes network-related activity.
- **Port Scanner** – Detects open and potentially exposed ports.
- **Process Scanner** – Monitors running processes for suspicious activity.
- **USB Scanner** – Detects connected USB devices and related activity.

### 🤖 AI-Based Threat Analysis

The project includes an AI analysis component that can evaluate detected security events and assist in identifying potentially malicious or suspicious behavior.

### 🔧 Automated Remediation

The `auto_fixer.py` module provides automated response/remediation capabilities for supported security issues.

### 🧪 Threat Simulation

The project includes `demo_threats.py` for demonstrating and testing the system against simulated security scenarios.

---

## 🏗️ Project Architecture

```text
                    ┌─────────────────────┐
                    │      Frontend       │
                    │     index.html      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Python Backend   │
                    │       main.py       │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   ┌─────────────┐      ┌─────────────┐     ┌─────────────┐
   │   Security  │      │ AI Analyzer │     │ Auto Fixer  │
   │   Scanners  │      │             │     │             │
   └──────┬──────┘      └─────────────┘     └─────────────┘
          │
    ┌─────┼─────┬──────────┬──────────┐
    ▼     ▼     ▼          ▼          ▼
 Filesystem Network       Ports    Processes     USB

