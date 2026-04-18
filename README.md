# Deception-Based Security Mechanism (Honeypot System)

A **GUI-based multi-layer honeypot system** designed to detect, log, and analyze suspicious or malicious activities using deception techniques.

---

## Overview

This project simulates a **real-world cybersecurity defense system** using deception. Instead of blocking attackers directly, it **traps, monitors, and analyzes** their behavior.

The system includes:

* Fake login interface (honeypot)
* Dummy API server
* Honey file monitoring
* Real-time alert dashboard
* Threat intelligence engine (IP tracking & attack detection)

---

## Key Features

* **Honeypot Login**

  * Detects typing, focus, and login attempts
  * Logs all interactions as suspicious

* **Dummy API Endpoint**

  * Simulates a backend server
  * Captures GET/POST requests and payloads

* **Honey File Monitoring**

  * Tracks file access (simulated)
  * Detects file modifications (real)

* **Alert Dashboard**

  * Real-time alert display
  * Severity classification (LOW → CRITICAL)
  * Export logs to JSON

* **Threat Intelligence Engine**

  * Tracks IP behavior
  * Detects brute-force attacks
  * Identifies repeat attackers
  * Simulates IP blocking

---

## System Architecture

```
User Interaction
       ↓
Deception Layer (Login / API / File)
       ↓
Alert Generation
       ↓
Threat Intelligence Engine
       ↓
GUI Dashboard (Monitoring & Logs)
```

---

## Technologies Used

* **Python**
* **Tkinter** (GUI)
* **Threading** (background tasks)
* **HTTP Server** (dummy API)
* **JSON** (log export)
* **File Handling** (monitoring)

---

## How to Run

1. Clone the repository:

```bash
git clone https://github.com/your-username/honeypot-security-system.git
cd honeypot-security-system
```

2. Run the application:

```bash
python app.py
```

3. Open the GUI and interact with:

* Login tab (enter credentials)
* API tab (simulate requests)
* Honey file tab (simulate access)

---

## Testing the Dummy API

You can test using curl:

```bash
curl http://127.0.0.1:8765/admin
```

---

## Threat Detection Logic

* ≥ 3 attempts → Warning (possible brute-force)
* ≥ 5 attempts → Critical + IP Blocked
* Repeated actions → Repeat attacker detected

---

## 📁 Project Structure

```
├── app.py
├── honey_document_CONFIDENTIAL.txt
├── logs / alerts (generated)
└── README.md
```

---

## Limitations

* IP blocking is simulated (not enforced at OS level)
* Honey file read detection is partially simulated
* Runs locally (not deployed on network)

---

## Future Improvements

* Real firewall-based IP blocking
* Email/SMS alerts
* Cloud deployment
* SIEM integration
* Machine learning for attack prediction

---

## Interview Explanation

> This project is a deception-based honeypot system that simulates attack surfaces like login portals, APIs, and sensitive files. It detects malicious interactions, logs them, and analyzes attacker behavior using a threat intelligence engine, similar to real SOC systems.

---

## Why This Project?

* Demonstrates **cybersecurity concepts**
* Shows **practical implementation**
* Includes **GUI + backend + threat analysis**
* Suitable for **internships and interviews**

---

## License

This project is for educational purposes.

---

## Final Note

This is not just a basic project — it simulates a **mini Security Operations Center (SOC)** using deception-based techniques.

---
