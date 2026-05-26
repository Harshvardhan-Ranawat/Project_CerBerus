<div align="center">

```
 ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝
██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗
██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║
╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║
 ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

### *Three heads. Three threat vectors. Always watching.*

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Watchdog](https://img.shields.io/badge/Watchdog-File%20Monitor-orange?style=flat)](https://pypi.org/project/watchdog/)
[![Telegram](https://img.shields.io/badge/Alerts-Telegram%20Bot-26A5E4?style=flat&logo=telegram&logoColor=white)](https://core.telegram.org/bots)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)]()

</div>

---

## What is Cerberus?

In Greek mythology, **Cerberus** is the three-headed dog that guards the gates of the underworld — letting nothing unauthorized pass.

**Project Cerberus** is a honey file-based **Intrusion Detection System** built on Python's `Watchdog` library. Just as the mythological Cerberus watches three realms, this system guards three threat vectors simultaneously:

| Head | Threat Vector | What It Catches |
|------|--------------|-----------------|
| 🐺 **Head 1** | File System Events | Unauthorized access, rename, deletion, copy, move of honey files |
| 🐺 **Head 2** | Network Intrusion | Remote attackers on the network attempting to access files from another machine |
| 🐺 **Head 3** | Insider Threat | Internal users attempting to copy sensitive files to USB / pendrive |

Cerberus runs **silently in the background** with zero performance impact — invisible to the attacker, always watching.

---

## Features

- 🍯 **Honey File Deployment** — Places decoy files that look like real sensitive documents across the system
- 👁️ **Real-Time File Monitoring** — Detects every interaction: `access`, `rename`, `delete`, `copy`, `move`
- 📊 **Risk-Scored Logging** — Every event is assigned a risk level (Low / Medium / Critical) and logged to a dashboard
- 🌐 **Network Intrusion Detection** — Catches attackers attempting to access honey files remotely from other machines on the network
- 🔌 **Insider Threat Detection** — Identifies users trying to exfiltrate files to external USB / pendrive storage
- 📲 **Real-Time Telegram Alerts** — Critical-level threats are instantly pushed to the admin via Telegram bot
- 🤫 **Zero Footprint** — Runs silently as a background process with no impact on system performance
- 📋 **Audit Dashboard** — All events are logged and displayed on a structured monitoring dashboard

---

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                        CERBERUS IDS                         │
│                                                             │
│   Honey Files                                               │
│   (Decoys)  ──▶  Watchdog Listener  ──▶  Event Classifier  │
│                        │                       │            │
│                        │              ┌─────────────────┐  │
│                        │              │   Risk Scoring  │  │
│                        │              │  LOW / MEDIUM / │  │
│                        │              │    CRITICAL     │  │
│                        │              └────────┬────────┘  │
│                        │                       │            │
│                   ┌────▼────┐         ┌────────▼────────┐  │
│                   │  Logs   │         │    Dashboard    │  │
│                   │ (Audit) │         │  (Monitoring)   │  │
│                   └─────────┘         └────────┬────────┘  │
│                                                │            │
│                                     ┌──────────▼─────────┐ │
│                                     │   Telegram Bot     │ │
│                                     │  (Critical Alerts) │ │
│                                     └────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Event Flow

1. Honey files are deployed across target directories
2. Watchdog listeners monitor every filesystem event on those files
3. Each event is classified and risk-scored
4. All events are logged to the audit trail and displayed on the dashboard
5. **Critical events** (e.g. file copied to external device, remote access detected) trigger an instant Telegram alert to the admin

---

## Risk Levels

| Level | Color | Trigger Examples |
|-------|-------|-----------------|
| 🟢 **LOW** | Green | File accessed locally by known process |
| 🟡 **MEDIUM** | Yellow | File renamed or moved within system |
| 🔴 **CRITICAL** | Red | File copied to USB · Remote access from network · File deleted |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Core Language | Python 3.8+ |
| File Monitoring | [Watchdog](https://pypi.org/project/watchdog/) |
| Alert Delivery | Telegram Bot API |
| Logging | Python `logging` module |
| Dashboard | Python (custom logging/display layer) |

---

## Installation

### Prerequisites

- Python 3.8 or higher
- A Telegram Bot Token ([create one via @BotFather](https://t.me/botfather))
- Your Telegram Chat ID

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/Harshvardhan-Ranawat/Project_CerBerus.git
cd Project_CerBerus

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure your settings
cp config.example.py config.py
# Edit config.py with your Telegram Bot Token, Chat ID, and honey file paths

# 4. Run Cerberus
python cerberus.py
```

### Configuration

Edit `config.py` with your settings:

```python
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = "your_bot_token_here"
TELEGRAM_CHAT_ID   = "your_chat_id_here"

# Honey File Paths to Monitor
HONEY_FILE_PATHS = [
    "/path/to/decoy/confidential_report.pdf",
    "/path/to/decoy/passwords.txt",
    "/path/to/decoy/financial_data.xlsx",
]

# Risk Thresholds
CRITICAL_EVENTS = ["deleted", "copied_to_usb", "remote_access"]
MEDIUM_EVENTS   = ["renamed", "moved"]
LOW_EVENTS      = ["accessed"]
```

---

## Telegram Alert Example

When a critical event is detected, the admin receives an instant Telegram message:

```
🚨 CERBERUS ALERT — CRITICAL

Event     : File copied to external device
File      : confidential_report.pdf
User      : DESKTOP-XYZ\john
Device    : USB Drive (E:\)
Timestamp : 2026-05-26 14:32:07
Risk Level: CRITICAL

⚠️ Immediate action recommended.
```

---

## Use Cases

- **Enterprise Networks** — Deploy honey files on shared drives to detect lateral movement by attackers
- **Insider Threat Programs** — Monitor sensitive directories for unauthorized exfiltration to external devices
- **Incident Response** — Use audit logs as forensic evidence to reconstruct attacker timelines
- **SOC Environments** — Integrate alert logs with SIEM tools for centralized threat monitoring
- **Home Labs** — Practice threat detection and honey file strategies in a controlled environment

---

## Dashboard Preview

### Mission Control
![Cerberus Mission Control Dashboard](screenshots/dashboard_mission_control.png)

The **Mission Control** panel gives a real-time overview of all threat activity:
- **Total Hits** — all honey file interaction events detected
- **Critical Alerts** — high-risk events requiring immediate action
- **Remote Attackers** — unique source IPs attempting network-level access
- **Breached Files** — honey files that have been interacted with
- **Threat Timeline** — risk-scored events plotted over time by severity (CRITICAL / HIGH / LOW)
- **Top Sources** — most active attacker IPs ranked by hit count
- **Targeted Files** — distribution of which honey files are being attacked most

### Forensic Log Explorer
![Cerberus Forensic Log Explorer](screenshots/dashboard_log_explorer.png)

The **Forensic Log Explorer** provides a full filterable audit trail of every event:
- Filter by severity: `CRITICAL` · `HIGH` · `LOW`
- Filter by specific honey file (passwords.txt, private_keys.pem, merger_plans.pptx, payroll_2025.xlsx, etc.)
- Every log entry captures: Timestamp · Severity · Target File · Action · Source IP · User · Risk Score
- Actions tracked: `OPENED` · `COPIED` · `RENAMED` · `DELETED` · `CLOSED`

---

## Project Structure

```
Project_CerBerus/
│
├── cerberus.py          # Main entry point
├── monitor.py           # Watchdog event handlers and listeners
├── classifier.py        # Risk scoring and event classification
├── alerts.py            # Telegram bot alert dispatcher
├── dashboard.py         # Logging and dashboard display
├── config.py            # Configuration (tokens, paths, thresholds)
├── requirements.txt     # Dependencies
└── README.md
```

---

## Why "Cerberus"?

The name isn't just aesthetic. The `Watchdog` library — which powers the entire file monitoring engine — is itself named after a watchdog process. Cerberus takes that concept further: just as the mythological three-headed dog simultaneously watches three gates of the underworld, this system simultaneously guards three threat vectors — filesystem events, network intrusions, and insider exfiltration — from a single silent process.

---

## Author

**Harshvardhan Ranawat**
MSc Cybersecurity — National Forensic Sciences University (NFSU)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/your-linkedin-here)
[![GitHub](https://img.shields.io/badge/GitHub-Harshvardhan--Ranawat-181717?style=flat&logo=github&logoColor=white)](https://github.com/Harshvardhan-Ranawat)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-115%2B%20Day%20Streak-212C42?style=flat&logo=tryhackme&logoColor=white)](https://tryhackme.com/p/your-username-here)

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*"Not all guards stand at the door. Some watch from the shadows."*

⭐ Star this repo if Cerberus helped you think about file-based threat detection differently.

</div>
