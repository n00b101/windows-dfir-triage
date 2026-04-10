# windows-dfir-triage v1.0
Lightweight Windows DFIR triage script for rapid incident response collection
#Author: Alwin Espiritu | alwinux

# 🚨 Windows DFIR Triage Script

Lightweight PowerShell-based DFIR triage script for rapid incident response collection.

## 📌 Features

- System information collection
- User and admin enumeration
- Process listing and process tree
- Network artifacts (netstat, ARP, DNS cache)
- Persistence checks (Run keys, services, scheduled tasks)
- WMI persistence detection
- Installed software inventory
- Full C:\ file listing
- Optional osquery integration

---

## ⚙️ Requirements

- Windows 10 / 11 / Server
- PowerShell 5+
- Administrator privileges

Optional:
- osquery installed and in PATH

---

## 🚀 How to Use

1. Download the script:
   ```powershell
   git clone https://github.com/n00b101/windows-dfir-triage.git
