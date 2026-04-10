# windows-dfir-triage v1.0
Lightweight Windows DFIR triage script for rapid incident response collection
#Author: alwinux | Alwin Espiritu | 2026-04-10
## ⚠️ Disclaimer
This tool is intended for authorized security testing and incident response only.

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
- PowerShell 5+ or 7
- Administrator privileges

Optional:
- osquery installed and in PATH

---

## 🚀 How to Use

1. Download the script:
   ```powershell
   git clone https://github.com/n00b101/windows-dfir-triage.git
2. Navigate to the folder:
   ```powershell
   cd windows-dfir-triage
3. Run the script as Administrator:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\dfir-triage.ps1

📂 Output
The script will generate a timestamped folder:
DFIR_Output_YYYY-MM-DD_HH-MM-SS

Inside:

systeminfo.txt
netstat_ano.txt
process_tree.txt
file_listing_C.csv

⚠️ Notes
The C:\ full file listing may take time
Ensure sufficient disk space
Designed for triage, not full forensic imaging

🧠 Use Cases
Incident Response (IR)
Threat Hunting
Live Response Collection
Malware Investigations


