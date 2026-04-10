# 🚨 Windows DFIR Triage Script v1.0

Lightweight PowerShell-based DFIR triage script for rapid incident response collection.

* **Author:** Alwin Espiritu (`alwinux`)
* **Date:** 2026-04-10

![License](https://img.shields.io/badge/license-MIT-green)

---

## ⚠️ Disclaimer

This tool is intended for **authorized digital forensic and incident response activities only**.
Unauthorized use may violate applicable laws and regulations.

---

## 🚀 Quick Start

```powershell
git clone https://github.com/n00b101/windows-dfir-triage.git
cd windows-dfir-triage
powershell -ExecutionPolicy Bypass -File .\dfir-triage.ps1
```

> 🔐 The script will automatically prompt for **Administrator privileges** if not already elevated.

---

## 📌 Features

* System information collection
* User and administrator enumeration
* Process listing and process tree
* Network artifacts:

  * netstat
  * ARP table
  * DNS cache
* Persistence checks:

  * Run keys
  * Services
  * Scheduled tasks
* WMI persistence detection
* Installed software inventory
* Full `C:\` file listing
* Optional osquery integration

---

## ⚙️ Requirements

* Windows 10 / 11 / Server
* PowerShell 5+ or 7
* Administrator privileges

**Optional:**

* osquery installed and added to PATH

---

## 📂 Output

The script generates a timestamped directory:

```
DFIR_Output_YYYY-MM-DD_HH-MM-SS
```

Each file includes:

* Command executed
* Timestamp
* Raw command output

---

## 📄 Collected Artifacts

### 🖥️ System Information

* `systeminfo.txt`
* `hostname.txt`
* `whoami_all.txt`
* `logical_disks.txt`

### 👤 User Enumeration

* `net_user.txt`
* `local_admins.txt`
* `query_user.txt`

### ⚙️ Process Collection

* `tasklist_verbose.txt`
* `process_tree.txt`

### 🌐 Network Information

* `netstat_ano.txt`
* `ipconfig_all.txt`
* `arp_table.txt`
* `route_table.txt`
* `dns_cache.txt`

### 🔐 Persistence Checks

* `scheduled_tasks.txt`
* `services.txt`
* `runkey_hklm.txt`
* `runkey_hkcu.txt`
* `startup_items.txt`

### 🧠 WMI Persistence

* `wmic_event_filters.txt`
* `wmic_event_consumers.txt`
* `wmic_bindings.txt`
* `wmi_event_filters_ps.txt`
* `wmi_event_consumers_ps.txt`
* `wmi_bindings_ps.txt`

### 📦 Installed Software

* `installed_software.txt`

### 📁 File System

* `file_listing_C.csv`

### 🧪 Optional (if osquery is installed)

* `osquery_processes.txt`
* `osquery_network.txt`

---

## ⚠️ Notes & Limitations

* Full `C:\` recursive listing may take significant time depending on disk size
* Output files can be large (especially file listings)
* Ensure sufficient disk space before execution
* Designed for **triage collection**, not full forensic imaging
* Some commands may require specific system permissions

---

## 🧠 Use Cases

* Incident Response (IR)
* Threat Hunting
* Live Response Collection
* Malware Investigations

---

## 🔍 Investigation Tips (DFIR Insight)

* Review `netstat_ano.txt` for suspicious outbound connections
* Correlate `process_tree.txt` with unusual parent-child relationships
* Inspect `runkey_*` and `scheduled_tasks.txt` for persistence
* Analyze WMI artifacts for stealth persistence mechanisms
* Check `dns_cache.txt` for recently resolved suspicious domains

---

## 📜 License

MIT License

---

## 🙌 Acknowledgements

Built for DFIR practitioners and security teams to accelerate live response and triage investigations.

---
