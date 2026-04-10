# 🚨 Windows DFIR Triage Script v1.1

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
git clone https://github.com/alwinuxlabs/windows-dfir-triage.git
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

  * netstat (including established connections)
  * ARP table
  * DNS cache
  * Hosts file
* Persistence checks:

  * Run keys
  * Services
  * Scheduled tasks
  * Startup folders
* WMI persistence detection
* Installed software inventory
* Event log collection (Security, System, PowerShell)
* PowerShell command history collection
* User activity (recent files)
* Environment variables collection
* Full `C:\` file listing
* Output hashing (SHA256)
* Automatic ZIP packaging of results
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

Additionally:

* 📦 A compressed archive (`.zip`) of the output is created
* 🔐 SHA256 hashes of collected files are generated for integrity

---

## 📄 Collected Artifacts

### 🖥️ System Information

* `systeminfo.txt`
* `hostname.txt`
* `whoami_all.txt`
* `logical_disks.txt`
* `env_variables.txt`

---

### 👤 User Enumeration

* `net_user.txt`
* `local_admins.txt`
* `query_user.txt`
* `logon_sessions.txt`

---

### ⚙️ Process Collection

* `tasklist_verbose.txt`
* `process_tree.txt`

---

### 🌐 Network Information

* `netstat_ano.txt`
* `netstat_established.txt`
* `ipconfig_all.txt`
* `arp_table.txt`
* `route_table.txt`
* `dns_cache.txt`
* `hosts_file.txt`

---

### 🔐 Persistence Checks

* `scheduled_tasks.txt`
* `services.txt`
* `runkey_hklm.txt`
* `runkey_hkcu.txt`
* `startup_items.txt`
* `startup_folder_allusers.txt`
* `startup_folder_currentuser.txt`

---

### 🧠 WMI Persistence

* `wmic_event_filters.txt`
* `wmic_event_consumers.txt`
* `wmic_bindings.txt`
* `wmi_event_filters_ps.txt`
* `wmi_event_consumers_ps.txt`
* `wmi_bindings_ps.txt`

---

### 📜 Event Logs

* `eventlog_security.txt`
* `eventlog_system.txt`
* `eventlog_powershell_operational.txt`

---

### 🧪 User Activity

* `powershell_history.txt`
* `recent_files.txt`

---

### 📦 Installed Software

* `installed_software.txt`

---

### 📁 File System

* `file_listing_C.csv`
  *(Includes: FullName, Length, CreationTime, LastWriteTime, LastAccessTime)*

---

### 🔐 Integrity

* `hashes.txt` (SHA256 hashes of collected files)

---

### 📦 Archive

* `DFIR_Output_YYYY-MM-DD_HH-MM-SS.zip`

---

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
* Event logs are limited to recent entries for performance

---

## 🧠 Use Cases

* Incident Response (IR)
* Threat Hunting
* Live Response Collection
* Malware Investigations

---

## 🔍 Investigation Tips (DFIR Insight)

* Review `netstat_established.txt` for suspicious outbound connections
* Correlate `process_tree.txt` with unusual parent-child relationships
* Inspect `runkey_*`, `startup_*`, and `scheduled_tasks.txt` for persistence
* Analyze WMI artifacts for stealth persistence mechanisms
* Check `dns_cache.txt` and `hosts_file.txt` for suspicious domains
* Review `powershell_history.txt` for attacker commands
* Investigate `eventlog_security.txt` for login activity

---

## 📜 License

MIT License

---

## 🙌 Acknowledgements

Built for DFIR practitioners and security teams to accelerate live response and triage investigations.

---
