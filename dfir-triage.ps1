# =====================
# GSO Forensics Windows DFIR Triage version 1.1
# =====================
# Author: Alwin Espiritu
# Description: Lightweight Windows DFIR triage script for rapid incident response collection

$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

Write-Host "=============================================="
Write-Host "GSO Forensics Windows DFIR Triage version 1.1"
Write-Host "=============================================="

# ----------------------
# 1. Check Admin Privileges
# ----------------------
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Not running as Administrator. Relaunching..." -ForegroundColor Red
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ----------------------
# 2. Output Folder
# ----------------------
$ScriptDir = Split-Path -Parent $PSCommandPath
$folderTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutputDir = Join-Path $ScriptDir "DFIR_Output_$folderTimestamp"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Host "[*] IR Collection started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

# ----------------------
# 3. Command Runner
# ----------------------
function RunCmd {
    param(
        [string]$name,
        [string]$cmd
    )

    $outfile = Join-Path $OutputDir "$name.txt"

    Write-Host "[*] Processing: $name" -ForegroundColor Yellow

    "=========================================" | Out-File $outfile
    "Command: $cmd" | Out-File $outfile -Append
    "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File $outfile -Append
    "=========================================" | Out-File $outfile -Append

    try {
        cmd.exe /c $cmd 2>&1 | Out-File $outfile -Append
        Write-Host "[+] Completed: $name" -ForegroundColor Green
    }
    catch {
        "Command failed: $_" | Out-File $outfile -Append
        Write-Host "[!] Failed: $name" -ForegroundColor Red
    }
}

# ----------------------
# 4. SYSTEM INFORMATION
# ----------------------
RunCmd "systeminfo" "systeminfo"
RunCmd "hostname" "hostname"
RunCmd "whoami_all" "whoami /all"
RunCmd "logical_disks" "wmic logicaldisk get name,freespace,size"
RunCmd "env_variables" "set"

# ----------------------
# 5. USER ENUMERATION
# ----------------------
RunCmd "net_user" "net user"
RunCmd "local_admins" "net localgroup administrators"
RunCmd "query_user" "query user"
RunCmd "logon_sessions" "quser"

# ----------------------
# 6. PROCESS COLLECTION
# ----------------------
RunCmd "tasklist_verbose" "tasklist /v"

Write-Host "[*] Processing: process_tree" -ForegroundColor Yellow
try {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine |
        Format-Table -AutoSize |
        Out-File (Join-Path $OutputDir "process_tree.txt")
    Write-Host "[+] Completed: process_tree" -ForegroundColor Green
}
catch {
    "Failed to collect process tree: $_" | Out-File (Join-Path $OutputDir "process_tree.txt")
    Write-Host "[!] Failed: process_tree" -ForegroundColor Red
}

# ----------------------
# 7. NETWORK INFORMATION
# ----------------------
RunCmd "netstat_ano" "netstat -ano"
RunCmd "netstat_established" "netstat -ano | findstr ESTABLISHED"
RunCmd "ipconfig_all" "ipconfig /all"
RunCmd "arp_table" "arp -a"
RunCmd "route_table" "route print"
RunCmd "dns_cache" "ipconfig /displaydns"
RunCmd "hosts_file" "type C:\Windows\System32\drivers\etc\hosts"

# ----------------------
# 8. PERSISTENCE CHECKS
# ----------------------
RunCmd "scheduled_tasks" "schtasks /query /fo LIST /v"
RunCmd "services" "sc query"
RunCmd "runkey_hklm" "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
RunCmd "runkey_hkcu" "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
RunCmd "startup_folder_allusers" "dir C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
RunCmd "startup_folder_currentuser" "dir %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

Write-Host "[*] Processing: startup_items" -ForegroundColor Yellow
try {
    Get-CimInstance Win32_StartupCommand |
        Format-Table Name, Command, Location -AutoSize |
        Out-File (Join-Path $OutputDir "startup_items.txt")
    Write-Host "[+] Completed: startup_items" -ForegroundColor Green
}
catch {
    "Failed to collect startup items: $_" | Out-File (Join-Path $OutputDir "startup_items.txt")
    Write-Host "[!] Failed: startup_items" -ForegroundColor Red
}

# ----------------------
# 8B. WMI PERSISTENCE
# ----------------------
RunCmd "wmic_event_filters" "wmic /namespace:\\root\subscription PATH __EventFilter get Name,Query,EventNamespace,CreatorSID"
RunCmd "wmic_event_consumers" "wmic /namespace:\\root\subscription PATH CommandLineEventConsumer get Name,CommandLineTemplate"
RunCmd "wmic_bindings" "wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding get Filter,Consumer"

Write-Host "[*] Processing: wmi_event_filters_ps" -ForegroundColor Yellow
try {
    Get-WmiObject -Namespace root\subscription -Class __EventFilter |
        Select-Object Name, Query, EventNamespace |
        Format-Table -AutoSize |
        Out-File (Join-Path $OutputDir "wmi_event_filters_ps.txt")
    Write-Host "[+] Completed: wmi_event_filters_ps" -ForegroundColor Green
}
catch {
    "Failed to collect WMI event filters: $_" | Out-File (Join-Path $OutputDir "wmi_event_filters_ps.txt")
    Write-Host "[!] Failed: wmi_event_filters_ps" -ForegroundColor Red
}

Write-Host "[*] Processing: wmi_event_consumers_ps" -ForegroundColor Yellow
try {
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
        Select-Object Name, CommandLineTemplate |
        Format-Table -AutoSize |
        Out-File (Join-Path $OutputDir "wmi_event_consumers_ps.txt")
    Write-Host "[+] Completed: wmi_event_consumers_ps" -ForegroundColor Green
}
catch {
    "Failed to collect WMI event consumers: $_" | Out-File (Join-Path $OutputDir "wmi_event_consumers_ps.txt")
    Write-Host "[!] Failed: wmi_event_consumers_ps" -ForegroundColor Red
}

Write-Host "[*] Processing: wmi_bindings_ps" -ForegroundColor Yellow
try {
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
        Select-Object Filter, Consumer |
        Format-Table -AutoSize |
        Out-File (Join-Path $OutputDir "wmi_bindings_ps.txt")
    Write-Host "[+] Completed: wmi_bindings_ps" -ForegroundColor Green
}
catch {
    "Failed to collect WMI bindings: $_" | Out-File (Join-Path $OutputDir "wmi_bindings_ps.txt")
    Write-Host "[!] Failed: wmi_bindings_ps" -ForegroundColor Red
}

# ----------------------
# 9. INSTALLED SOFTWARE
# ----------------------
Write-Host "[*] Processing: installed_software" -ForegroundColor Yellow
try {
    Get-Package |
        Format-Table Name, Version -AutoSize |
        Out-File (Join-Path $OutputDir "installed_software.txt")
    Write-Host "[+] Completed: installed_software" -ForegroundColor Green
}
catch {
    "Failed to collect installed software: $_" | Out-File (Join-Path $OutputDir "installed_software.txt")
    Write-Host "[!] Failed: installed_software" -ForegroundColor Red
}

# ----------------------
# 10. USER ACTIVITY
# ----------------------
RunCmd "powershell_history" "type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
RunCmd "recent_files" "dir %APPDATA%\Microsoft\Windows\Recent"

# ----------------------
# 11. EVENT LOGS
# ----------------------
RunCmd "eventlog_security" "wevtutil qe Security /c:200 /f:text"
RunCmd "eventlog_system" "wevtutil qe System /c:200 /f:text"
RunCmd "eventlog_powershell_operational" "wevtutil qe Microsoft-Windows-PowerShell/Operational /c:200 /f:text"

# ----------------------
# 12. FULL C: DRIVE LISTING
# ----------------------
Write-Host "[*] Processing: file_listing_C (this may take a while...)" -ForegroundColor Yellow
try {
    Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime |
        Export-Csv (Join-Path $OutputDir "file_listing_C.csv") -NoTypeInformation -Encoding utf8

    Write-Host "[+] Completed: file_listing_C" -ForegroundColor Green
}
catch {
    "Failed to list C:\ drive: $_" | Out-File (Join-Path $OutputDir "file_listing_C.csv")
    Write-Host "[!] Failed: file_listing_C" -ForegroundColor Red
}

# ----------------------
# 13. OPTIONAL OSQUERY
# ----------------------
if (Get-Command osqueryi -ErrorAction SilentlyContinue) {

    Write-Host "[*] Processing: osquery_processes" -ForegroundColor Yellow
    try {
        osqueryi "SELECT pid,name,path,cmdline,parent FROM processes;" |
            Out-File (Join-Path $OutputDir "osquery_processes.txt")
        Write-Host "[+] Completed: osquery_processes" -ForegroundColor Green
    }
    catch {
        "Failed to collect osquery processes: $_" | Out-File (Join-Path $OutputDir "osquery_processes.txt")
        Write-Host "[!] Failed: osquery_processes" -ForegroundColor Red
    }

    Write-Host "[*] Processing: osquery_network" -ForegroundColor Yellow
    try {
        osqueryi "SELECT pid,local_address,local_port,remote_address,remote_port FROM process_open_sockets;" |
            Out-File (Join-Path $OutputDir "osquery_network.txt")
        Write-Host "[+] Completed: osquery_network" -ForegroundColor Green
    }
    catch {
        "Failed to collect osquery network data: $_" | Out-File (Join-Path $OutputDir "osquery_network.txt")
        Write-Host "[!] Failed: osquery_network" -ForegroundColor Red
    }
}

# ----------------------
# 14. HASH OUTPUT FILES
# ----------------------
Write-Host "[*] Processing: hashes" -ForegroundColor Yellow
try {
    Get-ChildItem $OutputDir -File |
        Get-FileHash -Algorithm SHA256 |
        Select-Object Path, Algorithm, Hash |
        Format-Table -AutoSize |
        Out-File (Join-Path $OutputDir "hashes.txt")
    Write-Host "[+] Completed: hashes" -ForegroundColor Green
}
catch {
    "Failed to hash output files: $_" | Out-File (Join-Path $OutputDir "hashes.txt")
    Write-Host "[!] Failed: hashes" -ForegroundColor Red
}

# ----------------------
# 15. ZIP OUTPUT
# ----------------------
Write-Host "[*] Processing: zip_archive" -ForegroundColor Yellow
try {
    $zipFile = "$OutputDir.zip"
    if (Test-Path $zipFile) {
        Remove-Item $zipFile -Force
    }
    Compress-Archive -Path $OutputDir -DestinationPath $zipFile -Force
    Write-Host "[+] Completed: zip_archive" -ForegroundColor Green
}
catch {
    "Failed to create zip archive: $_" | Out-File (Join-Path $OutputDir "zip_archive_error.txt")
    Write-Host "[!] Failed: zip_archive" -ForegroundColor Red
}

# ----------------------
# 16. COMPLETE
# ----------------------
Write-Host ""
Write-Host "[+] IR Collection Complete at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "[+] Results saved to:" -ForegroundColor Cyan
Write-Host $OutputDir
Write-Host "[+] Archive saved to:" -ForegroundColor Cyan
Write-Host "$OutputDir.zip"
