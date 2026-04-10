# ==============================================
# GSO Forensics Windows DFIR Triage version 1.0
# Author: alwinux | Alwin Espiritu | 2026-0410
# ==============================================
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

Write-Host "======================="
Write-Host "DFIR Triage version 1.0"
Write-Host "======================="

# ----------------------
# 1. Check Admin Privileges
# ----------------------
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-NOT $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Not running as Administrator. Relaunching..." -ForegroundColor Red
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ----------------------
# 2. Output Folder
# ----------------------
$ScriptDir = Split-Path -Parent $PSCommandPath
$folderTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutputDir = "$ScriptDir\DFIR_Output_$folderTimestamp"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Host "[*] IR Collection started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

# ----------------------
# 3. Command Runner
# ----------------------
function RunCmd($name, $cmd){

    $outfile = "$OutputDir\$name.txt"

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
        "Command failed" | Out-File $outfile -Append
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

# ----------------------
# 5. USER ENUMERATION
# ----------------------
RunCmd "net_user" "net user"
RunCmd "local_admins" "net localgroup administrators"
RunCmd "query_user" "query user"

# ----------------------
# 6. PROCESS COLLECTION
# ----------------------
RunCmd "tasklist_verbose" "tasklist /v"

Write-Host "[*] Processing: process_tree" -ForegroundColor Yellow
Get-CimInstance Win32_Process |
Select-Object ProcessId,ParentProcessId,Name,CommandLine |
Format-Table -AutoSize |
Out-File "$OutputDir\process_tree.txt"
Write-Host "[+] Completed: process_tree" -ForegroundColor Green

# ----------------------
# 7. NETWORK INFORMATION
# ----------------------
RunCmd "netstat_ano" "netstat -ano"
RunCmd "ipconfig_all" "ipconfig /all"
RunCmd "arp_table" "arp -a"
RunCmd "route_table" "route print"
RunCmd "dns_cache" "ipconfig /displaydns"

# ----------------------
# 8. PERSISTENCE CHECKS
# ----------------------
RunCmd "scheduled_tasks" "schtasks /query /fo LIST /v"
RunCmd "services" "sc query"
RunCmd "runkey_hklm" "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
RunCmd "runkey_hkcu" "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

Write-Host "[*] Processing: startup_items" -ForegroundColor Yellow
Get-CimInstance Win32_StartupCommand |
Format-Table Name,Command,Location |
Out-File "$OutputDir\startup_items.txt"
Write-Host "[+] Completed: startup_items" -ForegroundColor Green

# ----------------------
# 8B. WMI PERSISTENCE
# ----------------------
RunCmd "wmic_event_filters" "wmic /namespace:\\root\subscription PATH __EventFilter get Name,Query,EventNamespace,CreatorSID"
RunCmd "wmic_event_consumers" "wmic /namespace:\\root\subscription PATH CommandLineEventConsumer get Name,CommandLineTemplate"
RunCmd "wmic_bindings" "wmic /namespace:\\root\subscription PATH __FilterToConsumerBinding get Filter,Consumer"

Write-Host "[*] Processing: wmi_event_filters_ps" -ForegroundColor Yellow
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
Select Name, Query, EventNamespace |
Format-Table -AutoSize |
Out-File "$OutputDir\wmi_event_filters_ps.txt"
Write-Host "[+] Completed: wmi_event_filters_ps" -ForegroundColor Green

Write-Host "[*] Processing: wmi_event_consumers_ps" -ForegroundColor Yellow
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
Select Name, CommandLineTemplate |
Format-Table -AutoSize |
Out-File "$OutputDir\wmi_event_consumers_ps.txt"
Write-Host "[+] Completed: wmi_event_consumers_ps" -ForegroundColor Green

Write-Host "[*] Processing: wmi_bindings_ps" -ForegroundColor Yellow
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
Select Filter, Consumer |
Format-Table -AutoSize |
Out-File "$OutputDir\wmi_bindings_ps.txt"
Write-Host "[+] Completed: wmi_bindings_ps" -ForegroundColor Green

# ----------------------
# 9. INSTALLED SOFTWARE
# ----------------------
Write-Host "[*] Processing: installed_software" -ForegroundColor Yellow
Get-Package |
Format-Table Name,Version |
Out-File "$OutputDir\installed_software.txt"
Write-Host "[+] Completed: installed_software" -ForegroundColor Green

# ----------------------
# 10. FULL C: DRIVE LISTING
# ----------------------
Write-Host "[*] Processing: file_listing_C (this may take a while...)" -ForegroundColor Yellow
try {
    Get-ChildItem "C:\" -Recurse -Force -ErrorAction SilentlyContinue |
    Select-Object FullName,Length,CreationTime,LastWriteTime,LastAccessTime |
    Export-Csv "$OutputDir\file_listing_C.csv" -NoTypeInformation -Encoding utf8

    Write-Host "[+] Completed: file_listing_C" -ForegroundColor Green
}
catch {
    "Failed to list C:\ drive" | Out-File "$OutputDir\file_listing_C.csv"
    Write-Host "[!] Failed: file_listing_C" -ForegroundColor Red
}

# ----------------------
# 11. OPTIONAL OSQUERY
# ----------------------
if (Get-Command osqueryi -ErrorAction SilentlyContinue){

    Write-Host "[*] Processing: osquery_processes" -ForegroundColor Yellow
    osqueryi "SELECT pid,name,path,cmdline,parent FROM processes;" |
    Out-File "$OutputDir\osquery_processes.txt"
    Write-Host "[+] Completed: osquery_processes" -ForegroundColor Green

    Write-Host "[*] Processing: osquery_network" -ForegroundColor Yellow
    osqueryi "SELECT pid,local_address,local_port,remote_address,remote_port FROM process_open_sockets;" |
    Out-File "$OutputDir\osquery_network.txt"
    Write-Host "[+] Completed: osquery_network" -ForegroundColor Green
}

# ----------------------
# 12. COMPLETE
# ----------------------
Write-Host ""
Write-Host "[+] IR Collection Complete at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "[+] Results saved to:" -ForegroundColor Cyan
Write-Host $OutputDir
