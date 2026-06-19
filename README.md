# soc-homelab-splunk-sysmon
Built a SOC monitoring pipeline from scratch — Sysmon telemetry → Splunk Universal Forwarder → Splunk Enterprise SIEM. Includes detection queries, dashboard panels, and full setup guide.

# SOC Home Lab — Sysmon + Splunk SIEM on Windows VM

A hands-on Security Operations Center (SOC) home lab built from scratch on a Windows virtual machine. This project covers endpoint telemetry collection with Sysmon, log forwarding with Splunk Universal Forwarder, and real-time threat visibility through a custom Splunk dashboard.

> Built as a self-directed learning project to develop practical blue team and SOC analyst skills.

---

## What This Project Does

- Captures deep endpoint telemetry (process creation, network connections, file changes) using **Sysmon**
- Forwards Windows Event Logs to a central SIEM using **Splunk Universal Forwarder**
- Ingests, searches, and visualizes security events using **Splunk Enterprise**
- Provides a multi-panel **SOC Monitoring Dashboard** for real-time threat visibility

---

## Tools & Technologies

| Tool | Purpose |
|------|---------|
| Windows 10 VM | Target endpoint being monitored |
| Sysmon v15 (Sysinternals) | Endpoint telemetry and event logging |
| Splunk Universal Forwarder 10.4 | Log collection and forwarding agent |
| Splunk Enterprise 9.x | SIEM — indexing, searching, dashboards |

---

## Architecture

```
Windows VM
│
├── Sysmon
│     └── Writes to: Windows Event Log (Microsoft-Windows-Sysmon/Operational)
│
├── Splunk Universal Forwarder
│     ├── inputs.conf  → monitors Sysmon channel
│     └── outputs.conf → forwards to localhost:9997
│
└── Splunk Enterprise
      ├── Receives on port 9997
      ├── Indexes to: main
      └── Dashboard: SOC Monitoring
```

---

## Dashboard Panels

The SOC Monitoring Dashboard includes the following panels:

| Panel | Description |
|-------|-------------|
| Total Sysmon Events | Live count of all ingested Sysmon events |
| Top Sysmon Event Types | Breakdown of event IDs (Process Create, Network Connect, etc.) |
| Top Executed Processes | Most frequently launched executables |
| PowerShell Executions | Tracks PowerShell activity — common in attacks |
| Process Creation Timeline | Time-series chart of process creation events |
| Sysmon Event Distribution | Pie chart showing event type proportions |
| Events by Host | Useful when scaling to multiple machines |

> **48,000+ events indexed in under 24 hours** from a single Windows VM during normal usage.

---

## Setup Guide

### Prerequisites

- A Windows 10/11 machine or VM
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) downloaded
- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free trial)
- [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html)

---

### Step 1 — Install and start Sysmon

Open PowerShell as Administrator and run:

```powershell
cd C:\Users\ADMIN\Downloads\Sysmon
.\Sysmon64.exe -accepteula -i
```

Verify it is running:

```powershell
sc query Sysmon64
```

You should see `STATE: 4 RUNNING`.

---

### Step 2 — Install Splunk Enterprise

1. Download and install Splunk Enterprise
2. Open `http://localhost:8000` in your browser
3. Log in with the credentials you set during installation
4. Enable receiving on port **9997**:
   - Go to **Settings → Forwarding and receiving → Configure receiving**
   - Click **New Receiving Port** → enter `9997` → Save

---

### Step 3 — Install Splunk Universal Forwarder

1. Download and install the Universal Forwarder
2. During setup, set the **receiving indexer** to `127.0.0.1:9997`

---

### Step 4 — Configure inputs.conf

Navigate to:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\
```

Create or edit `inputs.conf` with the following content:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
renderXml = true
```

---

### Step 5 — Configure outputs.conf

In the same `local\` directory, create or edit `outputs.conf`:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 127.0.0.1:9997
```

---

### Step 6 — Restart the forwarder

Open Command Prompt as Administrator:

```cmd
cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk restart
```

Verify the forwarder is active:

```cmd
splunk list forward-server
```

You should see `127.0.0.1:9997` listed as an active forward.

---

### Step 7 — Verify events in Splunk

In Splunk Enterprise, go to **Search & Reporting** and run:

```spl
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

If events appear, your pipeline is working correctly.

---

## Key SPL Queries

```spl
# All Sysmon events
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

# Process creation events (EventID 1)
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1

# Top executed processes
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| stats count by Image
| sort -count
| head 10

# PowerShell executions
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventID=1
| search Image="*powershell*"
| table _time Image CommandLine ParentImage

# Event type distribution
index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| stats count by EventID
| sort -count
```
Alert 1: PowerShell Execution
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*powershell*"

Alert 2: Reconnaissance Commands
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*whoami*" OR CommandLine="*ipconfig*" OR CommandLine="*systeminfo*" OR CommandLine="*net user*"

Alert 3: Suspicious Processes
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search Image="*powershell.exe*" OR Image="*cmd.exe*" OR Image="*rundll32.exe*" OR Image="*regsvr32.exe*"
---

## Troubleshooting

**No events in Splunk after setup?**

Check the forwarder logs for errors:

```cmd
cd "C:\Program Files\SplunkUniversalForwarder\bin"
splunk cmd btool inputs list --debug | findstr /i Sysmon
```

If you see `errorCode=5`, the forwarder lacks permission to read the Sysmon channel. Fix it by running Splunk Forwarder as a Local System account or granting read access to the Sysmon event log.

**Sysmon service not found?**

Make sure you ran the installer as Administrator and accepted the EULA:

```powershell
.\Sysmon64.exe -accepteula -i
```

---

## What I Learned

- How Sysmon generates structured telemetry from Windows kernel events
- How to configure a Splunk forwarder → indexer pipeline from scratch
- Debugging `inputs.conf` and `outputs.conf` misconfigurations
- Writing SPL queries for threat hunting and process analysis
- Building a multi-panel SOC dashboard for real-time visibility
- How much noise a single endpoint generates — and why tuning matters

---

## Future Improvements

- [ ] Add a Sysmon config file (e.g., SwiftOnSecurity ruleset) for better signal-to-noise ratio
- [ ] Simulate attack techniques (e.g., Atomic Red Team) and detect them in Splunk
- [ ] Build alert rules for suspicious behaviors (e.g., encoded PowerShell, LSASS access)
- [ ] Expand to multiple VMs (attacker + defender setup)
- [ ] Integrate with MITRE ATT&CK framework

---

## References

- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Splunk Documentation](https://docs.splunk.com/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## Author

**Zakir** — Cybersecurity enthusiast building hands-on blue team skills.  
Connect with me on https://www.linkedin.com/in/shaik-mohammad-zakir-103384321/

---

*This project was built entirely for learning purposes in a personal lab environment.*
