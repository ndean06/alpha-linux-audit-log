# alpha-linux-audit-log
Incident investigation using auditd, Sysmon for Linux, Sigma rules, and netflow data

## 🔍 Project Overview

This project documents a log-based investigation of a compromised Linux web server using advanced logging and detection tools. It focuses on identifying attacker behavior using `auditd`, Sysmon for Linux, Sigma rules via Zircolite, and netflow data — simulating real-world SOC and DFIR workflows.

---

## 🎯 Objective

* Use Linux `auditd` and Sysmon for Linux to monitor system-level activity
* Apply Sigma rules with Zircolite to detect known TTPs
* Investigate suspicious process behavior from the `www-data` service account
* Correlate host and network data to confirm lateral movement (RDP via SOCKS proxy)
* Practice real-world incident detection and analysis without a centralized SIEM

---

## 🔧 Tools & Technologies Used

| Tool / Tech            | Purpose                                                   |
| ---------------------- | --------------------------------------------------------- |
| `auditd`               | System activity auditing (file access, process execution) |
| `ausearch`, `aureport` | Filtering and reporting from audit logs                   |
| `Sysmon for Linux`     | Captures security-relevant system activity                |
| `sysmonLogView`        | Converts Sysmon XML logs to human-readable format         |
| `Zircolite`            | Runs Sigma rules locally against auditd/Sysmon logs       |
| `Sigma Rules`          | Generic log detection logic (MITRE-based)                 |
| `NetFlow data`         | Shows outbound network connections and traffic volume     |
| `grep`, `xxd`, `gedit` | Log inspection and decoding                               |

---

## 🧪 Investigation Summary

* Detected suspicious processes (`linpeas.sh`, `client.py`, `rpivot2`, etc.) run by `www-data`
* Decoded hex-encoded `proctitle` fields from auditd logs to uncover attacker commands
* Compared pre-intrusion and post-intrusion audit logs to establish baseline vs. compromise
* Applied Sigma rules with Zircolite to flag key behaviors like remote execution and recon
* Correlated event timestamps with NetFlow records showing RDP (TCP/3389) traffic from the Linux web server to a Windows file server (`10.130.9.42`)

---

## 🧠 Key Findings

* Web server's `www-data` account executed multiple tools beyond Apache — clear anomaly
* `rpivot2` SOCKS proxy script was used to pivot to internal systems
* RDP traffic confirmed to bastion Windows server with sensitive data
* Activity aligns with real-world post-exploitation and lateral movement techniques

---

## 📚 What I Learned

* How to decode and filter audit logs for deep system visibility
* How Sigma rules and Zircolite streamline threat detection
* Importance of comparing baseline logs to catch anomalies
* Real-world tactics like webshells, pivoting, and reconnaissance leave log trails

---

## 📁 Project Structure (Suggested)

```
alpha-linux-audit-log/
├── README.md
├── FINDINGS.md
├── TIMELINE.md
├── screenshots/
├── logs/
├── sigma-rules/
├── scripts/
└── LICENSE
```

---

## 🚀 Future Learning

* Expand detection with Zeek and Suricata
* Build ELK stack or Wazuh integration
* Deeper host forensics using memory or disk artifacts (Volatility, Autopsy)

---

**Status**: Completed
**Lab Source**: SANS SEC401 – Lab 6.3

Feel free to fork or use this structure to build your own forensic investigations!
