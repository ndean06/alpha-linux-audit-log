# 🧠 Findings – alpha-linux-audit-log

This file contains the detailed findings from the investigation of the compromised Linux web server in Lab 6.3. It summarizes specific evidence of attacker behavior across host-based logs and network data.

---

## 🔍 Key Detection Events

### 1. **Suspicious Process Execution by `www-data`**

* Multiple tools executed that should not be associated with a web service account:

  * `linpeas.sh` – privilege escalation script
  * `bash`, `timeout`, `tcpdump`, `client.py`, `git clone`
* Commands discovered via `proctitle` fields in auditd logs (decoded from hex)

### 2. **Sigma Rule Alerts via Zircolite**

* 177 matches: `Webshell Remote Command Execution`
* 11 matches: `System Information Discovery - Auditd`
* Alerts matched attacker TTPs, such as script execution and system recon

### 3. **rpivot2 Activity Confirmed**

* Detected execution of `client.py` (rpivot2 SOCKS proxy script)
* Parent PID traceable from earlier suspicious webshell commands
* Sysmon logs show client.py runtime and command line context

---

## 🔁 Baseline Comparison (Pre vs. Post-Intrusion)

### 📄 archive-audit.log (Pre-Intrusion)

* Only process executed by `www-data`: `/usr/sbin/apache2`
* Ran 202 times (normal for a web server)

### ⚠️ audit.log (Post-Intrusion)

* Dozens of unique commands executed by `www-data`
* Several matched known attacker tools and behaviors
* Strong anomaly indicating compromise

---

## 🌐 NetFlow Analysis – Lateral Movement

* RDP traffic (TCP/3389) detected from web server `10.130.8.94` to Windows bastion host `10.130.9.42`
* Large data transfer volume suggests exfiltration or staging
* Traffic correlated with `client.py` execution window

---

## 📌 Indicators of Compromise (IOCs)

| Type      | Value                            |
| --------- | -------------------------------- |
| File      | `linpeas.sh`, `client.py`        |
| Command   | `bash`, `tcpdump`, `git clone`   |
| Source IP | `10.130.8.94` (Linux web server) |
| Dest IP   | `10.130.9.42` (Windows server)   |
| Port      | TCP/3389                         |

---

## ✅ Summary

The investigation confirmed attacker behavior consistent with post-exploitation tactics:

* Webshell usage
* Privilege enumeration
* SOCKS proxy pivoting
* Remote Desktop access to sensitive Windows resources

Logs from `auditd`, Sysmon, and NetFlow collectively validated the compromise and gave a timeline of attacker actions.

---

