# ⏱️ Timeline – alpha-linux-audit-log

This file provides a chronological breakdown of key events uncovered during the investigation of the compromised Linux web server.

---

## 📅 Incident Timeline

| **Time (UTC)**        | **Event**                                                       | **Source**         |
| --------------------- | --------------------------------------------------------------- | ------------------ |
| `09/28/2023 20:56:12` | Start of recorded activity in `audit.log`                       | auditd             |
| `09/29/2023 01:03:22` | Execution of suspicious script: `linpeas.sh` by `www-data`      | Zircolite + auditd |
| `09/29/2023 01:03:24` | Webshell command spawns bash using timeout → `tcpdump` observed | auditd (proctitle) |
| `09/29/2023 01:04:11` | Sigma rule match: `Webshell Remote Command Execution`           | Zircolite          |
| `09/29/2023 01:08:39` | Execution of `client.py` (rpivot2 SOCKS proxy)                  | auditd + Sysmon    |
| `09/29/2023 01:09:00` | RDP connection established to 10.130.9.42 on port 3389          | NetFlow            |
| `09/29/2023 01:13:45` | Sustained outbound data transfer to Windows file server         | NetFlow            |
| `09/29/2023 14:23:51` | End of recorded activity in `audit.log`                         | auditd             |

---

## 🧠 Notes

* Timestamps aligned across logs using event IDs and PID relationships
* Parent-child process tracing confirmed chaining from webshell to `client.py`
* RDP activity was not present in baseline logs; it strongly correlates to compromise window

---
