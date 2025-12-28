# Detection Use Case: Brute Force Login Attempts

## Objective
Detect large-scale login attempts targeting multiple accounts from a single source IP, indicating potential password spraying or credential stuffing attacks.

---

## Threat Scenario
Attackers may attempt to compromise accounts by repeatedly guessing passwords across several accounts. This can lead to unauthorized access to sensitive information if not detected promptly.

---

## Detection Logic
Trigger alerts when multiple failed login attempts occur for different accounts from the same IP in a short time window.

**KQL Logic**
```kql
let threshold = 50;
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= threshold
```
---

**Explanation**

- Counts failed logins per IP every 15 minutes
- Illustrates IPs attempting mass credential attacks (brute force attempts)

---

**Investigation Workflow**

1. Validate source IP using ISACs, Threat Intel feeds, or OSINT
2. Identify targeted accounts, focused on high-value or admin accounts
3. Check historical patterns to rule out false positives
4. Escalate incidents for persistent or high-risk activity

---

**Response Actions**

- Block or quarantine suspicious/malicious IP addresses (ACLs, BHR or RPZ)
- Force password resets for affected account(s)
- Monitior for repeat attempts
- Updated Conditional Access or MFA Policies


---
**Tuning Considerations**

- Exclude corporate VPNs or trusted sources
- Adjust thresholds for organization size and login patterns
- Integrate UEBA signals to detect subtle attacks

---
