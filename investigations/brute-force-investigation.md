# Investigation: Brute Force Login Attempts

## Objective
Investigate alerts triggered by suspected brute force activity, confirming compromise potential and initiating appropriate response.

---

## Alert Summary
Multiple failed login attempts targeting multiple accounts from a single external IP.

---

## Investigation Steps
1. Identify source IP and geolocation  
2. Validate whether login attempts align with known corporate activity (VPN, scheduled tasks)  
3. Check affected accounts for prior compromise or unusual behavior  
4. Examine Defender for Endpoint telemetry for signs of malware or lateral movement  
5. Record findings and escalate if necessary  

---

## Findings
- Source IP is external and previously unseen  
- Failed logins targeted multiple accounts, including high-value users  
- No endpoint anomalies detected  

**Assessment:** High likelihood of brute force attempt, no confirmed compromise yet

---

## Recommended Response
- Block the external IP  
- Force password resets on affected accounts  
- Monitor targeted accounts and endpoints  
- Review and strengthen Conditional Access policies  

---

## Lessons Learned
- Early detection reduces risk to high-value accounts  
- Correlating IP, accounts, and endpoint telemetry improves SOC effectiveness  
- Tuning thresholds reduces alert fatigue
