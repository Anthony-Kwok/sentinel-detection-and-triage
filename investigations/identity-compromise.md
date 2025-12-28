
Goal:
Demonstrate that I understand **false positives and tuning**, not just detection.

---

## STEP 5 — Investigation Walkthrough

Goal: Demonstrate **analyst reasoning**.

```md
# Investigation: Potential Identity Compromise

## Alert Summary
Microsoft Sentinel generated an alert indicating abnormal sign-in behavior for a user account.

## Investigation Steps
1. Reviewed sign-in logs in Azure AD
2. Identified abnormal IP address and device
3. Checked MFA status and authentication method
4. Correlated activity with endpoint telemetry
5. Reviewed user activity timeline

## Findings
- Login originated from a foreign IP
- MFA was not triggered
- Endpoint telemetry showed no malware execution

## Assessment
The activity suggests possible credential compromise without endpoint persistence.

## Recommended Actions
- Force password reset
- Enforce MFA for the user
- Review conditional access policies
- Monitor for repeat activity
