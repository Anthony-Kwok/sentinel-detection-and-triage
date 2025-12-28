# Detection Use Case: Suspicious Sign-In Activity

## Objective
Detect potentially compromised accounts by analyzing abnormal authentication patterns and multi-factor authentication (MFA) anomalies in Azure AD, leveraging Microsoft Sentinel for centralized correlation and alerting.

---

## Threat Scenario
Attackers often attempt credential theft through:

- Password spraying  
- Brute force attacks  
- MFA bypass attempts  
- Logins from unusual geolocations or risky IP addresses  

Without detection, these activities can lead to unauthorized access to sensitive resources.

---

## Detection Logic
Alerts are triggered when multiple conditions indicate abnormal or risky sign-in behavior:

1. **Failed login patterns**: Multiple failed logins followed by a successful login within a short period.  
2. **Unfamiliar locations or IPs**: Sign-ins from locations that are unusual for the user or flagged as high-risk by Azure AD Identity Protection.  
3. **MFA anomalies**: Successful logins without MFA when the account policy requires it.  
4. **Impossible travel detection**: Sign-ins from geographically impossible locations within short time windows.

Each of these is correlated to reduce false positives using historical login behavior.

---

## Example KQL logic

```kql
let thresholdFailed = 5;
let suspiciousTimeWindow = 1h;
SigninLogs
| extend User = UserPrincipalName
| extend LoginTime = TimeGenerated
| extend Location = IPAddress
| summarize FailedAttempts = countif(ResultType != 0) 
            , FirstFailure=min(LoginTime) 
            , LastSuccess = maxif(LoginTime, ResultType == 0)
            by User, Location
| where FailedAttempts >= thresholdFailed 
      and LastSuccess - FirstFailure <= suspiciousTimeWindow
| join kind=inner (
    IdentityInfo
    | where MFARequired == true
    | extend MFAStatus = iff(MFACompleted == 1, "Passed", "Failed")
    | where MFAStatus == "Failed"
) on User
| project User, Location, FailedAttempts, FirstFailure, LastSuccess, MFAStatus
```
---

## Explanation
- **SigninLogs**: collects Azure AD login events.  
- **ResultType != 0**: counts failed login attempt
- This highlights accounts with failed login bursts, successful logins, and MFA bypass risk

---

## Investigation Workflow
1. **Validate user context**: Confirm role, business activity, and expected locations
2. **Check IP and geolocation**: Compare with historical login patterns and known VPN usage in logs.
3. **Endpoint correlation**: Review Defender for Endpoint telemetry for unusual device behavior
4. **Risk assessment**: Determine likelihood of compromise and assign risk score.
5. **Documentation**: Create incident record in ServiceNOW including alert, context and mitigation plan

---

## Response Actions
- For password reset and revoke Azure tokens for affected account(s)
- Enforce or review MFA policies and Conditional Access rules
- Monitor subsequent login attempts and endpoint activity
- Conduct user education if relevant (phishing awareness, MFA usage)
---

## Tuning 
- Exclude trusted locations and corporate VPN IPs
- Adjust thresholds per organizational login patterns
- Incorporate UEBA signals for historical baseline comparisons
- Tune detection rules to reduce false positives while maintaining sensitivity. 
---
