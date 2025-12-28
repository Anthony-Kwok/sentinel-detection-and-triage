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
