# Detection: Suspicious Azure AD Sign-In Activity

## Threat Scenario
An attacker attempts to access a user account using compromised credentials from an unfamiliar location or device.

## Detection Logic
The detection focuses on:
- Failed sign-in attempts followed by a successful login
- Sign-ins from unfamiliar geolocations
- Sign-ins without MFA where MFA is expected

## Example Logic 
```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress
| where FailedAttempts > 5
