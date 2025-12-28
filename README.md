# Identity Threat Detection & Investigation  
**Microsoft Sentinel – SIEM Design and Analyst Workflow**

## Objective
Demonstrate how identity and endpoint telemetry can be leveraged within a SIEM to detect, investigate, and respond to suspicious sign-in activity in a cloud environment, using a structured and repeatable analyst workflow.

This project is designed to showcase security analysis, detection design, and investigation reasoning rather than tool-specific configuration.

---

## Business Context
As organizations increasingly rely on cloud-based identity platforms such as Azure Active Directory, identity compromise has become a primary attack vector. Threats such as credential theft, MFA fatigue, and unauthorized access attempts can result in data exposure or business disruption if not detected and investigated promptly.

Effective security monitoring requires:
- Centralized log ingestion
- Well-designed detection logic
- Human-driven investigation and decision-making
- Clear response actions aligned to risk

---

## Scope
This repository focuses on:
- Identity-based threat detection concepts
- SIEM correlation and alerting logic
- Analyst investigation methodology
- Actionable security response recommendations

Out of scope:
- Production tenant configuration
- Real client data
- Offensive security or exploitation activities

---

## Tools & Technologies
- **Microsoft Sentinel** (SIEM)
- **Azure Active Directory** (identity telemetry)
- **Microsoft Defender for Endpoint** (endpoint context)
- **KQL** (conceptual query examples)
- **MITRE ATT&CK** (attack context mapping)

---

## Detection Architecture Overview
The diagram below illustrates the end-to-end flow of identity and endpoint telemetry into Microsoft Sentinel, the detection logic used to identify suspicious activity, and the analyst-led investigation and response process.

![Detection Flow Diagram](diagrams/detection-flow.png)

---

## Detection Use Case: Suspicious Sign-In Activity
The detection use case focuses on identifying potentially compromised user accounts by analyzing authentication patterns such as:
- Multiple failed sign-in attempts followed by a successful login
- Sign-ins from unfamiliar or anomalous locations
- Authentication activity where MFA is unexpectedly absent

Detection logic is designed with tuning considerations in mind to reduce false positives related to legitimate travel, VPN usage, or atypical working hours.

---

## Investigation Methodology
When an alert is generated, the analyst follows a structured investigation process:

1. Review Azure AD sign-in logs for authentication patterns
2. Validate IP address, device, and geolocation context
3. Assess MFA enforcement and authentication methods
4. Correlate identity activity with endpoint telemetry
5. Determine likelihood of compromise versus benign behavior

This approach emphasizes contextual analysis over alert volume.

---

## Findings & Assessment
In the simulated investigation scenario:
- Authentication originated from an unfamiliar location
- MFA was not enforced for the affected account
- No malicious endpoint activity was observed

Based on these findings, the activity is assessed as a **potential credential compromise without endpoint persistence**.

---

## Response & Recommendations
Recommended response actions include:
- Forcing a password reset for the affected account
- Enforcing MFA and reviewing Conditional Access policies
- Monitoring for repeat or related activity
- Reviewing identity security posture for similar risk exposure

These actions aim to reduce immediate risk while improving long-term identity security controls.

---

## Assumptions
- Logs are centrally ingested into Microsoft Sentinel
- Identity telemetry is available from Azure Active Directory
- Endpoint telemetry is accessible for investigation support

---

## Limitations
- This project uses sanitized and simulated data
- Detection logic is conceptual and not production-tuned
- No automated response actions are implemented

---

## Lessons Learned
- Identity-based threats may not present endpoint indicators
- SIEM effectiveness depends heavily on detection quality and tuning
- Clear investigation playbooks improve analyst efficiency and consistency

---

## Future Improvements
- Incorporate UEBA signals for anomaly detection
- Integrate risk-based Conditional Access controls
- Automate initial investigation enrichment steps

---

## Disclaimer
All examples in this repository use simulated or sanitized data.  
No proprietary, client, or sensitive information is included.
