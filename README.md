# Threat Hunt: Okta Account Takeover from Anomalous Geolocation
 
**Lab environment:** Microsoft Sentinel Training Lab dataset (`OktaV2_CL`)
**SC-200 domain:** Perform threat hunting · Respond to security incidents
**Detection surface:** Microsoft Sentinel (Defender portal) · KQL

---

## Summary

While hunting for signs of credential compromise across Okta sign-in data, I identified a single user account authenticating from a country that broke the organisation's baseline. Pivoting on that account surfaced a full account-takeover chain executed from Russia against a US-based tenant: the attacker seized super-admin privileges, planted their own MFA and an API token for persistence, and dismantled the legitimate users' MFA. All actions were recorded within the same second, indicating scripted rather than manual activity.

**Verdict:** True positive — active, in-progress tenant compromise. Critical severity.

---

## Environment note

This investigation was performed in a lab tenant using Microsoft's Sentinel Training Lab dataset. The Okta data lands in a custom table (`OktaV2_CL`), so column names differ from a production Okta ingestion, but the hunting logic and investigative reasoning transfer directly to a live environment.

---

## Scenario & hypothesis

Threat intelligence indicated that stolen Okta credentials for the organisation may be in circulation. If an attacker were using stolen credentials, their sign-ins would likely originate from a different geographic location than the legitimate user's normal pattern.

**Hypothesis:** An account authenticating from a country outside the organisation's baseline is a candidate for compromise.

---

## Hunt methodology

### Step 1 — Establish the baseline

Rather than starting from an alert, I baselined *where each user normally logs in from* by counting successful sign-ins per user, per country.

```KQL
OktaV2_CL
| where EventResult == "Success"
| summarize LoginCount = count() by ActorUsername, SrcGeoCountry
| order by ActorUsername asc
```

**Result:** Every account authenticated exclusively from the US — except one:

| ActorUsername | SrcGeoCountry | LoginCount |
|---|---|---|
| psharma@pkwork.onmicrosoft.com | US | 13 |
| ceo@pkwork.onmicrosoft.com | US | 6 |
| aturner@pkwork.onmicrosoft.com | US | 5 |
| spatel@pkwork.onmicrosoft.com | US | 4 |
| jliu@pkwork.onmicrosoft.com | US | 2 |
| **mirage@pkwork.onmicrosoft.com** | **RU** | **6** |

The `mirage` account authenticating exclusively from Russia, against an otherwise all-US baseline, was the outlier worth pivoting on.

### Step 2 — Pivot on the anomalous account

I pulled every action associated with the Russian-origin activity, ordered chronologically to reconstruct the sequence of events.

```kql
OktaV2_CL
| where SrcGeoCountry == "RU"
| project TimeGenerated, ActorDisplayName, EventMessage
| order by TimeGenerated asc
```

---

## Findings

The pivot revealed a textbook account-takeover and tenant-seizure chain, all attributed to the `mirage` actor:

| Order | Action (`EventMessage`) | Purpose |
|---|---|---|
| 1 | User login to Okta (password) | Initial access with compromised credentials |
| 2 | Grant user super admin role | Privilege escalation — full tenant control |
| 3 | Create API token | Persistence — a credential that survives password/MFA resets |
| 4 | Enroll new TOTP factor for attacker-controlled device | Persistence — attacker's own MFA |
| 5 | Deactivate SMS factor for user Priya Sharma | Weakening a victim's MFA |
| 6 | Reset all MFA factors for user CEO PKWork | Locking the legitimate CEO out |

**Key observation — automation:** Every event carried an identical timestamp (`Aug 8, 2026 12:09:52 PM`). A human operating the Okta console cannot grant a role, mint a token, enrol a factor, and reset MFA within the same second. The uniform timestamp indicates the actions were executed by a script or API automation, not manual clicks.

**Actor vs. target:** `mirage@pkwork` is the *attacker-controlled account* performing the actions. The `CEO` and `Priya Sharma` accounts are *victims* the attacker acted upon. Distinguishing actor from target is essential so response effort is directed at the right accounts.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1078 – Valid Accounts | Password login from RU using compromised credentials |
| Privilege Escalation | T1098.003 – Account Manipulation: Additional Cloud Roles | Grant super admin role |
| Persistence | T1098.001 – Account Manipulation: Additional Cloud Credentials | Create API token |
| Persistence | T1098.005 – Account Manipulation: Device Registration | Enroll attacker-controlled TOTP factor |
| Defense Evasion | T1556.006 – Modify Authentication Process: MFA | Deactivate victim SMS factor |
| Impact | T1531 – Account Access Removal | Reset CEO's MFA to deny legitimate access |

---

## Containment & response

The critical insight driving the response order: **a password reset alone does not contain this attacker.** The API token and the attacker-enrolled TOTP factor authenticate independently of the password, and an active session persists until explicitly revoked. Containment must close *every* path back in.

**Response sequence — stop the bleeding → close the doors → clean up → preserve evidence:**

1. **Revoke active sessions** — the attacker is authenticated in real time; terminate sessions immediately so access is cut before anything else.
2. **Revoke the API token** — the backdoor that ignores password and MFA controls; without this, all other steps are bypassed.
3. **Reset the account password** — blocks re-authentication with the stolen credentials.
4. **Reset all MFA factors** — removes the attacker-enrolled TOTP so their planted factor cannot be reused; legitimate user re-enrols clean.
5. **Undo the damage** — remove the granted super-admin role, re-enable Priya Sharma's SMS factor, restore the CEO's MFA.
6. **Preserve the attacker account as evidence** — disable (do not delete) `mirage` to retain the forensic trail of what was accessed, when, and from where.

---

## Lessons learned

- **Hunting beats waiting for alerts.** This chain was surfaced by baselining normal behaviour and spotting the outlier — not from a fired alert.
- **Containment means closing every path, not just the obvious one.** Password resets do not revoke API tokens or attacker-registered MFA. Sessions, tokens, and MFA factors must all be addressed.
- **Reset ≠ re-enable.** Resetting MFA factors wipes attacker-planted factors; merely "re-enabling" MFA can leave the attacker's device attached.
- **Preserve before you purge.** Deleting the attacker account destroys evidence; disable and investigate first.
- **Uniform timestamps are a tell.** Same-second activity across multiple sensitive operations points to scripted/API-driven attacks.

---

## Skills demonstrated

Threat hunting with KQL · Behavioural baselining · Pivot investigation · Attack-chain reconstruction · Identity-first incident response · MITRE ATT&CK mapping · Okta / cloud identity security
