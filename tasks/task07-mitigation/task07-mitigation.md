# Task 7: Mitigation and Countermeasures

**Project:** APT29 and the SolarWinds SUNBURST supply-chain compromise
**Written by:** Emna Guesmi

## 1. What the attack exposed

SUNBURST reached customers inside a signed Orion update. The attackers did not change Orion's source repository. They placed SUNSPOT on a build server, where it watched for `MsBuild.exe`, confirmed that the build was Orion's, replaced `InventoryManager.cs` with a backdoored copy, and restored the original after compilation (CrowdStrike, "Orion Source Code Replacement"). SolarWinds then signed the resulting component and published it through its normal update channel (FireEye/Mandiant, "SUNBURST Backdoor").

A signature identifies the key that signed an artifact. It does not show what happened to the code before signing. CISA describes code signing as evidence of the author's identity and of the code's integrity at the time of signing, and notes that attackers can undermine the signing process itself (CISA, *Defending Against Software Supply Chain Attacks*, p. 3). The public accounts cited here do not describe a control that caught the substitution before release, so a valid signature made a tampered build look trustworthy to the customers who installed it.

The countermeasures below are grouped by where they act. Sources are named where a control comes from CISA or a vendor report. Where a control is the team's proposal, the text says so.

## 2. Prevention

### 2.1 Harden the build environment

SUNSPOT needed a build server it could reach, modify, and keep running. Separating build infrastructure from office and developer networks, restricting outbound traffic, using short-lived build agents, and limiting who can change build jobs all reduce that opportunity. CISA recommends protecting code from unauthorized access and using properly configured compilation and build processes (CISA, *Defending Against Software Supply Chain Attacks*, p. 12). Network isolation and disposable agents are the team's extension of that advice for this incident.

### 2.2 Protect signing keys and verify the artifact

Signing-key protection matters, but it would not have stopped SUNBURST, because the attackers used SolarWinds' own signing process. Three controls cover different gaps:

- Keep signing keys in a hardware security module (HSM) and restrict who can use them (team recommendation). CISA recommends protecting the code-signing certificate (CISA, *Defending Against Software Supply Chain Attacks*, p. 12). This limits key theft and misuse but does not detect a tampered build.
- Compare the released artifact with an independently produced reference before release (team recommendation). This is the control aimed directly at the substitution.
- Rebuild from source in a controlled environment and compare hashes where the toolchain allows it (team recommendation). A reproducible malicious build is still malicious: a match shows that the build matched its inputs, not that the inputs were safe.

### 2.3 Reduce supplier and identity risk

Software bills of materials (SBOMs), vendor assessments, least privilege, multi-factor authentication (MFA), and a zero-trust posture toward vendor software limit what an attacker can do after a malicious update is installed. CISA recommends that customers request a software component inventory and consider supplier development practices, and that vendors publish an SBOM with each release (CISA, *Defending Against Software Supply Chain Attacks*, p. 7 and p. 13). The identity and network measures are the team's proposal. None of these prevent a build-pipeline compromise. They shorten the time to identify affected components and reduce the reach of stolen credentials.

## 3. Detection

### 3.1 DNS monitoring

SUNBURST generated subdomain names under `avsvmcloud[.]com` with a domain generation algorithm (DGA) and encoded a machine identifier and the victim's internal domain in them. The IP range in the DNS answer told the implant whether to stay passive, become active, or disable itself, and a CNAME response supplied the server for later HTTP(S) command and control (Mandiant, "SUNBURST Additional Technical Details", "Domain Generation Algorithm" and "DNS C2 and the C2 Coordinator Protocol"). It waited 12 to 14 days before its first check-in (Mandiant, "Anti-Analysis Environment Checks").

Useful detection points:

- Unusually long or algorithmically generated subdomains.
- DNS queries from servers that normally make few external requests.
- A and CNAME answers that point to unexpected hosts or ranges.
- Delayed or periodic check-ins that do not match normal software behavior.

CISA's Orion guidance includes reviewing stored network traffic for new external DNS domains contacted by a small number of hosts (CISA AA20-352A, "SolarWinds Orion Specific Mitigations", Step 1). The group's PoC uses a fixed name and a simplified handoff, so a DGA classifier is not designed for its fixed-domain check-in. A detection rule for the PoC needs to be defined and measured against benign lab traffic.

### 3.2 Network behavior

Once active, SUNBURST disguised its traffic as Orion Improvement Program (OIP) messages over HTTP(S) (Mandiant, "HTTP(S) C2"). Signature matching does not separate that from product telemetry. A baseline of expected destinations, request cadence, and payload structure is more useful. CISA recommends that customers learn a product's expected external communication pattern and monitor for deviations (CISA, *Defending Against Software Supply Chain Attacks*, p. 14).

### 3.3 Endpoint detection and response (EDR)

EDR has little to work with while SUNBURST behaves as a signed, passive Orion component. It becomes useful after the operator acts. Mandiant reported TEARDROP delivering Cobalt Strike BEACON in at least one victim (FireEye/Mandiant, "TEARDROP and BEACON Malware Used"), and EDR can flag process injection, credential access, persistence, and known BEACON behavior. That visibility does not confirm a supply-chain compromise on its own.

## 4. Response and recovery

CISA's advice separated exposure from follow-on compromise. AA20-352A states that not every organization that received the backdoor was targeted with follow-on actions (CISA AA20-352A, "Key Takeaways"). For affected federal agencies, Emergency Directive 21-01 required disconnecting or powering down affected Orion versions (CISA ED 21-01, Required Action 2).

AA20-352A set out three steps for networks using Orion:

1. Image system memory and affected hosts, review accounts, and inspect stored traffic for new external DNS domains (Step 1).
2. Disconnect or power down affected instances, block traffic to and from their hosts, and remove attacker-controlled accounts and persistence (Step 2).
3. Rebuild monitored hosts from trusted sources and reset all credentials stored in or used by SolarWinds software (Step 3).

Mandiant made a related recommendation: build new systems rather than upgrading an affected host in place, because an upgrade can overwrite forensic evidence and leave additional backdoors (FireEye/Mandiant, "Immediate Mitigation Recommendations"). CISA's later eviction guidance organized the work into pre-eviction, eviction, and post-eviction phases, including rebuilding and reimaging systems and resetting the `krbtgt` account twice (CISA AR21-134A, Phases 1-3 and "Eviction Phase").

### 4.1 Mapping to the group's PoC

The Task 5 PoC simulates a supplier pipeline that publishes a tampered V3 update. The client downloads it, verifies a SHA-256 digest and RSA signature, performs a DNS check-in, follows a CNAME handoff, and contacts an operator over HTTP. The table below connects those stages to the countermeasures above.

| PoC stage | Countermeasure | Expected benefit |
|---|---|---|
| Tampered V3 enters the release pipeline | Build isolation and strict access control | Fewer opportunities to change release artifacts. |
| Pipeline signs and publishes V3 | Independent artifact verification and reproducible builds | Detect a mismatch between approved inputs and the released artifact. |
| Client accepts the signed update | Least privilege and restricted update permissions | Limit the rights and network reach available to the installed software. |
| Client performs DNS check-in and CNAME handoff | DNS logging and anomaly detection | Show unexpected DNS activity associated with C2. |
| Client contacts the operator over HTTP | Network monitoring and segmentation | Detect or block unexpected outbound connections. |
| Operator sends commands | EDR | Record and investigate post-compromise activity. |

The PoC is a simulation. It installs a manifest-based update, runs a predefined check-in routine, and does not execute arbitrary code from the update, reproduce SUNSPOT's file replacement, implement the original DGA, or recreate TEARDROP or Cobalt Strike. The countermeasures in this section have not been tested in the lab.

## 5. Evaluation

The ratings below are the team's assessment, not measured results. Difficulty refers to a typical enterprise deployment, not the PoC.

| Countermeasure | Expected effectiveness | Deployment difficulty | Reasoning |
|---|---|---|---|
| Build pipeline isolation | High | High | Requires rebuilding build infrastructure, network controls, and developer workflows. |
| Reproducible builds | High for detecting build tampering | Very high | Needs pinned dependencies, deterministic toolchains, controlled timestamps, and discipline across projects. |
| Independent artifact verification | High | High | Needs a separate verification path, trusted build records, and a release gate. |
| HSM-protected signing keys | Low for this attack, high against key theft | Medium | Procurement and process work. It protects the signing step, which SUNBURST did not need to break. |
| DNS anomaly detection | High for post-installation visibility | Medium | Needs DNS logging and tuning. A fixed-domain PoC is not a DGA detection test. |
| Network behavior analysis | Medium to high | Medium to high | Needs a baseline and monitoring tools. It can flag OIP-like traffic only after normal traffic is understood. |
| EDR | Medium | Low to medium | Mostly product adoption and configuration. Limited against a signed passive backdoor. |
| MFA and least privilege | Medium | Low | Limits lateral movement and credential reuse, but not the initial update. |
| SBOM and vendor risk management | Low to medium now, higher over time | Medium | Needs contractual and review processes. It gives visibility rather than prevention. |

## 6. Conclusion

A valid signature answered the wrong question in this incident. It showed that SolarWinds had signed the artifact, not that the build that produced it was clean. The controls that would have helped most sit before signing, in build isolation and independent artifact verification, and they are also the hardest to deploy. Detection and recovery remain necessary because prevention can fail. The group's PoC can illustrate the gap, but it has not tested whether these controls would close it.

## References

- CrowdStrike Intelligence, "SUNSPOT: An Implant in the Build Process," 11 January 2021, "Orion Source Code Replacement." https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/
- FireEye/Mandiant, "Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor," 13 December 2020, "SUNBURST Backdoor," "TEARDROP and BEACON Malware Used," and "Immediate Mitigation Recommendations." https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
- Mandiant, "SUNBURST Additional Technical Details," 24 December 2020, "Anti-Analysis Environment Checks," "Domain Generation Algorithm," "DNS C2 and the C2 Coordinator Protocol," and "HTTP(S) C2." https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details
- CISA, "Defending Against Software Supply Chain Attacks," April 2021, pp. 3, 7, 12, 13, and 14. https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_508_1.pdf
- CISA, AA20-352A, "Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations," 17 December 2020 (updated 15 April 2021), "Key Takeaways" and "SolarWinds Orion Specific Mitigations," Steps 1-3. https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
- CISA, Emergency Directive 21-01, "Mitigate SolarWinds Orion Code Compromise," 13 December 2020, Required Action 2. https://www.cisa.gov/news-events/directives/emergency-directive-21-01
- CISA, AR21-134A, "Eviction Guidance for Networks Affected by the SolarWinds and Active Directory/M365 Compromise," 14 May 2021, Phases 1-3 and "Eviction Phase." https://www.cisa.gov/news-events/analysis-reports/ar21-134a
