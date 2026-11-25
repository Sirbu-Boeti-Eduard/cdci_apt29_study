# Attack write-up: the SolarWinds build compromise in a Mininet lab

Draft for the CDCI Assignment 1 report. It describes the attack steps of the SolarWinds supply-chain compromise attributed to APT29, then the subset of those steps recreated in `tasks/task05-poc`, and where the two differ. The lab code is at commit `7c99000`. Operating instructions live in `playbook.md` and `demo-runbook.md`; this file is the graded narrative, not a manual.

## 1. What the actor did

The campaign inserted a backdoor into the SolarWinds Orion build and shipped it to customers through the normal update channel. CrowdStrike's analysis of a build server describes an implant, SUNSPOT, that waited for `MsBuild.exe`, replaced one source file in the solution directory with a backdoored copy, and restored the original once the build exited [2]. The resulting binary was signed through SolarWinds' own signing process, so customers received a correctly signed update that contained the backdoor [1][4].

Once installed, the backdoor stayed quiet. It required an Active Directory domain, checked a blocklist of analysis tools, and waited until the plugin file was 12 to 14 days old before any network activity [1]. It then used a domain generation algorithm to build subdomains under `avsvmcloud[.]com`, encoding a user ID and the victim's domain, and resolved them with the system DNS client [1]. The coordinator answered with an A record, and the address block decided the next state: Truncate (3, disabled), New (4, passive), or Append (5, active) [1]. A CNAME response supplied the host for HTTPS command and control, and the malware required a CNAME because it could not use a raw address [1].

Active C2 imitated the Orion Improvement Program, with JSON documents under 10,000 bytes carrying fields such as `userId`, `sessionID` and a `steps` array, and commands hidden in the response body [1]. Tasking covered process execution, file transfer, registry access and reboot [1]. On selected victims the operators moved to a second stage: TEARDROP, Raindrop and other custom loaders delivered Cobalt Strike Beacon, after which they used AdFind, credential access and forged SAML tokens against cloud services [3][4].

## 2. The lab

The lab is one Mininet network inside a Docker container: an updater, a DNS coordinator and an HTTP receiver on a switch, and a victim whose only link to the switch crosses a bridging sensor. A separate pipeline signs releases, and five small web apps expose the supplier, the client, the operator, the presenter and the defender. The supplier publishes V1 and V2 as data-only packages and can publish one V3 package that declares a component. The client verifies the catalog digest, an RSA/SHA-256 signature with a pinned public key, and the component digest, then extracts the component and starts it as a process. `topology.py` runs `tcpdump` on the bridge, and `sensor.py` reads that capture file.

## 3. Kill-chain mapping

| Phase | Actor, per reporting | Lab | Status |
| --- | --- | --- | --- |
| Reconnaissance | Build chain understood before SUNSPOT was written [2] | Nothing | Not modelled |
| Weaponization | Source file replaced during the build, original restored after [2] | A prebuilt V3 package declares a component and pins its digest | Represented, not performed |
| Delivery | Signed update distributed through the normal channel [1] | Signed package published to a stable channel and downloaded over HTTP | Executed |
| Exploitation | Customer installs the update | Client verifies and installs V3 | Executed |
| Installation | Backdoored DLL loads inside the Orion process | Installer registers the declared component and starts one process | Executed, reduced |
| Command and control | DGA check-in, mode by A record, CNAME handoff, OIP-shaped HTTPS | Encoded check-in, mode by coordinator answer, CNAME handoff, HTTP POST | Executed, reduced |
| Actions on objectives | TEARDROP to Cobalt Strike, AdFind, credential access, SAML forgery [3][4] | One shell command and its output | Executed, reduced |

## 4. Step notes

### 4.1 Weaponization

SUNSPOT ran as `taskhostsvc.exe`, persisted through a scheduled task, watched for `MsBuild.exe`, read the build command line out of the process memory, and replaced `InventoryManager.cs` with a backdoored copy while keeping the original as a `.bk` file. It checked MD5 hashes first, wrapped its edits in `#pragma warning disable`, and restored the original after the build exited, so the repository looked untouched [2].

The lab does not have a build system. The V3 package is assembled out of band and uploaded, and the manifest names `orion-improvement-program`, its file and its SHA-256. The pipeline validates that the zip contains exactly the declared files, checks each digest, and signs the package. This is the compromise represented as an artifact rather than performed as a build step. It is the largest difference between the lab and the incident, and the reason the write-up does not claim to reproduce SUNSPOT.

### 4.2 Delivery and verification

The lab's client downloads the catalog, the package and the signature, checks the package against the catalog digest, verifies the signature with `openssl` against a public key that is not writable from the client, and checks the component digest before starting it. All checks pass. That is the point of the recreation: a correct verifier accepts a malicious build because the supplier signed it, exactly as the Orion customers did [1][4].

Two reductions: the real update was a signed DLL loaded by a running product, while the lab package is a zip containing a Python module; and the supplier in the lab is a small web app, not Orion. The trust property is preserved, the file format and the product are not.

### 4.3 Dormancy

The real implant waited 12 to 14 days, required an AD domain, and stopped when it found analysis tools [1]. The lab component starts three seconds after installation and performs no environment checks. The compression is deliberate, and so is the omission: the lab implant would run on any host, which is a capability the real one did not have.

### 4.4 Check-in and mode selection

The real DGA builds a random-looking label from an MD5 of the MAC address, domain and `MachineGuid`, encodes the user ID and the victim domain, and uses four suffix variants under a real domain [1]. The coordinator's A record selects a mode from hard-coded address blocks, and the mode value is stored in the DLL's XML configuration as `ReportWatcherRetry` [1].

The lab mirrors the shape and the values. The label is a base32 encoding of an XORed record holding a version byte, the mode byte, a four-byte uid, length-prefixed host and user names, and a CRC-16. The coordinator decodes it, rejects a bad checksum with NXDOMAIN, and answers `192.0.2.10` for passive, `192.0.2.20` for active, or NXDOMAIN when disabled. The component starts at 4 and moves to 5 on the activation address, sends a final check-in at 3, and exits.

Three differences matter. The lab writes the mode into the label, where the real malware kept it in its config, so the capture can be read without host access. The lab's implant queries the coordinator directly with its own UDP client, while SUNBURST used the system resolver [1]. And the lab beacons every four seconds against a real minimum of one minute between HTTP callouts and DNS sleeps measured in hours [1].

### 4.5 Command and control

The real HTTP thread used HTTPS to the CNAME host, delayed at least a minute between callouts, and shaped its JSON as Improvement Program messages with `userId`, `sessionID` and a `steps` array, hiding commands in GUID and hex strings inside the response body [1]. Messages over 10,000 bytes were sent as-is [1].

The lab posts to `/swip/upd/orion.improvementprogram.asmx` with `Orion/2020.2.4 (Windows NT 10.0; Win64; x64)` and a body of analogous fields: `customerId`, `machineName`, `userName`, `osVersion`, `ipAddress`, `processId`. The field names are analogous, not identical, and the write-up should say so. The receiver answers with `swip.tasks`, and the component returns output in a `telemetry` block. The lab uses plain HTTP so the tap and the audience can read the body, and it posts to the resolved address rather than the CNAME hostname, which Mandiant says the real malware could not do [1]. Both are stated in the playbook as deliberate.

### 4.6 Tasking and actions on objectives

The real command set covered process execution, file read and write, registry operations, hashing and reboot [1]. The lab runs one shell command per task with `/bin/sh -lc`, returns the exit code and output, and blocks destructive patterns with a guardrail. That is enough to show tasking over the same channel the beacon uses, and not enough to claim post-exploitation.

### 4.7 Follow-on

The second stage is where the campaign became an intrusion: custom loaders such as TEARDROP and Raindrop delivered Cobalt Strike Beacon, with an IFEO debugger value on `dllhost.exe` and a VBScript to separate the loader from the SolarWinds process. Operators then used AdFind, AUDITPOL, `netsh` firewall rules, credential access, DCSync and SAML token forgery [3][4].

None of this is in the lab. There is one victim, no Windows host and no second stage. It is listed here so the write-up does not read as if the chain ended where the lab ends.

## 5. Tools

| Software | Role in reporting | In the lab |
| --- | --- | --- |
| SUNBURST | Backdoor in the signed Orion DLL [1][4] | Behaviour reimplemented as a Python component |
| SUNSPOT | Build-time source replacement [2] | Not reproduced; the tampered artifact is uploaded by hand |
| TEARDROP | Memory-only loader for Cobalt Strike Beacon [3] | Not reproduced |
| Raindrop | Loader variant using AES-256, LZMA and XOR [3] | Not reproduced |
| Cobalt Strike | Post-exploitation framework reached through the loaders [3][4] | Not reproduced |
| AdFind | Active Directory enumeration [3][4] | Not reproduced |
| Mimikatz | Credential access [4] | Not reproduced |

No binary belonging to the actor, and no licensed tool, was run in this lab. What is recreated is the technique, not the tool: a signed package that carries code, and a check-in that lets the operator choose a victim. The tool report and the demo should say that in one sentence rather than let the mapping table imply otherwise.

## 6. Detection and response

The sensor reads the capture file that the tap writes. It does not read the DNS log, the receiver log or the beacon list, and it does not know the scenario phase. Seven rules are defined; five can fire in the current single-host lab. `T5-DGA-003` needs a hand-made lookalike, and `T5-DGA-004` needs a second source address, so neither appears in a normal run. `T5-DGA-002` imports the same encoder as the payload, so a valid checksum proves the lab's encoder ran, not that an unknown implant is present. The honest claim is that the check-in is decodable and periodic once captured, not that the rules would find SUNBURST.

Mandiant's incident-response note is that CNAME resolutions are a stronger signal than DGA decoding, because a decoded domain only shows the backdoor was present [1]. The lab shows the handoff in the operator console and the capture, but its seven rules still key on the encoded label. In that sense the lab demonstrates the weaker signal that Mandiant cautions against, and the write-up should say so rather than present the rule set as best practice.

Two response actions change real state. A resolver block makes the coordinator answer NXDOMAIN, and the component sends one final mode-3 check-in and exits. Tap isolation installs a `tc` egress filter on the switch-side bridge port, so the victim's frames stop reaching the network while the capture keeps recording them. Both are reversible, and the lab refuses to change the coordinator mode while a block is active.

## 7. Limits

- No build system, so no SUNSPOT-style replacement and restore.
- No Windows host, no signed PE, no DLL loading inside a product.
- No TLS, no steganography, and OIP fields that are analogous rather than identical.
- No 12 to 14 day dormancy and no environment checks.
- No persistence. The component lives in a work directory and dies with the container.
- No second stage, no lateral movement, no credential access, no collection.
- One victim, so two detection rules cannot fire and the reuse rule is untested.
- The lab's DNS is a purpose-built UDP server on the same subnet, not an authoritative server for a registered domain.

## 8. Evidence

- Lab commit `7c99000`.
- `pipeline/sample-v3-malicious.zip`, with payload, zip entry and pinned digest all `28cbdfb047c3eadceaf9ebb1d88b149ceb23cc405baacbca4d64b1b33a061810`.
- Client update history lines for found, downloaded, verified, installed, and the registered component.
- The capture at `/tmp/task05-poc/capture/c2-traffic.pcap` and the sensor snapshot at `/tmp/task05-poc/sensor/state.json`, both produced by the demo run.
- Screenshots for the report still need to be taken from a rehearsal; none are in the repository yet.

## References

1. Stephen Eckels, Jay Smith, William Ballenthin (Mandiant). "SUNBURST Additional Technical Details." 24 December 2020. Sections: Anti-Analysis Environment Checks; Domain Generation Algorithm; DNS C2 and the C2 Coordinator Protocol; HTTP(S) C2; Modes of Operation; Q&A. https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details
2. CrowdStrike Intelligence Team. "SUNSPOT: An Implant in the Build Process." 11 January 2021. Sections: Technical Analysis; Orion Source Code Replacement; TTPs. https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/
3. Microsoft Cyber Defense Operations Center and Microsoft Threat Intelligence. "Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop." 20 January 2021. Sections: The missing link; Variant 1: TEARDROP; Additional attacker tactics. https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
4. MITRE ATT&CK. "SolarWinds Compromise, Campaign C0024." Version 1.1, last modified 31 July 2026. Software table and Techniques. https://attack.mitre.org/campaigns/C0024/
