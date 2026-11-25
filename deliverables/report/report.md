# APT29 and the SolarWinds Supply-Chain Compromise

## From SUNSPOT to a controlled recreation in Mininet and Docker

Draft for CDCI Assignment 1. This Markdown file is the working text of the report; the LaTeX version will be produced from it. Section sources are the `tasks/` folders, which hold the references and the lab artefacts.

---

## 1. Introduction

In December 2020, FireEye disclosed that a backdoor had been distributed to customers of SolarWinds inside a correctly signed update of the Orion IT-monitoring platform. The campaign was attributed to APT29, a group working for Russia's Foreign Intelligence Service (SVR) [1][2]. The incident matters beyond its victim list because nothing in the delivery path was broken. The supplier's build system produced the malicious component, the supplier's signing process signed it, and customers installed it through the update channel they were told to trust.

This report covers the actor, the operation, the evidence of its victims, and a recreation of the attack chain in a controlled lab. The lab does not run the actor's binaries. It rebuilds the trust failure: a pipeline signs a package that carries code, and a client verifies every check correctly before installing it. Later sections separate what was executed from what was represented, and what the recreation cannot show.

Public reporting is the evidence base. Where a source describes an event, the text attributes it. Where the team draws a conclusion, the text says so. The lab is a simulation of behaviour described by Mandiant and CrowdStrike, not a reproduction of the SUNBURST binary [7][8].

## 2. The actor

APT29 is tracked under several names. Microsoft calls the group Midnight Blizzard or NOBELIUM, Mandiant used UNC2452 for the SolarWinds activity before merging it into APT29 [35], and older reporting uses Cozy Bear or The Dukes [1][6]. A 2022 joint advisory from Five Eyes agencies states that the SVR has run cyber operations since at least 2008 and lists APT29 among the names used for those actors [2].

The group's history shows long campaigns against government and diplomatic targets, with tooling rebuilt between them. ESET reported that Operation Ghost began in 2013 and was still active in 2019, targeting foreign ministries in at least three European countries and an EU member state's embassy in Washington [3]. In the Democratic National Committee breach, CrowdStrike found Cozy Bear on the network from summer 2015 and a separate actor, Fancy Bear, from April 2016, with no evidence that the two worked together [4]. In July 2020, the UK NCSC and Canada's CSE reported that APT29 had targeted organisations involved in COVID-19 vaccine development in Canada, the United States, and the United Kingdom, with the likely aim of obtaining vaccine research [5].

The pattern continued after SolarWinds. The group exploited JetBrains TeamCity in 2023 [36], then ran phishing campaigns against German political parties, European diplomats, and more than 100 organisations in 2024 and 2025 [25][26][27]. The techniques change; the target set does not.

## 3. The SolarWinds operation

### 3.1 Build compromise

SolarWinds stated that it could not determine how the attackers first entered its network [10]. What is documented is what they did once inside. CrowdStrike analysed an implant called SUNSPOT that ran on the Orion build server as `taskhostsvc.exe`, kept alive by a scheduled task. It waited for `MsBuild.exe`, read the build command line from process memory, and replaced `InventoryManager.cs` in the solution directory with a modified copy, keeping the original as a `.bk` file. It restored the original when the build exited, so the source repository looked untouched. The implant checked MD5 hashes before and after the swap and wrapped its edits in `#pragma warning disable` [8].

The result was an Orion component containing SUNBURST. SolarWinds signed it through its normal release process and published it as a routine update [6][7].

### 3.2 Dormancy and check-in

SUNBURST did not act immediately. It required an Active Directory domain, stopped if the domain resembled a SolarWinds test environment, compared running processes against a list of analysis tools, and waited until the plugin file was 12 to 14 days old [7]. It then built a subdomain under `avsvmcloud[.]com` with a domain generation algorithm, encoding a user identifier and the victim's domain, and resolved it with the system DNS client [7].

The coordinator answered with an A record, and the address range set the next state. Truncate (3) disabled the implant. New (4) kept it passive and checking in. Append (5) made it active. A CNAME response supplied the host for HTTPS command and control, which the malware required because it could not use a raw address [7].

### 3.3 Command and control and follow-on

Active traffic imitated the Orion Improvement Program: JSON documents under 10,000 bytes with fields such as `userId`, `sessionID`, and a `steps` array, with commands hidden in the response body. The tasking covered process execution, file transfer, registry access, and reboot [7]. On selected victims, operators delivered second-stage loaders. TEARDROP ran in memory, read its payload from a file disguised as an image, and in at least one case used an Image File Execution Options value on `dllhost.exe` to start Cobalt Strike Beacon [9]. Raindrop performed the same role with a different loader [9]. Operators then used AdFind for directory enumeration, stole credentials including through DCSync, and forged SAML tokens to reach Microsoft 365 mailboxes [6][9].

The scale is often misread. About 18,000 customers received the affected update. GAO reported that SolarWinds estimated fewer than 100 were actually compromised, and that nine U.S. federal agencies were among them [11]. Receiving the update proved exposure, not intrusion.

## 4. Online presence and threat intelligence

APT29's infrastructure work is visible in public reporting, and it follows a consistent preference for services that other organisations already trust.

HAMMERTOSS, documented by FireEye in 2015, generated a new Twitter handle each day and read instructions from a tweet that pointed to an image on a site such as GitHub. The hashtag carried the offset of the hidden data and part of the key. Stolen data went to cloud storage accounts the operators created [19]. A 2021 advisory describes infrastructure bought with false identities and cryptocurrency, often through temporary email accounts and resellers, including personas using email services on `cock[.]li` or related domains [20]. No government or vendor report names a specific wallet or payment, and this report does not claim one exists.

The group also borrows legitimate mailing infrastructure. Microsoft reported that NOBELIUM used a compromised USAID Constant Contact account to send phishing mail to about 3,000 accounts at more than 150 organisations, with links through Constant Contact's redirector [21]. Polish authorities described embassy-themed emails that led to a compromised website and an ENVYSCOUT script using HTML smuggling [22]. Unit 42 documented a reused car-sale flyer sent to diplomatic missions in Kyiv, with payload control over the Microsoft Graph and Dropbox APIs [23]. In 2023, Microsoft reported Teams messages from newly created `onmicrosoft.com` tenants that asked users to approve an authenticator prompt [24].

Each case uses a service the target already allows. That is the intelligence value: blocking the actor's domains is less useful than recognising when a trusted service is being used to deliver an untrusted request.

## 5. Victims and business impact

Three SolarWinds customers illustrate the range of outcomes.

Mimecast reported that the actor accessed part of its production environment, including certificates, customer connection information, and encrypted or hashed credentials, and downloaded a limited number of source-code repositories. By 31 March 2021 it had recorded $0.8 million in pretax incident expenses, net of anticipated insurance recoveries [15]. A 2024 SEC order found that the actor exfiltrated an authentication certificate and used it against five customers' cloud platforms, and that it accessed a database holding encrypted credentials for about 31,000 customers and server or configuration information for about 17,000. The order put the source-code loss at 58 percent of Mimecast's exgestion code, 50 percent of its Microsoft 365 authentication code, and 76 percent of its interoperability code, and imposed a $990,000 penalty over the company's disclosures [14].

The Department of Justice reported compromised Microsoft 365 accounts in 27 U.S. Attorneys' offices, with at least 80 percent of employees affected in four New York districts. It treated all mail in those accounts as accessed, for a period from about 7 May to 27 December 2020 [16]. Its later review traced the intrusion to Orion and found that Office 365 configuration choices widened the actor's access [17].

Check Point found infected Orion installations on two servers and activity between July and October 2020, including command and control, unauthorised software, two compromised corporate accounts, and attempted lateral movement. Its logs did not cover all activity before September, so the full scope remained undetermined, and its investigation found no evidence that customer data or code was accessed. The SEC imposed a $995,000 penalty over its risk disclosures [18].

Two kinds of cost recur. The first is incident response: forensics, credential resets, customer notification, and legal work. The second is disclosure risk. Mimecast and Check Point were penalised for how they described their incidents, not for being breached. For a managed service provider, the exposure also reaches customers whose credentials or certificates sat in the compromised environment, so the certificate mattered to more parties than the source code did.

## 6. Recreating the attack

### 6.1 Design

The lab is one Mininet network inside a Docker container. A supplier pipeline signs releases, an updater serves them, a DNS coordinator answers check-ins, and an HTTP receiver acts as the control server. The victim's only link to the switch crosses a bridging sensor, so every packet is captured rather than read from an application log. Five small web apps expose the supplier, the client, the operator, the presenter, and the defender.

The client verifies the catalog digest, an RSA/SHA-256 signature against a pinned public key, and the component digest before extraction. The supplier can publish V1 and V2 as data-only packages and one V3 package that declares a component. The manifest names `orion-improvement-program`, its file, and its SHA-256; the pipeline rejects files the manifest does not declare.

### 6.2 Executed chain

| Kill-chain phase | In the incident | In the lab | Status |
| --- | --- | --- | --- |
| Reconnaissance | Build chain understood before SUNSPOT was written [8] | Nothing | Not modelled |
| Weaponization | Source file replaced during the build, original restored [8] | Prebuilt V3 package declares a component and pins its digest | Represented |
| Delivery | Signed update through the normal channel [6] | Signed package published to a stable channel, downloaded over HTTP | Executed |
| Exploitation | Customer installs the update | Client verifies and installs V3 | Executed |
| Installation | Backdoored DLL loads inside Orion | Installer registers the component and starts one process | Executed, reduced |
| Command and control | DGA check-in, mode by A record, CNAME handoff, OIP-shaped HTTPS | Encoded check-in, mode by coordinator answer, CNAME handoff, HTTP POST | Executed, reduced |
| Actions on objectives | TEARDROP to Cobalt Strike, AdFind, credential access, SAML forgery | One shell command and its output | Executed, reduced |

The client accepts the tampered package because every check passes. The catalog digest matches, the signature verifies against the pinned key, and the component digest matches the manifest. That is the property the lab was built to show: verification answers whether the supplier signed the artifact, not whether the build was clean.

After installation, the component waits three seconds, builds a base32 label from an XORed record holding a version byte, a mode byte, a user identifier, host and user names, and a CRC-16, and queries the coordinator. A bad checksum returns NXDOMAIN. The coordinator answers `192.0.2.10` for passive, `192.0.2.20` for active, or NXDOMAIN when disabled. The component starts at mode 4, moves to 5 on the activation address, and exits after a final mode-3 check-in when the coordinator is disabled.

Active traffic goes to `/swip/upd/orion.improvementprogram.asmx` with an `Orion/2020.2.4` agent string and a body of fields modelled on the Improvement Program: `customerId`, `machineName`, `userName`, `osVersion`, `ipAddress`, and `processId`. The receiver answers with `swip.tasks`, and the component returns output in a `telemetry` block. One shell command per task runs with `/bin/sh -lc`, with a guardrail against destructive patterns.

Evidence from the demo run is the client history for found, downloaded, verified, installed, and registered component; the capture at `/tmp/task05-poc/capture/c2-traffic.pcap`; and the sensor state at `/tmp/task05-poc/sensor/state.json`. The sample package and its digest are pinned in `pipeline/sample-v3-manifest.json` [12].

### 6.3 What the recreation does not do

The largest gap is weaponization. There is no build system, so SUNSPOT's replacement and restore is represented by a prebuilt package rather than performed. The lab has no Windows host, no signed PE, and no DLL loaded inside a product. Dormancy is compressed from 12 to 14 days to three seconds, and the environment checks are omitted, which makes the lab implant more portable than the original. Check-ins repeat every four seconds against a real minimum of one minute for HTTP and sleeps measured in hours for DNS. The control channel is plain HTTP so the capture can be read, and the implant queries the coordinator directly instead of using the system resolver. There is one victim, no persistence, no second stage, and no lateral movement.

These are stated here because the mapping table makes the chain look more complete than the lab is. What the lab reproduces is the trust path and the shape of the check-in, not the actor's code.

## 7. Detection

The sensor reads the capture file the tap writes. It does not read the DNS log, the receiver log, or the scenario state. Seven rules are defined and five can fire in a single-host run. Two need conditions the lab does not produce: a hand-made lookalike domain and a second source address. One rule imports the implant's own encoder, so a valid checksum shows that the lab's encoder ran, not that an unknown implant is present.

The claim the lab supports is narrower than "the rules detect SUNBURST". The check-in is decodable and periodic once captured, and the telemetry upload is visible on the wire. Mandiant's incident-response note is that CNAME resolutions are a stronger signal than decoding a DGA label, because a decoded domain only proves the backdoor was there [7]. The lab's rules key on the encoded label, which is the weaker signal. It shows what can be recovered from traffic, not what a defender should prioritise.

Response actions change real state. A resolver block makes the coordinator answer NXDOMAIN, and the implant sends one final mode-3 check-in and exits. Tap isolation installs an egress filter on the switch-side bridge port, so the victim's frames stop reaching the network while the capture keeps recording them. Both are reversible, and the lab refuses to change the coordinator mode while a block is active.

## 8. Countermeasures

The controls fall into three groups: those that act before signing, those that act at the customer, and those that act after installation.

Before signing, the useful controls address the build itself. Separating build infrastructure from office networks, restricting outbound traffic, using short-lived agents, and limiting who can change build jobs all reduce the opportunity SUNSPOT used. CISA recommends protecting code from unauthorised access and using properly configured build processes [28]. Comparing a released artifact with an independently produced reference, or rebuilding from source and comparing hashes, targets the substitution directly. Neither proves the code is benign; a reproducible malicious build is still malicious.

At the customer, the signature is the wrong question. Least privilege, restricted update permissions, and a baseline of expected vendor traffic limit what an installed component can do. SBOMs and supplier assessments shorten the time to identify affected components but do not prevent the build compromise [28].

After installation, detection depends on behaviour. DNS logging and anomaly analysis can show an unexpected check-in, and network baselines can separate vendor telemetry from a lookalike. EDR has little to work with while a signed component behaves normally, but becomes useful when the operator acts. CISA's Orion guidance covers reviewing stored traffic for new external DNS domains and comparing a product's expected external communications with what is observed [13][28].

| Countermeasure | Expected effectiveness | Deployment difficulty | Reason |
| --- | --- | --- | --- |
| Build pipeline isolation | High | High | Rebuilds infrastructure, network controls, and developer workflow |
| Reproducible builds | High for detecting tampering | Very high | Pinned dependencies, deterministic toolchains, controlled timestamps |
| Independent artifact verification | High | High | Needs a separate verification path, trusted records, and a release gate |
| HSM-protected signing keys | Low for this attack | Medium | Protects the signing step, which the attackers did not need to break |
| DNS anomaly detection | High for visibility | Medium | Needs logging and tuning; a fixed-domain lab is not a DGA test |
| Network behaviour analysis | Medium to high | Medium to high | Needs a baseline before deviations mean anything |
| EDR | Medium | Low to medium | Limited against a signed passive component |
| MFA and least privilege | Medium | Low | Limits movement, not the initial update |
| SBOM and vendor risk management | Low to medium now | Medium | Gives visibility rather than prevention |

The controls with the most effect are also the hardest to deploy, which is the practical problem with supply-chain defence. A customer cannot verify a build it did not perform, and a supplier cannot prove a build was clean without records the attacker could not alter.

## 9. Academic literature

Six peer-reviewed papers cover the stages the lab touches.

in-toto (USENIX Security 2019) checks that authorised actors performed the expected steps in a supply chain and that materials and products match recorded evidence. The authors mapped it retrospectively to 30 historical compromises. It addresses the gap SUNSPOT exploited, with the caveat that it depends on trusted policy, keys, and redundant builds [29].

The Backstabber's Knife Collection (DIMVA 2020) analysed 469 malicious packages in npm, PyPI, and RubyGems, and studied 174 of them. Trusted distribution can carry malicious code, and conditional execution makes it hard to observe. The sample is open source, so it supports the trust failure but not the build compromise [30].

The SoK taxonomy by Ladisa et al. (IEEE S&P 2023) separates build-time compromise from distribution and maps 107 attack vectors to safeguards. It places the lab's scenario and Task 7's controls, but its mappings are not test results [31].

Gokkaya et al. (JISA 2026) reviewed the supply-chain literature and argues for prioritising controls by risk rather than applying all of them. It frames the mitigation discussion and does not evaluate SolarWinds defences [32].

Benedetti et al. (ICSE 2025) measured reproducibility across six package ecosystems. A signature says nothing about the build behind it, and an independent rebuild gives a comparison point. The paper does not perform that comparison, and reproducibility does not prove benign code [33].

Manasrah et al. (JKSU-CIS 2022) detected DGA domains from lexical features of query names. SUNBURST used DNS for control, so query-name telemetry is worth monitoring. The study analyses registrable domains, not subdomains or CNAME targets, so it supports check-in monitoring but not the handoff the lab demonstrates [34].

Two conclusions follow. A signature identifies the signer; provenance and rebuilds address the build. DNS monitoring shows behaviour; it does not show how an artifact was produced. Neither layer replaces the other.

## 10. Research question

The literature does not test provenance verification, independent rebuilding, and DNS monitoring together in a SolarWinds-style lab, and the PoC implements none of them as defences. That gap gives the question:

**How effectively can independent build-artifact verification and DNS activity monitoring detect different stages of a compromised but legitimately signed software-update workflow in a controlled Mininet/Docker simulation?**

Three sub-questions separate the stages. Before release, can an independently generated reference artifact or a trusted provenance policy distinguish the tampered V3 from an approved release when both pass signature checks? After installation, can DNS logging reveal the check-in and CNAME handoff, and can a stated rule separate them from benign lab traffic? And which stages remain invisible when either control is used alone?

The evaluation would run a baseline approved update, the tampered update, an artifact comparison, DNS monitoring on labelled runs, and both controls together, recording detected releases, flagged check-ins, false positives on benign runs, and the stage at which each alert fires. The lab would need benign comparison traffic before any detection rate means anything. If reproducible builds cannot be implemented, an approved-reference comparison is the narrower fallback, and it must not be described as proof of reproducible-build security.

The limits are the lab's: a predefined check-in routine, simplified DNS, no SUNSPOT replacement, no original DGA, and no later-stage malware. Results would describe this environment, not SolarWinds.

## 11. Conclusion

The SolarWinds campaign worked because the attackers did not need to break a defence. They used the supplier's build and signing process, and customers installed the result with every check passing. The lab reproduces that trust failure and the shape of the check-in that followed, and it stops where the intrusion began: no second stage, no lateral movement, no collection.

The defensive lesson is that signatures answer a narrower question than most organisations assume. Build isolation, provenance records, and independent verification act before the signature exists. DNS and network monitoring act after installation. The literature supports both, and none of the papers shows the combination tested in a lab like this one, which is what the research question proposes to do.

---

## References

1. MITRE ATT&CK. "APT29." Group G0016. https://attack.mitre.org/groups/G0016/
2. U.S., Australian, Canadian, New Zealand, and UK cybersecurity authorities. "Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure." Joint Cybersecurity Advisory AA22-110A, 20 April 2022. https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a
3. ESET. "Operation Ghost Hunt: The DNC hacking group 'Dukes' still attacks government targets, ESET discovers." 17 October 2019. https://www.eset.com/us/about/newsroom/press-releases/operation-ghost-hunt-the-dnc-hacking-group-dukes-still-attacks-government-targets-eset-discovers-1/
4. Dmitri Alperovitch, CrowdStrike. "Bears in the Midst: Intrusion Into the Democratic National Committee." 14 June 2016. https://www.crowdstrike.com/en-us/blog/bears-midst-intrusion-democratic-national-committee/
5. UK NCSC and Communications Security Establishment Canada. "Advisory: APT29 targets COVID-19 vaccine development." 16 July 2020. https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development
6. FireEye/Mandiant. "Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor." 13 December 2020. https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
7. Stephen Eckels, Jay Smith, William Ballenthin, Mandiant. "SUNBURST Additional Technical Details." 24 December 2020. https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details
8. CrowdStrike Intelligence. "SUNSPOT: An Implant in the Build Process." 11 January 2021. https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/
9. Microsoft. "Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop." 20 January 2021. https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
10. SolarWinds. "SolarWinds Investigation Update." SEC filing, 7 May 2021. https://www.sec.gov/Archives/edgar/data/1739942/000173994221000076/swi-20210507.htm
11. U.S. Government Accountability Office. "SolarWinds Cyberattack Demands Significant Federal and Private-Sector Response." GAO-22-104746, 2022. https://www.gao.gov/products/gao-22-104746
12. Task 5 lab. `tasks/task05-poc`, commit `7c99000`. Playbook, runbook, and sample manifest.
13. CISA. "Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations." AA20-352A, 17 December 2020, updated 15 April 2021. https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
14. U.S. Securities and Exchange Commission. "In the Matter of Mimecast Limited." Release 33-11322, 22 October 2024. https://www.sec.gov/files/litigation/admin/2024/33-11322.pdf
15. Mimecast. FY2021 Form 10-K. Filed 27 May 2021. https://www.sec.gov/Archives/edgar/data/1644675/000156459021030433/mime-10k_20210331.htm
16. U.S. Department of Justice, Office of Privacy and Civil Liberties. "Department of Justice Statement on the intrusion into the Department's Microsoft O365 email environment." Updated 12 October 2022. https://www.justice.gov/opcl/department-justice-statement-intrusion-department-s-microsoft-o365-email-environment
17. U.S. Department of Justice. "Comprehensive Cyber Review." July 2022. https://www.justice.gov/usdoj-media/dag/media/1232936/dl?inline=
18. U.S. Securities and Exchange Commission. "In the Matter of Check Point Software Technologies Ltd." Release 33-11321, 22 October 2024. https://www.sec.gov/files/litigation/admin/2024/33-11321.pdf
19. FireEye Threat Intelligence. "HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group." July 2015. https://services.google.com/fh/files/misc/rpt-apt29-hammertoss-stealthy-tactics-define-en.pdf
20. CISA, FBI, and DHS. "Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders." AA21-116A, 26 April 2021. https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a
21. Tom Burt, Microsoft. "Another Nobelium cyberattack." 27 May 2021. https://blogs.microsoft.com/on-the-issues/2021/05/27/nobelium-cyberattack-nativezone-solarwinds/
22. Military Counterintelligence Service (SKW) and CERT Polska. "Espionage campaign linked to Russian intelligence services." 13 April 2023. https://www.gov.pl/web/baza-wiedzy/espionage-campaign-linked-to-russian-intelligence-services
23. Unit 42, Palo Alto Networks. "Diplomats Beware: Cloaked Ursa Phishing With a Twist." 12 July 2023, updated 20 July 2023. https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/
24. Microsoft Threat Intelligence. "Midnight Blizzard conducts targeted social engineering over Microsoft Teams." 2 August 2023. https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/
25. Luke Jenkins and Dan Black, Mandiant. "APT29 Uses WINELOADER to Target German Political Parties." 22 March 2024. https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties
26. Microsoft Threat Intelligence. "Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files." 29 October 2024. https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/
27. Check Point Research. "Renewed APT29 Phishing Campaign Against European Diplomats." 15 April 2025. https://research.checkpoint.com/2025/apt29-phishing-campaign/
28. CISA. "Defending Against Software Supply Chain Attacks." April 2021. https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_508_1.pdf
29. S. Torres-Arias, H. Afzali, T. K. Kuppusamy, R. Curtmola, and J. Cappos. "in-toto: Providing farm-to-table guarantees for bits and bytes." 28th USENIX Security Symposium, pp. 1393-1410, 2019. https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias
30. M. Ohm, H. Plate, A. Sykosch, and M. Meier. "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks." DIMVA 2020, LNCS 12223, pp. 23-43. https://doi.org/10.1007/978-3-030-52683-2_2
31. P. Ladisa, H. Plate, M. Martinez, and O. Barais. "SoK: Taxonomy of Attacks on Open-Source Software Supply Chains." 2023 IEEE Symposium on Security and Privacy, pp. 1509-1526. https://doi.org/10.1109/SP46215.2023.10179304
32. B. Gokkaya, L. Aniello, and B. Halak. "Software supply chain: A taxonomy of attacks, mitigations and risk assessment strategies." Journal of Information Security and Applications, vol. 97, art. 104324, 2026. https://doi.org/10.1016/j.jisa.2025.104324
33. G. Benedetti et al. "An Empirical Study on Reproducible Packaging in Open-Source Ecosystems." ICSE 2025, pp. 1052-1063. https://doi.org/10.1109/ICSE55347.2025.00136
34. A. M. Manasrah, T. Khdour, and R. Freehat. "DGA-based botnets detection using DNS traffic mining." Journal of King Saud University - Computer and Information Sciences, vol. 34, no. 5, pp. 2045-2061, 2022. https://doi.org/10.1016/j.jksuci.2022.03.001
35. Mandiant. "UNC2452 Merged into APT29." 2021. https://cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-into-apt29
36. CISA, FBI, NSA, SKW, CERT Polska, and NCSC. "Russian Foreign Intelligence Service (SVR) Exploiting JetBrains TeamCity CVE Globally." AA23-347A, 13 December 2023. https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
