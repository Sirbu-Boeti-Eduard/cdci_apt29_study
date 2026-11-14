# CDCI APT29 Study

## 1. Project Overview and Role

This repository is the team's shared workspace for CDCI Assignment 1 — Tracking an APT Group. The study focuses on APT29 and uses the SUNBURST/SolarWinds incident as a technical case study.

The project brings together open-source threat intelligence, technical analysis, a controlled Mininet/Docker proof of concept, countermeasures, academic research, and the final report and presentation. The repository organizes the research and supporting evidence so the team can build a clear, source-backed account of the actor and its activity. The PoC work belongs in an isolated lab environment.

The original assignment brief is included at the repository root: [APT group attack recreation (2025-2026).pdf](./APT%20group%20attack%20recreation%20%282025-2026%29.pdf).

## 2. Colleagues and Team

## 3. Project Directories and Structure

```text
cdci_apt29_study/
├── .agents/
│   └── skills/                 # Repository-specific agent skills
├── deliverables/
│   ├── presentation/           # Final presentation
│   └── report/                 # Final report (LaTeX)
├── tasks/
│   ├── task01-history/         # APT history
│   ├── task02-ttp/             # TTPs, tools, malware, vulnerabilities, apps, protocols
│   ├── task03-cti/             # Online presence and cyber threat intelligence
│   ├── task04-victims/         # Victims and business impact
│   ├── task05-poc/             # Controlled Mininet/Docker proof of concept and demo
│   ├── task06-writeup/         # Attack-step write-up
│   ├── task07-mitigation/      # Countermeasures and deployment difficulty
│   ├── task08-papers/           # Peer-reviewed literature
│   └── task09-rqs/              # Research question
├── APT group attack recreation (2025-2026).pdf
└── README.md
```

## 4. Attacker Summary

### Introduction

- **APT29**
  - A Russian cyber-espionage group attributed to Russia's Foreign Intelligence Service (SVR). [MITRE ATT&CK](https://attack.mitre.org/groups/G0016/)
  - Early reporting called the SolarWinds activity **UNC2452**; Mandiant later attributed it to APT29. [Mandiant attribution update](https://cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-into-apt29)
- **SolarWinds**
  - A software company that makes IT management tools.
  - Its Orion platform helped IT teams monitor and manage networks, servers, applications, and other infrastructure from a central view. [SolarWinds Orion Platform datasheet](https://www.solarwinds.com/assets/solarwinds/swdcv2/licensed-products/orion/resources/datasheets/orion-platform-datasheet.pdf)
- **SUNBURST**
  - A backdoor hidden in a trusted, digitally signed Orion component distributed through legitimate software updates.
  - After installation, it waited before contacting attacker-controlled infrastructure; selected victims could then receive follow-on commands. [Google/Mandiant technical report](https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details)
- **Impact**
  - Nearly 18,000 customers may have received the compromised update. GAO reported SolarWinds estimated fewer than 100 customers were actually compromised; nine U.S. federal agencies were reported compromised. [GAO report](https://www.gao.gov/products/gao-22-104746)
  - In selected victims, attackers moved through networks and stole data for espionage. [Google/Mandiant campaign report](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor)
- **Aftermath**
  - After discovery in December 2020, CISA ordered federal agencies to disconnect affected Orion versions. Government and industry teams investigated and worked to remove the threat. [CISA response timeline](https://www.cisa.gov/sites/default/files/publications/YIR_Combined_040521_508.pdf)

### Stage 0: Build Pipeline Compromise

1. **Initial access:** Public reporting does not establish how the attackers first gained access to SolarWinds' internal network. SolarWinds said it could not determine the exact entry method. [SolarWinds investigation update](https://www.sec.gov/Archives/edgar/data/1739942/000173994221000076/swi-20210507.htm)

2. **Build tampering:** After gaining access to SolarWinds' environment, the attackers used a tool called **SUNSPOT** in the Orion automated build environment. They did not alter the source-code repository. During an Orion build, SUNSPOT temporarily replaced a source file in the build workspace with a version that added the **SUNBURST** backdoor, then restored the original file. [SolarWinds investigation update](https://www.sec.gov/Archives/edgar/data/1739942/000173994221000076/swi-20210507.htm) · [CrowdStrike SUNSPOT analysis](https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/)

3. **Signed update:** The normal software development and release process continued. The resulting Orion component contained SUNBURST, was signed through SolarWinds' legitimate signing process, and was distributed to customers as a regular Orion update. [Google/Mandiant campaign report](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor)

### Stage 1: Installation and Dormancy

1. **Installation:** Customers installed the affected Orion update, and the normal Orion host loaded the trojanized plugin.
2. **Delay and checks:** SUNBURST waited until the plugin was about 12–14 days old, then checked the host environment before network activity. [Google/Mandiant technical report](https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details)
3. **Exposure:** Receiving the affected update indicates exposure; it does not by itself confirm follow-on activity.

### Stage 2: DNS Check-ins and Mode Selection

1. **Victim-identifying lookup:** SUNBURST generated a DGA subdomain containing encoded victim information, such as the organization domain, and queried the DNS coordinator.
2. **Coordinator signal:** The coordinator responded with a DNS A record. SUNBURST interpreted the returned IP range as a signal to stay passive, become active, or disable itself. A CNAME response supplied the final server for HTTP(S) command and control. [Google/Mandiant technical report](https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details)
3. **Modes:**
   - **New (4) — Passive:** continued DNS check-ins and encoded the victim's domain in generated subdomains.
   - **Append (5) — Active:** enabled or continued command and control; generated subdomains encoded the user ID or service information.
   - **Truncate (3) — Disabled:** the killswitch stopped further network activity.

### Stage 3: Active Command and Control

1. **Connection:** Once active, SUNBURST used the CNAME-provided server for HTTP(S) command and control, disguising its traffic as normal Orion Improvement Program (OIP) messages.
2. **Hidden data and tasks:** OIP-like fields that looked like routine telemetry carried encoded information and instructions. Examples included collecting or uploading system details, running a process, or rebooting the computer. [Google/Mandiant technical report](https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details)

### Stage 4: Conclusion — Follow-on Espionage

1. **Use of access:** Operators used the foothold to profile selected victim networks and move laterally using compromised credentials and remote-access tools.
2. **Tools and objective:** In at least one documented case, TEARDROP was used to deploy Cobalt Strike BEACON. The campaign included collecting and stealing data. [Google/Mandiant campaign report](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor)
3. **Conclusion:** The Orion supply-chain compromise gave APT29 a quiet way into customer networks, which it used to conduct targeted espionage.
