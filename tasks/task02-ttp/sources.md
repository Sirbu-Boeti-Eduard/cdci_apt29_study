# Task 02 sources

Every source cited in this folder, with duplicates removed. Mirrors that were opened in place of the original are noted next to it.
Status: **verified** = the source was opened and the claim was found at the location cited in the task file. **UNVERIFIED** = it could not be opened from our environment; check by hand before using it.
"Used in" lists the task02 files that cite the source: TTPs = `solarwinds-ttps.md`, Tools = `apt29-tools.md`, CVEs = `vulnerabilities-apps-protocols.md`, IOCs = `iocs.md`.

Core sources for the report and slides:
- Mandiant, "SUNBURST Additional Technical Details" (the course reference report)
- MITRE ATT&CK G0016 / C0024
- CISA AA20-352A
- CrowdStrike, "SUNSPOT: An Implant in the Build Process"
- NSA/CISA/FBI, "Russian SVR Targets U.S. and Allied Networks" (April 2021)

## Framework and base data

| Source | URL | Used in | Status |
|---|---|---|---|
| MITRE ATT&CK, Group G0016 APT29 | https://attack.mitre.org/groups/G0016/ | all | verified |
| MITRE ATT&CK, Campaign C0024 SolarWinds Compromise | https://attack.mitre.org/campaigns/C0024/ | TTPs | verified |
| MITRE ATT&CK, Campaign C0023 Operation Ghost | https://attack.mitre.org/campaigns/C0023/ | Tools | verified |
| MITRE ATT&CK Enterprise STIX data v20.1 (2026-11-05), the base extract for all four files | https://github.com/mitre-attack/attack-stix-data | all | verified |

## SolarWinds / SUNBURST campaign

| Source | URL | Used in | Status |
|---|---|---|---|
| Mandiant (S. Eckels, J. Smith, W. Ballenthin), "SUNBURST Additional Technical Details", 24 Dec 2020. **Course reference report.** | https://cloud.google.com/blog/topics/threat-intelligence/sunburst-additional-technical-details | TTPs, IOCs | verified |
| FireEye/Mandiant, "Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor", 13 Dec 2020 | https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor | TTPs, IOCs | verified |
| CrowdStrike Intelligence, "SUNSPOT: An Implant in the Build Process", 11 Jan 2021 | https://crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis | TTPs, IOCs | verified |
| SolarWinds (S. Ramakrishna), "New Findings From Our Investigation of SUNBURST", 11 Jan 2021 | https://www.solarwinds.com/blog/new-findings-from-our-investigation-of-sunburst | TTPs | verified |
| SolarWinds, Security Advisory (affected Orion versions) | https://www.solarwinds.com/sa-overview/securityadvisory | IOCs | verified |
| CISA, AA20-352A "Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations", 17 Dec 2020 (updated 15 Apr 2021) | https://www.cisa.gov/uscert/ncas/alerts/aa20-352a | TTPs, CVEs, IOCs | verified |
| CISA, Emergency Directive 21-01 and supplemental guidance | https://www.cisa.gov/emergency-directive-21-01 | IOCs | verified |
| Microsoft, "Analyzing Solorigate, the compromised DLL file that started a sophisticated cyberattack", 18 Dec 2020 | https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/ | IOCs | verified |
| Microsoft (MSTIC, CDOC, M365 Defender Research), "Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop", 20 Jan 2021 | https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/ | TTPs, IOCs | verified |
| Microsoft 365 Defender Team, "Using Microsoft 365 Defender to protect against Solorigate", 28 Dec 2020 | https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/ | TTPs | verified |
| MSRC, "Customer Guidance on Recent Nation-State Cyber Attacks", 13/14 Dec 2020 | https://www.microsoft.com/msrc/blog/2020/12/customer-guidance-on-recent-nation-state-cyber-attacks | TTPs | verified |
| Microsoft (R. Nafisi, A. Lelli), "GoldMax, GoldFinder, and Sibot: Analyzing NOBELIUM's layered persistence", 4 Mar 2021 | https://microsoft.com/en-us/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware | TTPs | verified |
| Symantec Threat Hunter Team, "Raindrop: New Malware Discovered in SolarWinds Investigation", 18 Jan 2021 | https://www.security.com/solarwinds/solarwinds-raindrop-malware-0 | TTPs, IOCs | verified |
| Volexity (D. Cash et al.), "Dark Halo Leverages SolarWinds Compromise to Breach Organizations", 14 Dec 2020 | https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/ | TTPs, CVEs | verified |
| CrowdStrike, "Early Bird Catches the Wormhole: Observations from the StellarParticle Campaign", 27 Jan 2022 | https://www.crowdstrike.com/en-us/blog/observations-from-the-stellarparticle-campaign/ | TTPs | verified |
| Mandiant, "Remediation and Hardening Strategies for Microsoft 365 to Defend Against APT29" (white paper v1.3) | https://services.google.com/fh/files/misc/remediation-and-hardening-strategies-for-microsoft-wp-en.pdf | TTPs | verified |
| Netresec, "Reassembling Victim Domain Fragments from SUNBURST DNS" (SunburstDomainDecoder), 17 Dec 2020 | https://netresec.com/?b=20C0f71 | IOCs | verified |

## Government advisories on APT29 / SVR

| Source | URL | Used in | Status |
|---|---|---|---|
| NSA/CISA/FBI, "Russian SVR Targets U.S. and Allied Networks" (U/OO/132340-21), 15 Apr 2021 | https://media.defense.gov/2021/apr/15/2002621240/-1/-1/0/csa_svr_targets_us_allies_uoo13234021.pdf | CVEs | verified |
| CISA/FBI/DHS, AA21-116A "Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders", 26 Apr 2021 | https://us-cert.cisa.gov/ncas/alerts/aa21-116a | CVEs | verified |
| NCSC/CISA/FBI/NSA, "Further TTPs associated with SVR cyber actors", v1.0, 7 May 2021 (opened via AHA mirror: https://www.aha.org/system/files/media/file/2021/05/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf) | https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf | Tools, CVEs | verified |
| NCSC (UK) and CSE (Canada), with NSA and CISA, "Advisory: APT29 targets COVID-19 vaccine development" V1.1, 16 Jul 2020 | https://www.ncsc.gov.uk/sites/default/files/documents/Advisory-APT29-targets-COVID-19-vaccine-development-V1-1.pdf | Tools, CVEs | verified (WellMail port 25 and SoreFang/SangFor details UNVERIFIED) |
| CISA/FBI/NSA/SKW/CERT Polska/NCSC, AA23-347A "Russian Foreign Intelligence Service (SVR) Exploiting JetBrains TeamCity CVE Globally", 13 Dec 2023 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a | Tools, CVEs, IOCs | verified |
| CERT Polska, APT29 TeamCity post, Dec 2023 | https://cert.pl/en/posts/2023/12/apt29-teamcity/ | CVEs | verified |
| NCSC/CISA/NSA/FBI et al., AA24-057A "SVR cyber actors adapt tactics for initial cloud access", 26 Feb 2024 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a | Tools, CVEs | verified |
| FBI/NSA/CNMF/NCSC-UK, "Update on SVR Cyber Operations and Vulnerability Exploitation" (JCSA-20241010-001), 10 Oct 2024 | https://www.ic3.gov/CSA/2024/241010.pdf | CVEs | verified |
| SKW & CERT Polska, "Espionage campaign linked to Russian intelligence services", 13 Apr 2023 | https://www.gov.pl/web/baza-wiedzy/espionage-campaign-linked-to-russian-intelligence-services | Tools | verified |
| NSDC of Ukraine (RNBO), "APT29 attacks Embassies using CVE-2023-38831", Nov 2023 (news item: https://www.rnbo.gov.ua/en/Diialnist/6708.html) | https://www.rnbo.gov.ua/files/2023_YEAR/CYBERCENTER/november/APT29%20attacks%20Embassies%20using%20CVE-2023-38831%20-%20report%20en.pdf | CVEs | verified |

## APT29 tools and campaigns (vendor research)

| Source | URL | Used in | Status |
|---|---|---|---|
| F-Secure Labs, "The Dukes: 7 years of Russian cyberespionage", Sep 2015 (opened via WithSecure mirror: https://www.withsecure.com/wp-content/uploads/2026/05/dukes-whitepaper.pdf) | https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf | Tools, CVEs | verified |
| F-Secure, "The Dukes: 7 years of Russian cyber-espionage" (blog), 2015 | https://blog.f-secure.com/the-dukes-7-years-of-russian-cyber-espionage | CVEs | verified |
| F-Secure, weblog post on MiniDuke, 1 Apr 2014 (original dead; opened via Internet Archive mirror) | http://web.archive.org/web/20190905091001/https://www.f-secure.com/weblog/archives/00002688.html | CVEs | verified |
| Kaspersky GReAT, "The MiniDuke Mystery: PDF 0-day Government Spy Assembler 0x29A Micro Backdoor", Feb 2013 | https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/ | CVEs | verified |
| FireEye Threat Intelligence, "HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group", Jul 2015 | https://services.google.com/fh/files/misc/rpt-apt29-hammertoss-stealthy-tactics-define-en.pdf | Tools | verified |
| Mandiant, "Dissecting One of APT29's Fileless WMI and PowerShell Backdoors (POSHSPY)", 3 Apr 2017 | https://cloud.google.com/blog/topics/threat-intelligence/dissecting-one-ofap/ | Tools | verified |
| Mandiant (M. Dunwoody), "APT29 Domain Fronting With TOR", 27 Mar 2017 | https://cloud.google.com/blog/topics/threat-intelligence/apt29-domain-frontin | Tools, CVEs | verified |
| FireEye, "Not So Cozy: An Uncomfortable Examination of a Suspected APT29 Phishing Campaign", 19 Nov 2018 | https://cloud.google.com/blog/topics/threat-intelligence/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign | Tools | verified |
| ESET (M. Faou, M. Tartare, T. Dupuy), "Operation Ghost: The Dukes aren't back – they never left" (whitepaper), Oct 2019 | https://www.welivesecurity.com/wp-content/uploads/2019/10/ESET_Operation_Ghost_Dukes.pdf | Tools | verified |
| ESET, "Operation Ghost: The Dukes never left" (blog), 17 Oct 2019 | https://www.welivesecurity.com/2019/10/17/operation-ghost-dukes-never-left/ | Tools | verified |
| MSTIC, "New sophisticated email-based attack from NOBELIUM", 27 May 2021 | https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/ | Tools, CVEs | verified |
| MSTIC, "Breaking down NOBELIUM's latest early-stage toolset", 28 May 2021 | https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/ | Tools | verified |
| MSRC, "New Nobelium activity", 25 Jun 2021 | https://www.microsoft.com/en-us/msrc/blog/2021/06/new-nobelium-activity | Tools, CVEs | verified |
| Microsoft, "FoggyWeb: Targeted NOBELIUM malware leads to persistent backdoor", 27 Sep 2021 | https://www.microsoft.com/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor | Tools, CVEs | verified |
| MSTIC, "NOBELIUM targeting delegated administrative privileges to facilitate broader attacks", 25 Oct 2021 | https://www.microsoft.com/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/ | Tools, CVEs | verified |
| ESET, "ESET Threat Report T3 2021", 9 Feb 2022 (summary: https://www.welivesecurity.com/2022/02/09/eset-threat-report-t32021/) | https://ccinfo.nl/_downloads/4fd7042d7a6b564c00d3abcac9260210 | CVEs | verified |
| Mandiant, "Tracking APT29 Phishing Campaigns", Apr 2022 | https://cloud.google.com/blog/topics/threat-intelligence/tracking-apt29-phishing-campaigns/ | Tools | verified |
| Mandiant, "UNC3524: Eye Spy on Your Email", 2 May 2022 (merge note Nov 2022) | https://cloud.google.com/blog/topics/threat-intelligence/unc3524-eye-spy-email/ | Tools, CVEs | verified |
| Mandiant, "APT29 Continues Targeting Microsoft 365", 2022 | https://cloud.google.com/blog/topics/threat-intelligence/apt29-continues-targeting-microsoft/ | Tools, CVEs | verified |
| Mandiant, blog post on APT29 abuse of Windows Credential Roaming, 2022 | https://cloud.google.com/blog/topics/threat-intelligence/apt29-windows-credential-roaming | CVEs | verified |
| Microsoft, "MagicWeb: NOBELIUM's post-compromise trick to authenticate as anyone", 24 Aug 2022 | https://www.microsoft.com/security/blog/2022/08/24/magicweb-nobeliums-post-compromise-trick-to-authenticate-as-anyone/ | Tools | verified |
| Palo Alto Unit 42, "Cloaked Ursa: Online Storage Services Campaigns", 2022 | https://unit42.paloaltonetworks.com/cloaked-ursa-online-storage-services-campaigns/ | CVEs | verified |
| Mandiant, APT29 diplomatic phishing report (URL slug "apt29-evolving-diplomatic-phishing"; full title to confirm) | https://cloud.google.com/blog/topics/threat-intelligence/apt29-evolving-diplomatic-phishing?hl=en | Tools | verified |
| MSTIC, "Midnight Blizzard conducts targeted social engineering over Microsoft Teams", Aug 2023 | https://www.microsoft.com/en-us/security/blog/?p=131208 | Tools, CVEs | verified |
| Microsoft Threat Intelligence, "Midnight Blizzard: Guidance for responders on nation-state attack", 25 Jan 2024 | https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/ | Tools, CVEs | verified |
| Mandiant, "APT29 Uses WINELOADER to Target German Political Parties", 22 Mar 2024 | https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties | Tools, IOCs | verified |
| Microsoft Threat Intelligence, "Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files", 29 Oct 2024 | https://microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files | Tools, CVEs, IOCs | verified |
| Check Point Research, "Unmasking APT29: The Sophisticated Phishing Campaign Targeting European Diplomacy", Apr 2025 | https://research.checkpoint.com/2025/apt29-phishing-campaign/ | Tools | verified |
| Volexity, "Multiple Russian Threat Actors Targeting Microsoft Device Code Authentication", 13 Feb 2025 | https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/ | Tools, CVEs | verified |
| Google Threat Intelligence Group, "Creative phishing: academics and critics of Russia" (UNC6293), Jun 2025 | https://cloud.google.com/blog/topics/threat-intelligence/creative-phishing-academics-critics-of-russia | CVEs | verified |

## Vulnerabilities

| Source | URL | Used in | Status |
|---|---|---|---|
| Google TAG, "How we protect users from 0-day attacks", Jul 2021 | https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks/ | CVEs | verified |
| Google TAG, "State-backed attackers and commercial surveillance vendors repeatedly use the same exploits", 29 Aug 2024 | https://blog.google/threat-analysis-group/state-backed-attackers-and-commercial-surveillance-vendors-repeatedly-use-the-same-exploits/ | CVEs | verified |
| CERT/CC, VU#843464 "SolarWinds Orion API authentication bypass", 26 Dec 2020 (not APT29: context for CVE-2020-10148) | https://kb.cert.org/vuls/id/843464 | CVEs | verified |
| Sophos (Secureworks CTU), "SUPERNOVA web shell deployment linked to SPIRAL threat group" (not APT29) | https://www.sophos.com/en-us/blog/supernova-web-shell-deployment-linked-to-spiral-threat-group | CVEs | verified |
| CVSS scores: NVD records, read from a GitHub mirror of NVD because nvd.nist.gov was blocked here | https://nvd.nist.gov/ | CVEs | verified (the quoted scores match the NVD CVSS v3.1 base scores) |
| CISA Known Exploited Vulnerabilities catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | CVEs | verified |

## Detection content (repositories)

| Source | URL | Used in | Status |
|---|---|---|---|
| Mandiant, sunburst_countermeasures (YARA, Snort, HXIOC, indicator CSVs), HEAD 5e238b2 | https://github.com/mandiant/sunburst_countermeasures | IOCs | verified |
| Azure/Azure-Sentinel (Solorigate hunting queries) | https://github.com/Azure/Azure-Sentinel | IOCs | verified |
| SigmaHQ/sigma (SUNBURST-related rules) | https://github.com/SigmaHQ/sigma | IOCs | verified |

## Secondary sources (news, lower weight; use only to cross-check)

| Source | URL | Used in | Status |
|---|---|---|---|
| KrebsOnSecurity, "Malicious Domain in SolarWinds Hack Turned into 'Killswitch'", 16 Dec 2020 | https://krebsonsecurity.com/2020/12/malicious-domain-in-solarwinds-hack-turned-into-killswitch/ | IOCs | verified |
| Security Affairs, "FireEye, GoDaddy, and Microsoft created a kill switch for SolarWinds backdoor", 17 Dec 2020 | https://securityaffairs.com/112376/apt/solarwinds-backdoor-kill-switch.html | IOCs | verified |
| BleepingComputer, "US think tank breached three times in a row by SolarWinds hackers", Dec 2020 | https://www.bleepingcomputer.com/news/security/us-think-tank-breached-three-times-in-a-row-by-solarwinds-hackers/ | CVEs | verified |
| Infosecurity Magazine, "Russian Hackers Target Microsoft 365 Accounts with Device Code Phishing", Feb 2025 | https://www.infosecurity-magazine.com/news/russian-microsoft-device-code/ | Tools | verified |
| CyberScoop, Russian threat groups' device code phishing of Microsoft accounts, 14 Feb 2025 | https://cyberscoop.com/russia-threat-groups-device-code-phishing-microsoft-accounts/ | CVEs | verified |
