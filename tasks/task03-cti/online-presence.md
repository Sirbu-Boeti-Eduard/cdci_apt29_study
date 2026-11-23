Written by: Teodor Maciuca

------------------
Finding (source-reported): FireEye reported in 2015 that the APT29 backdoor HAMMERTOSS took its instructions from Twitter. The malware generated a new Twitter handle each day, and APT29 operators registered that day's handle only when they wanted to send a command. The tweet carried a URL and a hashtag. The URL pointed to a page, in FireEye's example on GitHub, holding an image with encrypted instructions appended to it. The hashtag gave the offset of the hidden data and part of the decryption key. FireEye also observed URLs leading to compromised websites, and stolen data was uploaded to cloud storage accounts that the operators created.

Attribution: FireEye coined the name APT29 and assigned HAMMERTOSS to it; in 2015 it described the group only as suspected to be sponsored by the Russian government. MITRE ATT&CK lists HAMMERTOSS as APT29 software (S0037).

See also: [task02 tool catalogue](../task02-ttp/apt29-tools.md), "Notes by era."

References:
- [FireEye Threat Intelligence, "HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group"](https://services.google.com/fh/files/misc/rpt-apt29-hammertoss-stealthy-tactics-define-en.pdf), July 2015, p. 3 (introduction), p. 7 (Stage 1, Figure 1), p. 8 (Stage 2, Figure 2), p. 10 (Stage 3, Figure 4), and p. 12 (cloud storage upload).
- [MITRE ATT&CK, "APT29" (G0016)](https://attack.mitre.org/groups/G0016/), "Software" table, HAMMERTOSS (S0037).

------------------
Finding (source-reported): A 2021 U.S. advisory on SVR cyber operations states that infrastructure used in the intrusions is frequently obtained using false identities and cryptocurrencies. It adds that these identities are usually supported by low-reputation infrastructure such as temporary email accounts, that a number of SVR cyber personas use email services hosted on `cock[.]li` or related domains, and that VPS infrastructure is often procured from a network of VPS resellers.

Finding (team interpretation): We found no government or vendor report that names a specific cryptocurrency wallet or payment used by APT29. The advisory above confirms that the SVR pays for infrastructure with cryptocurrency but gives no addresses or amounts. For the grading item on crypto wallets, the honest answer is that public reporting describes the practice without exposing wallets.

Attribution: U.S. government. The advisory's summary identifies "SVR cyber actors" as also known as APT 29, the Dukes, CozyBear, and Yttrium.

References:
- [CISA, FBI, and DHS, "Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders"](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a), Joint Cybersecurity Advisory AA21-116A, 26 April 2021, "Summary" and "General Tradecraft Observations."

------------------
Finding (source-reported): Microsoft reported that NOBELIUM (APT29) gained access to the Constant Contact account of USAID and used the mass-mailing service to send phishing emails posing as a USAID alert. The campaign targeted about 3,000 accounts at more than 150 organizations. Microsoft traced its earliest testing to 28 January 2021. The emails showed `ashainfo@usaid.gov` as the sender, while the real sending address ended in `in.constantcontact.com`. Links passed through Constant Contact's redirector `r20.rs6[.]net` to the actor-controlled `usaid.theyardservice[.]com`, and subject lines used variants of "Special Alert!".

Attribution: Microsoft, under its name NOBELIUM. MITRE ATT&CK lists NOBELIUM as an associated name for APT29.

References:
- [Tom Burt, Microsoft, "Another Nobelium cyberattack"](https://blogs.microsoft.com/on-the-issues/2021/05/27/nobelium-cyberattack-nativezone-solarwinds/), 27 May 2021, second paragraph (access to USAID's Constant Contact account).
- [Microsoft Threat Intelligence Center, "New sophisticated email-based attack from NOBELIUM"](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/), 27 May 2021, introduction, "Early testing and initial discovery," "Escalated targeting and delivery," and "Advanced hunting."
- [MITRE ATT&CK, "APT29" (G0016)](https://attack.mitre.org/groups/G0016/), "Associated Groups."

------------------
Finding (source-reported): Poland's Military Counterintelligence Service and CERT Polska reported a 2023 campaign in which emails impersonating embassies of European countries reached staff at diplomatic posts. The emails invited recipients to a meeting or to work together on documents. The link led to a compromised website running the ENVYSCOUT script, which used HTML smuggling to deliver ISO or IMG disk images. The report says the actor prefers vulnerable websites belonging to random entities for its infrastructure, and that the SNOWYAMBER tool abused the Notion service to communicate.

Attribution: Polish government. The headline attributes the campaign only to "Russian intelligence services"; the body links the activity to what Microsoft calls NOBELIUM and Mandiant calls APT29, and to the SolarWinds campaign.

References:
- [Military Counterintelligence Service (SKW) and CERT Polska, "Espionage campaign linked to Russian intelligence services"](https://www.gov.pl/web/baza-wiedzy/espionage-campaign-linked-to-russian-intelligence-services), 13 April 2023, "The course of the observed campaigns" and "Tools used during the campaign."

------------------
Finding (source-reported): Unit 42 reported that in mid-April 2023 a diplomat at the Polish Ministry of Foreign Affairs emailed a genuine flyer advertising a used BMW 5-series in Kyiv. Cloaked Ursa likely obtained the flyer and, on 4 May 2023, sent altered copies to diplomatic missions in Kyiv. The altered flyer offered "more high quality photos" through a shortened link that downloaded shortcut files disguised as images. Unit 42 counted at least 22 of over 80 foreign missions in Kyiv as targets. The payload's command and control used the Microsoft Graph and Dropbox APIs.

Attribution: Unit 42, under its name Cloaked Ursa, which it equates with APT29. The basis is similarity to known campaigns and targets, known techniques, and code overlap with other Cloaked Ursa malware. MITRE ATT&CK's list of associated names for APT29 does not include Cloaked Ursa, so this equivalence rests on Unit 42 alone.

References:
- [Unit 42, Palo Alto Networks, "Diplomats Beware: Cloaked Ursa Phishing With a Twist"](https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/), 12 July 2023 (updated 20 July 2023), "Executive Summary" and "BMW for Sale."

------------------
Finding (source-reported): Microsoft reported that Midnight Blizzard used compromised Microsoft 365 tenants to create new `onmicrosoft.com` domains with security-themed names, such as `msftprotection.onmicrosoft[.]com`, `identityverification.onmicrosoft[.]com`, and `teamsprotection.onmicrosoft[.]com`. From these, the actor sent Microsoft Teams chat requests posing as technical support or a security team and asked users to enter a code into the Microsoft Authenticator app on their phone. The campaign affected fewer than 40 organizations in government, NGO, IT services, technology, discrete manufacturing, and media sectors.

Attribution: Microsoft, under its name Midnight Blizzard. MITRE ATT&CK lists Midnight Blizzard as an associated name for APT29.

See also: [task02 applications and platforms](../task02-ttp/vulnerabilities-apps-protocols.md), section 2.

References:
- [Microsoft Threat Intelligence, "Midnight Blizzard conducts targeted social engineering over Microsoft Teams"](https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/), 2 August 2023, "Midnight Blizzard's latest credential phishing attack," "Use of security-themed domain names in lures," "Social engineering attack chain," and "Indicators of compromise."
- [MITRE ATT&CK, "APT29" (G0016)](https://attack.mitre.org/groups/G0016/), "Associated Groups."

------------------
Finding (source-reported): Mandiant reported that from as early as 26 February 2024 APT29 sent German political parties phishing emails inviting recipients to a dinner reception on 1 March, bearing the logo of the Christian Democratic Union (CDU). The link pointed to a ZIP file with the ROOTSAW dropper on a compromised WordPress site under the actor's control. The same site later served the WINELOADER backdoor.

Attribution: Mandiant, which names APT29 directly. The post gives no formal confidence level.

See also: the delivery and control domains are listed in [task02 IOCs](../task02-ttp/iocs.md), section 6.

References:
- [Luke Jenkins and Dan Black, Mandiant, "APT29 Uses WINELOADER to Target German Political Parties"](https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties), 22 March 2024, "Threat Detail" (Figure 1) and "Technical Annex," subsection "Initial Access."

------------------
Finding (source-reported): Microsoft reported that from 22 October 2024 Midnight Blizzard sent spear-phishing emails to thousands of targets in over 100 organizations, mainly government, higher education, defense, and NGOs in the United Kingdom, Europe, Australia, and Japan. The emails came from addresses of legitimate organizations that the actor had compromised earlier, used lures about Microsoft, Amazon Web Services, and Zero Trust, and attached Remote Desktop Protocol files signed with a Let's Encrypt certificate. Opening a file connected the victim's computer to an attacker-controlled server and exposed local files, network drives, clipboard data, and connected devices.

Attribution: Microsoft, under its name Midnight Blizzard. Microsoft notes that CERT-UA reported overlapping activity under its own label UAC-0215; that label is CERT-UA's tracking name and should not be read as a separate attribution to APT29.

See also: sender and server domains are listed in [task02 IOCs](../task02-ttp/iocs.md), section 6.

References:
- [Microsoft Threat Intelligence, "Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files"](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/), 29 October 2024, introduction, "Spear-phishing campaign," "RDP connection," "Targets," and "Email infrastructure."

------------------
Finding (source-reported): Check Point Research reported that from January 2025 an actor impersonated a European Ministry of Foreign Affairs in emails inviting diplomats to wine-tasting events and diplomatic dinners. The emails came from at least two domains, `bakenhof[.]com` and `silry[.]com`. The link downloaded `wine.zip`, which started the GRAPELOADER loader, but only under certain conditions such as time or location; otherwise it redirected to the ministry's real website.

Attribution (uncertain): Check Point links the campaign to APT29 through its overlap with the 2024 WINELOADER campaigns and through code similarities, and gives no formal confidence level. This is the weakest attribution in this file.

References:
- [Check Point Research, "Unmasking APT29: The Sophisticated Phishing Campaign Targeting European Diplomacy"](https://research.checkpoint.com/2025/apt29-phishing-campaign/), 15 April 2025, "Introduction," "Campaign Overview" (subsection "Phishing Emails"), and "Attribution."

------------------
