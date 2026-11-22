# APT29: malware and tool catalogue

A reference for the group's wider toolset, beyond the SolarWinds attack itself. It supports the
"favorite tools and techniques" part of the task and shows how consistent APT29's methods are across
many years. For the SolarWinds-specific tools (SUNSPOT, SUNBURST, TEARDROP, Raindrop, Cobalt Strike)
see [`solarwinds-ttps.md`](solarwinds-ttps.md); for the recurring techniques see [`README.md`](README.md),
section 4. Full citations are in [`sources.md`](sources.md).

"ID" is the MITRE ATT&CK software identifier where one exists.

| Name | ID | Type | Era / first seen | Role | Control channel |
|---|---|---|---|---|---|
| PinchDuke | S0048 | malware | 2008–2010 | Credential stealer | HTTPS |
| GeminiDuke | S0049 | malware | 2009–2012 | Information stealer, loader | HTTPS |
| CosmicDuke | S0050 | malware | 2010–2015 | Information stealer, loader | HTTPS; FTP for exfiltration |
| MiniDuke | S0051 | malware | 2010–2019 | Downloader / backdoor | HTTPS; Twitter as a fallback address |
| CozyDuke | S0046 | malware | 2014–2015 | Modular backdoor platform | HTTPS; Twitter backup |
| OnionDuke | S0052 | malware | 2013–2015 | Dropper, stealer | HTTPS; Twitter backup |
| SeaDuke | S0053 | malware | 2014–2015 | Cross-platform backdoor (Python) | HTTPS |
| HAMMERTOSS | S0037 | malware | 2015 | Backdoor (.NET) | Daily Twitter handle → image on GitHub |
| CloudDuke | S0054 | malware | 2015 | Downloader, backdoor | HTTPS or Microsoft OneDrive |
| POSHSPY | S0150 | malware | 2015–2017 | Fallback PowerShell backdoor, file-less | HTTPS to generated domains |
| Tor + meek | S0183 / S0175 | tool | 2015–2017 | Covert tunnel | Tor disguised as web traffic to Google |
| PolyglotDuke | S0518 | malware | 2013–2019 | First-stage downloader | Address read from public posts (Twitter, Reddit, Imgur…) |
| RegDuke | S0511 | malware | 2017–2019 | First-stage loader + file-less backdoor | Dropbox |
| FatDuke | S0512 | malware | 2016–2019 | Third-stage backdoor | Custom protocol over HTTP |
| LiteDuke | S0513 | malware | 2014–2015 | Third-stage backdoor | HTTP |
| WellMess | S0514 | malware | 2018–2020 | Backdoor (Go / .NET) | HTTP, TLS, DNS |
| WellMail | S0515 | malware | 2020 | Lightweight backdoor (Go) | TCP with TLS |
| SoreFang | S0516 | malware | 2020 | First-stage downloader | HTTP |
| Sliver | S0633 | tool | 2020–2021 | Open-source intrusion framework | Mutual TLS, HTTPS, DNS |
| Cobalt Strike (Beacon) | S0154 | tool | 2018 onward | Commercial intrusion tool, delivered by custom loaders | HTTP / DNS / internal pipe |
| EnvyScout (ROOTSAW) | S0634 | malware | 2021–2024 | Dropper via HTML smuggling | none (writes files) |
| BoomBox | S0635 | malware | 2021 | Downloader + reconnaissance | Dropbox |
| NativeZone | S0637 | malware | 2021 | Cobalt Strike loader | loads Beacon |
| VaporRage (BOOMMIC) | S0636 | malware | 2021–2022 | Shellcode downloader | HTTP from compromised websites |
| BEATDROP | n/a | malware | 2022 | Downloader | Trello |
| FoggyWeb | S0661 | malware | 2021 | Passive federation-server backdoor | HTTP on federation-service paths |
| MagicWeb | n/a | malware | 2022 | Federation-server authentication bypass | none (passive) |
| QUIETEXIT | S1084 | malware | 2022 | Backdoor on network appliances | Reverse SSH; control on hacked cameras |
| reGeorg | S1187 | malware | 2022 | Web shell / proxy (backup access) | HTTP tunnel |
| SNOWYAMBER | n/a | malware | 2022 | Downloader, target triage | Notion |
| HALFRIG | n/a | malware | 2023 | Loader with embedded Cobalt Strike | Beacon |
| QUARTERRIG (MUSKYBEAT) | n/a | malware | 2023 | Downloader / in-memory dropper | Cobalt Strike / Brute Ratel |
| SPICYBEAT, ICEBEAT, BURNTBATTER, STATICNOISE | n/a | malware | 2023 | Downloaders / loaders | OneDrive / Dropbox; Zulip (ICEBEAT) |
| GraphicalProton | n/a | malware | 2023 | Backdoor | OneDrive (primary), Dropbox (backup) |
| WINELOADER | n/a | malware | 2024 | Modular backdoor | HTTP to attacker domains |
| GRAPELOADER | n/a | malware | 2025 | First-stage loader | HTTPS polling |
| AADInternals, ROADTools | S0677 / S0684 | tool | 2021 onward | Cloud-directory enumeration and abuse | cloud interfaces |
| Mimikatz, Rubeus, EDRSandBlast, SharpChromium | S0002 and others | tool | 2023 | Credential theft, disabling endpoint defences | none |

---

## Notes by era

**The Duke family (2008–2015).** APT29's earliest toolset ran several malware families in parallel. A
recurring trait even then was the use of legitimate web services to receive or back up the control
address. MiniDuke, CozyDuke, and OnionDuke used Twitter, and CloudDuke used Microsoft OneDrive.
**HAMMERTOSS** (2015) is the clearest example: it generated a new Twitter handle each day, read a tweet
that pointed to an image hosted on a site such as GitHub, and extracted commands hidden after the end
of the image file, an early use of image steganography.

**Operation Ghost (2013–2019).** A long-running, staged campaign against foreign ministries. First-stage
tools (**PolyglotDuke**, **RegDuke**) read their control address from posts on public sites, encoded in
unusual character sets. RegDuke also hid data in the pixels of images and persisted through a
background process that triggered when Microsoft Word opened. Later stages (**MiniDuke**, **FatDuke**)
provided full backdoor access.

**COVID-19 vaccine targeting (2020).** APT29 used the **WellMess** and **WellMail** backdoors and the
**SoreFang** downloader against vaccine-research organisations, gaining access by exploiting public
vulnerabilities and by phishing for credentials. After these tools were exposed, operators switched to
the open-source **Sliver** framework to keep access.

**The NOBELIUM / Midnight Blizzard chain (2021).** Alongside the SolarWinds clean-up, the group ran a
large phishing operation using a consistent chain: **EnvyScout** (an HTML-smuggling dropper) delivered a
disk image containing a shortcut and a library, which loaded **BoomBox**, **NativeZone**, or
**VaporRage**, ending in Cobalt Strike. It also developed backdoors that live inside an organisation's
federation server, **FoggyWeb** (steals the token-signing certificates) and **MagicWeb** (lets the
attacker sign in as any user), which directly enable the Golden SAML technique seen in the SolarWinds
attack.

**Diplomatic phishing (2022–2025).** A steady series of campaigns against embassies and ministries,
with new downloaders each year (**BEATDROP** via Trello, **SNOWYAMBER** via Notion, **GraphicalProton**
via OneDrive, **WINELOADER** and **GRAPELOADER** via compromised websites). The method is remarkably
stable: a smuggled image or archive, a legitimate signed program that side-loads a malicious library,
and a commercial tool (Cobalt Strike or Brute Ratel) for control. The 2024 WINELOADER campaign used a
dinner-invitation lure. The 2025 GRAPELOADER campaign used a wine-tasting lure. Both were delivered
through the same technique.

## Notes on cloud and identity (2021 onward)

As organisations moved to the cloud, APT29 shifted its focus from malware to **identity**. Recurring
methods across 2021–2025 include: slow password spraying from residential and other hard-to-block
addresses; theft and reuse of authentication tokens so no password is needed; abuse of cloud
applications (adding credentials to legitimate applications, granting them mailbox-read permissions);
registering the attacker's own device for multi-factor authentication; and social engineering over
Microsoft Teams. In the 2023–2024 breach of Microsoft's own corporate systems, the entry point was a
password spray against a legacy test account without multi-factor authentication, followed by abuse of
cloud applications to read corporate mailboxes. In October 2024 the group sent signed remote-desktop
configuration files to thousands of targets. When opened, these connected the victim's computer to
an attacker-controlled server.

*Full citations, with the exact section used for each claim, are in [`sources.md`](sources.md).*
