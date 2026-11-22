# SolarWinds / SUNBURST: detailed technique reference

This is the technical companion to the walkthrough in [`README.md`](README.md): the same attack, in
more depth, grouped by Cyber Kill Chain phase, with MITRE ATT&CK techniques named inline. It covers
the SolarWinds Compromise campaign (ATT&CK **C0024**, August 2019 – January 2021).

The primary source is the report the professor assigned: Mandiant, *SUNBURST Additional Technical
Details* (24 December 2020), referred to below as **Mandiant ATD**. The other vendor and government
reports support it. Full citations for every source named here are in [`sources.md`](sources.md).
Domain names are written with `[.]` so they cannot be clicked by accident.

A note on the kill chain: the Lockheed Martin model was designed for direct intrusions. In a
supply-chain attack, weaponization and delivery happen at the third party (SolarWinds), and
"exploitation" means the victim's own trusted software loads the code. **No software vulnerability is
exploited**.

---

## Weaponization: tampering with the build (SUNSPOT)

The attackers did not modify Orion's source repository. Instead they placed an implant, **SUNSPOT**
(on disk as `taskhostsvc.exe`, persisted by a scheduled task at boot), on the build server. SUNSPOT
hashed the name of every running process to detect the compiler `MsBuild.exe`, read the build's
command line from process memory to confirm it was building Orion, and then replaced a single source
file, `InventoryManager.cs`, with a back-doored version. The original was kept as a `.bk` copy and the
swap was guarded by MD5 checks; after the build, SUNSPOT restored the original and deleted its
temporary files. It logged to an RC4-encrypted file (`C:\Windows\Temp\vmware-vmdmp.log`).

*Techniques:* Compromise Software Supply Chain (`T1195.002`), Process Discovery (`T1057`), Stored Data
Manipulation (`T1565.001`), Execution Guardrails (`T1480`), File Deletion (`T1070.004`), Masquerading
(`T1036.005`). *Source: CrowdStrike, "SUNSPOT: An Implant in the Build Process".*

The resulting file, `SolarWinds.Orion.Core.BusinessLayer.dll`, was signed with SolarWinds' genuine
certificate on 24 March 2020 and shipped as a normal hotfix from SolarWinds' download site.
Trojanized updates were signed between March and May 2020.

*Techniques:* Code Signing (`T1553.002`), Compromise Software Supply Chain (`T1195.002`).
*Sources: FireEye/Mandiant SUNBURST report; CISA AA20-352A.*

---

## Exploitation: how the backdoor starts

When the Orion "Inventory Manager" plug-in loads, a routine method calls the backdoor class. Before
doing anything, SUNBURST confirms its own process name hashes to the expected value for
`solarwinds.businesslayerhost` (using a 64-bit FNV-1a hash combined with XOR). All the strings it looks
for are stored only as these hashes, so they are not visible in the file. To ensure only one copy runs,
it creates a named pipe (`583da945-62af-10e8-4902-a8f205c72b2e`) and exits if the pipe already exists.

There is no exploit here: the victim's trusted Orion service runs the attacker's code with Orion's own
privileges.

*Techniques:* Compromise Software Supply Chain (`T1195.002`), Obfuscated Files or Information
(`T1027`), Execution Guardrails: Mutual Exclusion (`T1480.002`). *Source: Mandiant ATD,
"Anti-Analysis Environment Checks".*

---

## Installation: dormancy and environment checks

Before contacting anyone, SUNBURST confirmed it was on a genuine, interesting target:

- **Dormancy.** It ran only once the back-doored file was at least **12–14 days old** (a random value
  in that range), far longer than an automated analysis sandbox observes a file.
- **Stop conditions.** It stayed inactive if the configuration value `ReportWatcherRetry` was 3 (its
  disabled state), if the machine was not joined to an Active Directory domain, if the domain name
  matched a block-list of 15 names that resemble SolarWinds' own labs (for example `swdev.local`,
  `lab.local`, `test`), or if it could not resolve `api.solarwinds[.]com`. It stored its state inside
  legitimate Orion configuration keys (`ReportWatcherRetry`, `ReportWatcherPostpone`).
- **Security-tool checks.** It hashed the names of running processes, services, and drivers and
  compared them against built-in block-lists of antivirus, endpoint-detection, and forensic tools. If
  a blocked process or driver was present it paused and retried later; if a blocked service was
  present it disabled that service in the registry (`...\services\<name>\Start = 4`), which takes
  effect at the next reboot.

*Techniques:* Time-Based Evasion (`T1497.003`), System Checks (`T1497.001`), Security Software
Discovery (`T1518.001`), System Service Discovery (`T1007`), Impair Defenses: Disable Tools
(`T1562.001`), Modify Registry (`T1112`). *Source: Mandiant ATD, "Anti-Analysis Environment Checks" and
"Anti-Analysis Blocklists".*

> For incident response: the `ReportWatcherRetry` / `ReportWatcherPostpone` configuration values and
> the `Start` values of security services are useful forensic indicators that SUNBURST ran.

---

## Command and control, stage 1: DNS

First contact used the Domain Name System. SUNBURST generated subdomain names under
**`avsvmcloud[.]com`** with a domain generation algorithm and resolved them through the system's normal
name resolution; the attackers operated the authoritative name server for that domain (the "command
coordinator"). Each generated name encoded a machine identifier and the victim's internal domain name,
so the operators could tell **which organisation** each infection belonged to and select only the ones
worth pursuing. Lookups were spaced at random intervals (a few minutes, up to a few hours).

The **IP address range** returned in the answer told the backdoor what to do:

| Address range returned | Effect |
|---|---|
| 18.130.0.0/16, 99.79.0.0/16, 184.72.0.0/15 | Must arrive immediately before an alias (CNAME) record; the low bytes carry configuration (proxy method, scheme, delay). |
| 8.18.144.0/23, 71.152.53.0/24, 87.238.80.0/21, 199.201.117.0/24 (and the ranges above) | Continue signalling over DNS. |
| Private / reserved ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3, IPv6 local), plus 96.31.172.0/24, 131.228.12.0/22, 144.86.226.0/24, 20.140.0.0/15 | **Kill switch:** terminate and set `ReportWatcherRetry` so it never runs again. |
| 41.84.159.0/24, 74.114.24.0/21, 154.118.140.0/24, 217.163.7.0/24 | Return an active sample to the quiet, passive state. |

Because the kill-switch set includes private and reserved ranges, a sandbox or sinkhole that answers
with a private address switches the malware off. That is how the attack was contained: in
December 2020 the `avsvmcloud[.]com` domain was redirected to a sinkhole whose address falls in a
kill-switch range. An encrypted web channel could only be reached through an alias (CNAME) record, not
a raw address.

*Techniques:* Dynamic Resolution: Domain Generation Algorithms (`T1568.002`), Application Layer
Protocol: DNS (`T1071.004`), Data Encoding (`T1132`). *Source: Mandiant ATD, "Domain Generation
Algorithm" and "DNS C2 and the C2 Coordinator Protocol".*

---

## Command and control, stage 2: HTTPS

Once an alias record pointed to a real control server, SUNBURST opened an encrypted web channel
(handled by its `HttpHelper` component) and ran the commands it received, waiting at least a minute
between requests. Outgoing data was wrapped in a format that imitates Orion's own "Improvement Program"
telemetry. Replies looked like harmless program data, but the commands were concealed inside
identifier- and hex-like strings, a form of **steganography**, and were then XOR-decoded and
decompressed. The control servers used host names that matched real names inside the victim's network
and were usually hosted in the victim's own country.

SUNBURST understood a small, generic command set ("Jobs"):

| ID | Command | Operation |
|---|---|---|
| 0 | Idle | No operation |
| 1 | Exit | Stop the current thread |
| 2 | SetTime | Set the delay between actions |
| 3 | CollectSystemDescription | Profile the system |
| 4 | UploadSystemDescription | Fetch a URL and return the response |
| 5 | RunTask | Start a program with given arguments |
| 6 | GetProcessByDescription | List processes |
| 7 | KillTask | End a process |
| 8 | GetFileSystemEntries | List files and folders |
| 9 | WriteFile | Write data to a file |
| 10–12 | FileExists / DeleteFile / GetFileHash | File checks, deletion, hashing |
| 13–16 | Registry read / write / delete / list | Registry operations |
| 17 | Reboot | Restart the computer |

The command set is deliberately basic: SUNBURST's role was to profile the host and deliver the second
stage, not to carry out the operation itself.

*Techniques:* Web Protocols (`T1071.001`), Protocol Impersonation (`T1001.003`), Steganography
(`T1001.002`), Ingress Tool Transfer (`T1105`), Hide Infrastructure (`T1665`). *Source: Mandiant ATD,
"HTTP(S) C2"; FireEye/Mandiant SUNBURST report, "Supported Commands".*

---

## Second stage: TEARDROP, Raindrop and Cobalt Strike

On selected victims, and through the web channel above, SUNBURST delivered a loader to launch
**Cobalt Strike** (a commercial intrusion-testing tool whose agent is called Beacon, widely abused by
attackers):

- **TEARDROP** runs only in memory, as a service, and reads its payload from a file disguised as an
  image (`gracious_truth.jpg`). Loaders were given names that resemble real Windows files (for example
  `C:\Windows\SKB\LangModel.dll`).
- **Raindrop** does the same job but is built from modified 7-Zip code; it decodes its payload in
  several layers. It was seen on *other* machines inside a victim's network, used to spread, rather
  than delivered directly by SUNBURST.

The connection between SUNBURST and Cobalt Strike was deliberately broken: a registry "Image File
Execution Options" entry caused a script to run the next time a routine Windows program started, which
launched the loader and then deleted the entry, so finding Cobalt Strike did not lead investigators
back to the SolarWinds process.

*Techniques:* Ingress Tool Transfer (`T1105`), Image File Execution Options Injection (`T1546.012`),
Create or Modify System Process: Windows Service (`T1543.003`), Rundll32 (`T1218.011`), Steganography
(`T1027.003`), Indicator Removal: Clear Persistence (`T1070.009`). *Sources: FireEye/Mandiant SUNBURST
report; Microsoft, "Deep dive into the Solorigate second-stage activation"; Symantec, "Raindrop".*

---

## Actions on objectives: inside the network

Human operators then worked by hand, aiming to look like ordinary administrators.

- **Reconnaissance.** They used the **AdFind** utility (renamed to blend in: Volexity saw it as
  `sqlceip.exe`, posing as SQL Server telemetry) to list domains, computers, and accounts, and
  specific commands to map Exchange.
- **Credential theft.** They requested service tickets to crack offline (Kerberoasting), attempted to
  read group-managed service-account passwords, and used privileged accounts to replicate password
  data from domain controllers (DCSync).
- **Lateral movement.** They used a **different stolen credential for each step** ("credential
  hopping"), never the one used for remote access, and moved over Remote Desktop, Windows Management
  Instrumentation, and PowerShell remoting.
- **Anti-forensics.** They stopped audit logging, added firewall rules to limit some outbound traffic
  during reconnaissance, disabled security services on remote machines, and altered file timestamps to
  match real Windows files.

*Techniques:* Account / Domain Trust / Remote System Discovery (`T1087.002`, `T1482`, `T1018`),
Kerberoasting (`T1558.003`), DCSync (`T1003.006`), Valid Accounts (`T1078`), Remote Services
(`T1021.001`, `T1021.006`), Windows Management Instrumentation (`T1047`), Indicator Removal (`T1070`,
`T1070.006`). *Sources: FireEye/Mandiant SUNBURST report; CrowdStrike, "StellarParticle"; Microsoft,
"Deep dive"; Volexity, "Dark Halo".*

---

## Actions on objectives: the pivot to the cloud

The objective was email, much of it in Microsoft 365, so the attackers moved from the on-premises
network into the cloud.

- **Golden SAML.** With domain-level privileges they obtained the certificate that an organisation's
  federation server uses to sign single-sign-on tokens (Security Assertion Markup Language, SAML), and
  forged tokens to impersonate **any** user. These tokens bypass multi-factor authentication because
  the cloud service assumes it was already satisfied. (CISA describes the same technique; Mandiant
  named it "Golden SAML".)
- **Cloud persistence.** They added their own certificate as a trusted login provider, and added
  credentials to legitimate cloud applications that already had permission to read mail, then used
  those to read specific users' mailboxes through Microsoft's interfaces.
- **Multi-factor bypass (on-premises).** At one victim they stole the secret key of the Duo
  multi-factor system from a webmail server and forged a valid session cookie; this was not a flaw in
  Duo. Browser-cookie and saved-password theft were also used to bypass multi-factor authentication.
- **Email theft.** On Exchange servers they exported selected mailboxes, compressed them into
  password-protected archives, and downloaded them through a request to a URL disguised as an image
  (`owa/auth/Redir.png`), then deleted the export records.

*Techniques:* Unsecured Credentials: Private Keys (`T1552.004`), Forge Web Credentials: SAML Tokens
(`T1606.002`) and Web Cookies (`T1606.001`), Trust Modification (`T1484.002`), Additional Cloud
Credentials / Roles (`T1098.001`, `T1098.003`), Application Access Token (`T1550.001`), Remote Email
Collection (`T1114.002`), Archive via Utility (`T1560.001`), Exfiltration Over Encrypted Non-C2
Protocol (`T1048.002`), Clear Mailbox Data (`T1070.008`). *Sources: Microsoft 365 Defender team; MSRC,
"Customer Guidance"; CISA AA20-352A; Volexity, "Dark Halo"; CrowdStrike, "StellarParticle".*

---

## Later tooling and alternative access

- **GoldMax, Sibot, GoldFinder (mid-2020 onward).** A set of follow-on tools Microsoft attributes to
  the same actor: GoldMax, a Go back-door that persists as a scheduled task posing as management
  software and blends decoy traffic into its command channel; Sibot, a small script that persists via a
  daily scheduled task and the registry; and GoldFinder, which traces the network path to the control
  server to spot proxies and security devices. *Source: Microsoft, "GoldMax, GoldFinder, and Sibot".*
- **TrailBlazer and a Linux GoldMax variant.** CrowdStrike describes an additional implant that
  persists through Windows Management Instrumentation event subscriptions and disguises its control
  traffic as Google Notifications, plus a Linux version of GoldMax. *Source: CrowdStrike,
  "StellarParticle".*
- **Alternative initial access.** For some victims, CISA notes entry routes other than the Orion update:
  password guessing or spraying, and weakly secured administrator credentials on external remote-access
  services. Detection should therefore not stop at Orion servers. *Source: CISA AA20-352A.*

---

*Full citations, with the exact section or figure used for each claim, are in [`sources.md`](sources.md).*
