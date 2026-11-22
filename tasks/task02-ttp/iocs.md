# SolarWinds / SUNBURST: indicators of compromise

A defender-oriented reference: the artifacts that identify the SolarWinds attack, plus a short set from
APT29's recent campaigns. All network indicators are **defanged** (`hxxp`, `[.]`) so they cannot be
clicked or resolved by accident. Full citations are in [`sources.md`](sources.md).

---

## 1. Affected product

- **Affected Orion versions:** 2019.4 HF5, 2020.2 (no hotfix), 2020.2 HF1.
- **Trojanized component:** `SolarWinds.Orion.Core.BusinessLayer.dll`, loaded by `SolarWinds.BusinessLayerHost.exe`.
- **Update package:** `CORE-2019.4.5220.20574-SolarWinds-Core-v2019.4.5220-Hotfix5.msp`.
- **Configuration / kill-switch value:** `ReportWatcherRetry` in the Orion configuration file (a value of 3 means disabled).

## 2. File hashes (SHA-256)

**SUNBURST (trojanized DLL):**

| Hash | Orion build |
|---|---|
| `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` | 2019.4 HF5 |
| `dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b` | 2020.2 RC1 |
| `019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134` | 2020.2 RC2 |
| `ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6` | 2020.2 |

**SUNSPOT (build-server implant):**

| Hash | File |
|---|---|
| `c45c9bda8db1d470f1fd0dcc346dc449839eb5ce9a948c70369230af0b3ef168` | `taskhostsvc.exe` |
| `0819db19be479122c1d48743e644070a8dc9a1c852df9a8c0dc2343e904da389` | back-doored `InventoryManager.cs` |

**TEARDROP / Raindrop (second-stage loaders):**

| Hash | Note |
|---|---|
| `b820e8a2057112d0ed73bd7995201dbed79a79e13c79d4bdad81a22f12387e07` | TEARDROP |
| `f2d38a29f6727f4ade62d88d8a68de0d52a0695930b8c92437a2f9e4de92e418` | Raindrop |
| `be9dbbec6937dfe0a652c0603d4972ba354e83c06b8397d6555fd1847da36725` | Raindrop |

The legitimate SolarWinds signing certificate used to sign the trojanized files has SHA-256
`53f8dfc65169ccda021b72a62e0c22a4db7c4077f002fa742717d41b3c40f2c7`. (The public rule sets below contain
the complete hash lists.)

## 3. Host artifacts

| Artifact | Value | Malware |
|---|---|---|
| Single-instance named pipe | `583da945-62af-10e8-4902-a8f205c72b2e` | SUNBURST |
| Configuration keys used for state | `ReportWatcherRetry`, `ReportWatcherPostpone` | SUNBURST |
| Security service disabled via registry | `...\services\<name>\Start = 4` | SUNBURST |
| Parent process of suspicious children | `solarwinds.businesslayerhost.exe` | SUNBURST |
| Web paths imitating Orion telemetry on a non-SolarWinds host | `/swip/Events`, `/swip/Upload.ashx`, `/swip/upd/…` | SUNBURST |
| Mutexes | `{12d61a41-4b74-7610-a4d8-3028d2f56395}`, `{56331e4d-76a3-0390-a7ee-567adf5836b7}` | SUNSPOT |
| Encrypted log file | `C:\Windows\Temp\vmware-vmdmp.log` | SUNSPOT |
| Build-hijack files | `InventoryManager.bk`, `InventoryManager.tmp` | SUNSPOT |
| Payload file (fake image) | `gracious_truth.jpg` | TEARDROP |
| Service DLL / export | `netsetupsvc.dll` / `NetSetupServiceMain` | TEARDROP |

Second-stage loaders were placed under Windows-like paths such as `C:\Windows\SKB\LangModel.dll` and
`C:\Windows\Registration\crmlog.dll`.

## 4. Network indicators

**Primary control domain:** `avsvmcloud[.]com`, with generated subdomains of the form
`<encoded data>.appsync-api.{eu-west-1,us-west-2,us-east-1,us-east-2}.avsvmcloud[.]com`.

**Follow-on (CNAME) control domains:** `freescanonline[.]com`, `deftsecurity[.]com`, `thedoccloud[.]com`,
`websitetheme[.]com`, `highdatabase[.]com`, `digitalcollege[.]org`, `virtualdataserver[.]com`.

**Second-stage (Cobalt Strike) domains:** `incomeupdate[.]com`, `databasegalore[.]com`, `panhardware[.]com`,
`zupertech[.]com`.

**Containment:** in December 2020, `avsvmcloud[.]com` was taken over and pointed to `20.140.0[.]1`, an
address inside one of SUNBURST's kill-switch ranges, which shut down any copy that still checked in.

**Behavioural address ranges (configuration, not infrastructure).** SUNBURST's behaviour was controlled
by the IP range returned to its DNS queries. Several of these are private or reserved ranges and
**must not be blocked**. The full table is in [`solarwinds-ttps.md`](solarwinds-ttps.md), section
"Command and control, stage 1: DNS".

## 5. Detection content (public rule sets)

Ready-made detection rules are published and can be cited in the mitigation task rather than reproduced
here:

- **Mandiant `sunburst_countermeasures`:** YARA, Snort, and OpenIOC rules for SUNBURST, TEARDROP, and
  Cobalt Strike, plus indicator lists and the full set of hashed process/service names SUNBURST checks.
- **CISA AA20-352A:** indicator list and the `Sparrow.ps1` tool for detecting compromised Microsoft 365
  accounts, and Emergency Directive 21-01.
- **Microsoft:** Defender antivirus detections (`Trojan:MSIL/Solorigate.*`) and advanced-hunting /
  Sentinel queries for the SUNBURST DNS pattern, suspicious SolarWinds child processes, and the TEARDROP
  loader.
- **Sigma:** community rules for the UNC2452 process, PowerShell, and VBScript patterns.

## 6. Recent APT29 indicators (2023–2024)

| Campaign | Indicator | Value |
|---|---|---|
| TeamCity exploitation (Dec 2023) | GraphicalProton control URL | `hxxps://matclick[.]com/wp-query[.]php` |
| WINELOADER (German parties, 2024) | Delivery / control | `waterforvoiceless[.]org/invite.php`; `hxxps://siestakeying[.]com/auth.php` |
| Remote-desktop-file phishing (Oct 2024) | Sender domains (compromised) | `sellar[.]co.uk`, `townoflakelure[.]com`, `swpartners[.]com.au` |
| Remote-desktop-file phishing (Oct 2024) | Attacker server domains | `…aws.s3-ua[.]cloud`, `…gov-ua[.]cloud`, `…mfa-gov[.]cloud` |

*Full citations, with the exact section used for each indicator, are in [`sources.md`](sources.md).*
