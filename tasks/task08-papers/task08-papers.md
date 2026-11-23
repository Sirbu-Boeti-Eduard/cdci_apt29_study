# Task 8: Academic Literature Review

**Written by:** Emna Guesmi  
**Project:** APT29 and the SolarWinds SUNBURST supply-chain compromise

## 1. Scope and selection

This review covers six peer-reviewed papers on software supply-chain attacks, build and release integrity, and command-and-control detection. All were published between 2019 and 2026, inside the assignment's 15-year window. Three come from flagship venues (USENIX Security, IEEE S&P, ICSE). The others are a specialist security conference (DIMVA) and two peer-reviewed journals (JISA and JKSU-CIS). Studies of open-source package ecosystems are used as analogous evidence, not as analyses of SolarWinds' proprietary Orion build.

The group's Task 5 PoC publishes a tampered V3 update, has a client accept it after SHA-256 and RSA-signature checks, then simulates a DNS check-in, a CNAME handoff, and HTTP contact with an operator. It does not reproduce SUNSPOT's source-file replacement or SUNBURST's domain-generation algorithm. The papers below are mapped to those stages as potential defenses and research directions, not as tested results.

## 2. The papers

### in-toto: USENIX Security 2019

Santiago Torres-Arias, Hammad Afzali, Trishank Karthik Kuppusamy, Reza Curtmola, and Justin Cappos introduced in-toto at the 28th USENIX Security Symposium (pp. 1393–1410). The framework checks that authorized actors performed the expected steps in a software supply chain, and that materials and products match recorded cryptographic evidence. The authors retrospectively mapped it to 30 historical compromises and reported coverage between 83% and 100% across the deployments they examined.

The work matters here because a malicious artifact can be signed after a compromised build. Provenance and step verification add a control before release if the layout covers the build step and the attestations are checked. The guarantees still depend on trusted policies and keys, and a single compromised build step is only caught when builds are redundant and attestations are checked. in-toto records which steps ran and how artifacts moved; it does not judge whether the code is benign. A compromised authorized actor or an unobserved step weakens the guarantee further.

### Backstabber's Knife Collection: DIMVA 2020

Marc Ohm, Henrik Plate, Arnold Sykosch, and Michael Meier identified 469 malicious packages in npm, PyPI, and RubyGems between November 2015 and November 2019, and analyzed the 174 they could obtain. They classified injection paths, activation triggers, objectives, and obfuscation, and built attack trees. In the sample, 61% used typosquatting, 56% ran on installation, 41% used conditional execution, and data exfiltration was the most common goal (55%). Objectives can overlap, and the authors present the figures as properties of the retrieved sample rather than the wider ecosystem.

Trusted distribution can deliver malicious code, and conditional execution makes it hard to observe. The PoC shows the same trust failure one layer up: a client accepts an attacker-influenced update. The sample is open source and npm-heavy, and it does not cover SUNSPOT's build compromise.

### SoK: IEEE S&P 2023

Piergiorgio Ladisa, Henrik Plate, Matias Martinez, and Olivier Barais built an attack-tree taxonomy for open-source supply chains from literature and documented incidents. They then surveyed 17 domain experts on the utility and cost of safeguards and 134 developers on their use; 53 developers completed the optional taxonomy assessment. The taxonomy covers 107 attack vectors tied to 94 real-world attacks or vulnerabilities, with 33 mitigating safeguards.

The taxonomy separates build-time compromise from distribution, which fits SUNSPOT and the PoC's signed tampered release. It is useful for placing preventive safeguards and for Task 7's discussion of deployment difficulty. It does not cover DNS or C2 detection or key custody, and its mappings do not show that a safeguard would stop the simulated attack.

### Gokkaya: JISA 2026

Betul Gokkaya, Leonardo Aniello, and Basel Halak published a systematic literature review in the Journal of Information Security and Applications (vol. 97, article 104324, 2026). The review corpus covers 2015 to 2023, though the reference list includes later work. It identifies 19 attack types, including six newly highlighted types, and maps 25 controls to attack categories. The authors emphasize risk-based prioritization instead of applying every control. Their abstract reports 96 reviewed papers and their highlights report 98; this review does not rely on either total.

The paper helps frame how build integrity, release verification, supplier controls, and monitoring could be prioritized. It is a literature synthesis and risk framework, not an experimental evaluation of SolarWinds defenses or this PoC. It is not a source for DNS or EDR detection or HSM practice.

### Reproducible Packaging: ICSE 2025

Giacomo Benedetti, Oreofe Solarin, Courtney Miller, Greg Tystahl, William Enck, Christian Kästner, Alexandros Kapravelos, Alessio Merlo, and Luca Verderame studied reproducibility across npm, Maven, PyPI, Go, RubyGems, and Cargo. They sampled 4,000 packages per ecosystem (ICSE 2025, pp. 1052–1063). Go packages ship no artifacts, so they do not contribute a reproducibility rate. Rates vary widely, and configuration or tooling changes improve them substantially; configuration changes raised Maven from 2.1% to 92.6%. The authors present reproducibility as a foundation for comparing a local build with a published artifact, but they do not perform that comparison themselves.

The paper is relevant because a valid signature says nothing about the build behind it. Our inference is that a separately rebuilt V3 artifact could be compared with the distributed one, and that a mismatch would justify investigation. Independent builds still need trusted sources, reproducible toolchains, and a separate trust boundary. A reproducible malicious build is still malicious, and the paper mentions SolarWinds only briefly. The study covers package ecosystems, not the group's pipeline.

### DNS DGA Detection: JKSU-CIS 2022

Ahmed Manasrah, Thair Khdour, and Raeda Freehat used 15 lexical features of DNS query names and four classifiers (KNN, SVM, decision tree, and ANN) to detect DGA domains (Journal of King Saud University – Computer and Information Sciences, 34(5), 2045–2061, 2022). Their malicious names came from wordlists for seven DGA families, alongside Alexa top domains and the PsyBoG captured-traffic corpus. They report up to 99.1% accuracy with an ANN on the generated dataset, with results varying by classifier and data source.

SUNBURST used DNS in its command-and-control workflow, so query-name telemetry is worth monitoring. The paper analyzes registrable domain names only. It does not inspect subdomains or CNAME targets, so it supports check-in monitoring but not detection of the PoC's CNAME handoff. The PoC also uses a fixed name and no original DGA, so a detector of this kind would not see its token in a subdomain of a fixed parent. Any detection claim would need testing on lab traffic.

## 3. Comparison

| Paper | Evidence | Stage | Lesson | Limit |
|---|---|---|---|---|
| [1] in-toto | Framework, retrospective mapping | Build and release | Verify steps and artifact flow | Needs trusted policy, keys, and redundant builds |
| [2] Backstabber's Knife | Manual package study | Dependency and execution | Trusted packages can carry malicious code | Open-source sample, not Orion |
| [3] SoK Taxonomy | Taxonomy and surveys | Entire supply chain | Place safeguards against specific attack vectors | Mappings are not PoC test results |
| [4] Supply Chain Taxonomy | Systematic review and risk framework | Risk management | Prioritize controls by exposure and risk | No SolarWinds-specific experiment |
| [5] Reproducible Packaging | Empirical multi-ecosystem study | Build and artifact integrity | Compare build outputs independently | Reproducibility does not prove benign code |
| [6] DGA Detection | DNS query-name detection research | Post-installation network | Analyze suspicious query names | Does not inspect CNAME targets or this PoC |

## 4. What the papers show together

The papers support two defensive layers. Before release, in-toto records and checks production steps [1], reproducible builds provide a foundation for comparing artifacts [5], and the taxonomies place safeguards at the right stages [3, 4]. After installation, malicious-package research shows how hidden or conditional execution evades inspection [2], and DNS query-name analysis offers one signal of C2 behavior [6].

Neither layer substitutes for the other. A valid signature identifies the signer and the integrity of the signed artifact; it does not show that the build was clean. DNS monitoring shows network behavior; it does not show how an artifact was produced.

## 5. Mapping to the Task 5 PoC

| Simulated stage | Literature-informed control | What a future extension could measure |
|---|---|---|
| Tampered V3 enters pipeline | Authorized build steps and provenance checks [1, 3] | Whether a policy rejects an unapproved modification |
| Pipeline signs and publishes V3 | Independent reproducible build comparison [5] | Whether expected and published artifact hashes match |
| Client accepts signed V3 | Release provenance verification [1] | Whether the client rejects an artifact without valid step evidence |
| Client performs DNS check-in and CNAME handoff | DNS query-name telemetry and anomaly analysis [6]; CNAME inspection would be a separate control | Visibility of DNS queries and the detection rate on labeled lab traffic; CNAME handoff needs separate logging |
| Client contacts the operator over HTTP | Network segmentation and traffic monitoring as proposed defenses [3, 4] | Whether an egress rule blocks unauthorized destinations |
| Operator issues commands | Endpoint monitoring as a proposed defense [3, 4] | Whether lab instrumentation records the simulated command execution |

These are proposed evaluations, not experiments already performed by the group. No detection rates, false-positive rates, or mitigation successes are claimed for the PoC.

## 6. Gaps and the Task 9 question

The literature provides building blocks, but no paper tests provenance verification, independent rebuilding, and DNS monitoring together in a SolarWinds-style lab. The PoC does not implement those defenses either. A focused next step would add one or two controls, record outcomes, and compare what is caught before release with what is caught after installation.

**Candidate research question:** How effectively can independent build-artifact verification and DNS activity monitoring detect different stages of a compromised but legitimately signed software-update workflow in a controlled Mininet/Docker simulation?

Answering it would require defined success criteria, implemented controls, benign and tampered update cases, and measured outcomes. The question is a proposal, not a result.

## 7. References

[1] S. Torres-Arias, H. Afzali, T. K. Kuppusamy, R. Curtmola, and J. Cappos, “in-toto: Providing farm-to-table guarantees for bits and bytes,” *28th USENIX Security Symposium*, pp. 1393–1410, 2019. https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias

[2] M. Ohm, H. Plate, A. Sykosch, and M. Meier, “Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks,” *Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA 2020)*, LNCS 12223, pp. 23–43, 2020. https://doi.org/10.1007/978-3-030-52683-2_2

[3] P. Ladisa, H. Plate, M. Martinez, and O. Barais, “SoK: Taxonomy of Attacks on Open-Source Software Supply Chains,” *2023 IEEE Symposium on Security and Privacy*, pp. 1509–1526, 2023. https://doi.org/10.1109/SP46215.2023.10179304

[4] B. Gokkaya, L. Aniello, and B. Halak, “Software supply chain: A taxonomy of attacks, mitigations and risk assessment strategies,” *Journal of Information Security and Applications*, vol. 97, art. 104324, 2026. https://doi.org/10.1016/j.jisa.2025.104324

[5] G. Benedetti, O. Solarin, C. Miller, G. Tystahl, W. Enck, C. Kästner, A. Kapravelos, A. Merlo, and L. Verderame, “An Empirical Study on Reproducible Packaging in Open-Source Ecosystems,” *2025 IEEE/ACM 47th International Conference on Software Engineering*, pp. 1052–1063, 2025. https://doi.org/10.1109/ICSE55347.2025.00136

[6] A. M. Manasrah, T. Khdour, and R. Freehat, “DGA-based botnets detection using DNS traffic mining,” *Journal of King Saud University – Computer and Information Sciences*, vol. 34, no. 5, pp. 2045–2061, 2022. https://doi.org/10.1016/j.jksuci.2022.03.001

---

**Written by:** Emna Guesmi
