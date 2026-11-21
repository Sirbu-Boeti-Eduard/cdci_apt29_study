# Task 8 — Academic Literature Review: APT29 / SolarWinds SUNBURST

**Written by:** Emna Guesmi  
**Project:** APT29 and the SolarWinds software supply-chain compromise  
**Scope:** Six peer-reviewed papers published between 2019 and 2026

## 1. Objective and selection criteria

This review examines academic research relevant to the SolarWinds SUNBURST supply-chain compromise and the group's controlled proof of concept (PoC). The six papers were selected for their relevance to (1) software supply-chain attacks, (2) build and release integrity, and (3) detection of command-and-control (C2) activity. All were published within the assignment's 15-year window in peer-reviewed conferences or journals. Papers about open-source package ecosystems are used as *analogous evidence*, not as studies of the proprietary SolarWinds Orion build system.

The group's Task 5 PoC models a pipeline publishing a tampered V3 update, a client accepting the update after SHA-256 and RSA-signature checks, and a simulated DNS check-in/CNAME handoff followed by HTTP operator communication. It is a controlled demonstration, not a faithful reproduction of SUNSPOT's source-file replacement or SUNBURST's domain-generation algorithm (DGA). The analysis below maps academic findings to those stages as *potential defenses and research directions*, not experimentally validated PoC results.

## 2. Selected peer-reviewed research

### Paper 1 — in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes (2019)

**Authors:** Santiago Torres-Arias, Hammad Afzali, Trishank Karthik Kuppusamy, Reza Curtmola, Justin Cappos.  
**Venue:** 28th USENIX Security Symposium, pp. 1393–1410. [1]

**Research objective and method:** The authors introduce **in-toto**, a framework for verifying that authorized actors performed the expected steps in a software supply chain and that materials and products match recorded cryptographic evidence. They evaluate the approach against 30 historical supply-chain compromises and demonstrate use in different deployment environments.

**Main contribution:** Software integrity should be checked across the production process, not only at the final artifact. Signed metadata describing authorized steps and artifacts enables downstream verification against a defined policy.

**Relevance to SUNBURST and PoC:** A malicious artifact can be legitimately signed after a compromised build. Supply-chain provenance and step verification could add controls before release and client installation. This is especially relevant to the PoC's signed, tampered V3 update.

**Limitations:** The guarantees depend on appropriate policies, trusted keys, and reliable recording of steps. Compromised authorized actors or unobserved operations may undermine the assurance; in-toto is not a universal detector of malicious code.

### Paper 2 — Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks (2020)

**Authors:** Marc Ohm, Henrik Plate, Arnold Sykosch, Michael Meier.  
**Venue:** Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA 2020), LNCS 12223, pp. 23–43. [2]

**Research objective and method:** The researchers manually collected and analyzed 174 real malicious packages distributed through npm, PyPI, and RubyGems between November 2015 and November 2019. They classified code-injection paths, activation triggers, objectives, and obfuscation, and developed attack trees.

**Main findings:** Within the analyzed sample, 61% used typosquatting, 56% triggered during installation, 41% used conditional execution, and 55% primarily pursued data exfiltration. These percentages describe the available sample, not the prevalence of all supply-chain attacks.

**Relevance to SUNBURST and PoC:** The study illustrates how trusted software distribution can deliver intentionally malicious behavior to downstream users, and why execution may be difficult to observe. The PoC similarly demonstrates downstream acceptance of an attacker-influenced update.

**Limitations:** The evidence is about open-source packages, with substantial npm representation; it does not analyze SUNSPOT's proprietary build-system compromise or reproduce SUNBURST.

### Paper 3 — SoK: Taxonomy of Attacks on Open-Source Software Supply Chains (2023)

**Authors:** Piergiorgio Ladisa, Henrik Plate, Matias Martinez, Olivier Barais.  
**Venue:** IEEE Symposium on Security and Privacy (SP 2023), pp. 1509–1526. [3]

**Research objective and method:** The authors develop a software supply-chain attack-tree taxonomy using literature and documented incidents, then survey 17 domain experts and 134 software developers about the taxonomy and safeguards.

**Main findings:** The taxonomy covers 107 attack vectors, links them to 94 real-world incidents, and maps 33 mitigating safeguards. The survey also addresses perceived safeguard utility, cost, and use.

**Relevance to SUNBURST and PoC:** This framework helps classify opportunities for compromise across development, build, and distribution and systematically connect the PoC's tampered release to preventive safeguards. It is also useful when discussing deployment difficulty in Task 7.

**Limitations:** The taxonomy concentrates on open-source supply chains. The safeguard mappings are not proof that any particular measure would stop the group's simulated attack.

### Paper 4 — Software Supply Chain: A Taxonomy of Attacks, Mitigations and Risk Assessment Strategies (2026)

**Authors:** Betul Gokkaya, Leonardo Aniello, Basel Halak.  
**Venue:** Journal of Information Security and Applications, vol. 97, article 104324. [4]

**Research objective and method:** This systematic literature review synthesizes supply-chain attack categories, mitigation controls, and risk-assessment approaches, including risks related to components, dependencies, and suppliers. The reviewed literature covers 2015–2023.

**Main findings:** The paper identifies 19 distinct attack types, including six newly highlighted types, and maps 25 security controls to attack categories. It emphasizes risk-based prioritization rather than applying every control indiscriminately. **Publication note:** the publisher's abstract reports 96 reviewed papers while its highlights report 98; this review does not rely on either disputed total.

**Relevance to SUNBURST and PoC:** It provides a structure for discussing how build integrity, release verification, supplier controls, and downstream monitoring could be prioritized for a trusted-update attack. This supports the reasoning behind Task 7's countermeasure comparison.

**Limitations:** The work is a literature synthesis and risk framework, not an experimental evaluation of SolarWinds-specific defenses or this PoC.

### Paper 5 — An Empirical Study on Reproducible Packaging in Open-Source Ecosystems (2025)

**Authors:** Giacomo Benedetti, Oreofe Solarin, Courtney Miller, Greg Tystahl, William Enck, Christian Kästner, Alexandros Kapravelos, Alessio Merlo, Luca Verderame.  
**Venue:** IEEE/ACM 47th International Conference on Software Engineering (ICSE 2025), pp. 1052–1063. [5]

**Research objective and method:** The authors assess build reproducibility in six package ecosystems—npm, Maven, PyPI, Go, RubyGems, and Cargo—using representative samples of 4,000 packages per ecosystem. They investigate sources of non-reproducibility and possible build-tool or infrastructure improvements.

**Main findings:** Reproducibility rates differ widely across ecosystems, but the researchers report that infrastructure configuration and build-tool changes can substantially improve reproducibility. Independent rebuilding may make it possible to check whether published artifacts correspond to expected inputs.

**Relevance to SUNBURST and PoC:** This is particularly relevant because the paper explicitly discusses SolarWinds as a build-integrity failure. A separately rebuilt V3 artifact could, under suitable conditions, be compared with the distributed artifact; a mismatch would warrant investigation even if the released artifact carries a valid signature.

**Limitations:** Independent builds require reliable source inputs, reproducible toolchains, and an independent trust boundary. A reproducible malicious build is still malicious; equality alone does not prove source-code safety. The study concerns package ecosystems rather than the group's specific pipeline.

### Paper 6 — DGA-based Botnets Detection Using DNS Traffic Mining (2022)

**Authors:** Ahmed M. Manasrah, Thair Khdour, Raeda Freehat.  
**Venue:** Journal of King Saud University – Computer and Information Sciences, vol. 34, no. 5, pp. 2045–2061. [6]

**Research objective and method:** The authors investigate machine-learning detection of DGA-related domains using lexical features of observed DNS queries, including indicators of unusual domain-name structure. Their evaluation uses benign and malicious DNS-domain datasets from multiple sources and botnet families.

**Main findings:** The study demonstrates that DNS-name characteristics can help distinguish some DGA-generated domains from legitimate domains. Its reported results are specific to the evaluated datasets, features, and classifiers; they are not a SUNBURST detection benchmark.

**Relevance to SUNBURST and PoC:** SUNBURST used DNS in its C2 workflow, making DNS telemetry a useful detection surface. In the group's PoC, DNS logging could reveal the simulated check-in and CNAME handoff; this paper motivates analysis of such traffic.

**Limitations:** The group's PoC does not implement the original SUNBURST DGA. A lexical DGA detector would not necessarily flag a simple fixed-domain check-in or a CNAME handoff. The method must be tested on appropriate traffic before any detection claim is made.

## 3. Comparative analysis

| Paper | Evidence type | Security stage | Main lesson for the project | Key limitation |
|---|---|---|---|---|
| [1] in-toto | Framework and case-based evaluation | Development/build/release | Verify provenance across authorized steps | Depends on policy and trust assumptions |
| [2] Backstabber's Knife | Manual malicious-package study | Dependency/distribution/execution | Trusted packages can deliver malicious behavior | Open-source sample, not Orion |
| [3] SoK Taxonomy | Taxonomy, incident mapping, surveys | Entire software supply chain | Match attack vectors to safeguards | Mappings are not PoC test results |
| [4] Supply Chain Taxonomy | Systematic review and risk framework | Risk management | Prioritize controls based on exposure and risk | No SUNBURST-specific experiment |
| [5] Reproducible Packaging | Empirical multi-ecosystem study | Build/artifact integrity | Independently compare build outputs | Reproducibility does not prove benign code |
| [6] DGA Detection | DNS-based detection research | Post-installation network/C2 | Analyze suspicious DNS behavior | Not validated against this PoC's simplified DNS |

## 4. Synthesis: what the six papers collectively show

The papers point to **two complementary defensive layers**. First, supply-chain assurance seeks to reduce the chance that malicious code reaches a user through a trusted release: in-toto records and checks authorized production steps [1], reproducible packaging supports independent artifact comparison [5], and the attack taxonomies help identify where safeguards belong [3, 4]. Second, post-installation monitoring recognizes that preventive checks can fail: malicious-package research documents hidden or conditional execution [2], while DNS analysis offers one potential signal of C2 behavior [6].

These layers address different questions. **A valid signature asks who signed an artifact; it does not establish that every preceding build step was uncompromised.** Likewise, DNS monitoring cannot establish whether a software artifact was produced safely. Defense in depth requires both upstream verification and downstream observation.

## 5. Mapping the literature to the group's Task 5 PoC

| Simulated stage | Literature-informed control or research direction | What could be measured in a future extension |
|---|---|---|
| Tampered V3 enters pipeline | Authorized build steps and provenance checks [1, 3] | Whether a policy rejects an unapproved modification |
| Pipeline signs/publishes V3 | Independent reproducible build comparison [5] | Whether expected and published artifact hashes match |
| Client accepts signed V3 | Release provenance verification [1] | Whether client rejects an artifact without valid step evidence |
| Client performs DNS check-in/CNAME handoff | DNS telemetry and anomaly analysis [6] | Visibility of DNS queries and CNAME responses; detection rate on labeled lab traffic |
| Client contacts operator over HTTP | Network segmentation and traffic monitoring as proposed defenses [3, 4] | Whether an egress rule blocks unauthorized destinations |
| Operator issues commands | Endpoint monitoring as a proposed defense [3, 4] | Whether lab instrumentation records the simulated command execution |

**Important:** These are proposed evaluations, not experiments already performed by the group. No detection rates, false-positive rates, or mitigation successes are claimed for the PoC.

## 6. Research gaps and direction for Task 9

The literature establishes useful building blocks, but these papers do not jointly test provenance verification, independent artifact rebuilding, and DNS monitoring in a single SolarWinds-inspired laboratory pipeline. The group's current PoC also does not implement those defenses experimentally. A focused next step would be to introduce one or two verifiable controls, record outcomes, and compare what is detected before release versus after installation.

**Candidate research question for Task 9:** *How effectively can independent build-artifact verification and DNS activity monitoring detect different stages of a compromised but legitimately signed software-update workflow in a controlled Mininet/Docker simulation?*

To answer it rigorously, the group would need to define observable success criteria, implement the selected controls, generate benign and tampered update cases, and measure outcomes. The question is a proposal, not a result.

## 7. References

[1] S. Torres-Arias, H. Afzali, T. K. Kuppusamy, R. Curtmola, and J. Cappos, “in-toto: Providing farm-to-table guarantees for bits and bytes,” *28th USENIX Security Symposium*, pp. 1393–1410, 2019. https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias

[2] M. Ohm, H. Plate, A. Sykosch, and M. Meier, “Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks,” *Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA 2020)*, LNCS 12223, pp. 23–43, 2020. https://doi.org/10.1007/978-3-030-52683-2_2

[3] P. Ladisa, H. Plate, M. Martinez, and O. Barais, “SoK: Taxonomy of Attacks on Open-Source Software Supply Chains,” *2023 IEEE Symposium on Security and Privacy*, pp. 1509–1526, 2023. https://doi.org/10.1109/SP46215.2023.10179304

[4] B. Gokkaya, L. Aniello, and B. Halak, “Software supply chain: A taxonomy of attacks, mitigations and risk assessment strategies,” *Journal of Information Security and Applications*, vol. 97, art. 104324, 2026. https://doi.org/10.1016/j.jisa.2025.104324

[5] G. Benedetti, O. Solarin, C. Miller, G. Tystahl, W. Enck, C. Kästner, A. Kapravelos, A. Merlo, and L. Verderame, “An Empirical Study on Reproducible Packaging in Open-Source Ecosystems,” *2025 IEEE/ACM 47th International Conference on Software Engineering*, pp. 1052–1063, 2025. https://doi.org/10.1109/ICSE55347.2025.00136

[6] A. M. Manasrah, T. Khdour, and R. Freehat, “DGA-based botnets detection using DNS traffic mining,” *Journal of King Saud University – Computer and Information Sciences*, vol. 34, no. 5, pp. 2045–2061, 2022. https://doi.org/10.1016/j.jksuci.2022.03.001

---

**Written by:** Emna Guesmi
