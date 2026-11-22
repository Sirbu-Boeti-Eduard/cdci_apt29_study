# Task 9: Research Question

**Project:** APT29 and the SolarWinds SUNBURST supply-chain compromise  
**Written by:** Emna Guesmi

## 1. Research question

**How effectively can independent build-artifact verification and DNS activity monitoring detect different stages of a compromised but legitimately signed software-update workflow in a controlled Mininet/Docker simulation?**

## 2. Motivation

The SolarWinds SUNBURST incident illustrates a weakness in relying on a vendor's final software signature alone. Malicious changes introduced before signing can reach customers in an apparently legitimate update. The group's Task 5 proof of concept (PoC) models this trust problem: a pipeline publishes a tampered V3 update; the client accepts its SHA-256 digest and RSA signature, then performs a simulated DNS check-in and CNAME handoff before contacting an operator over HTTP.

Task 8 identifies two relevant defensive approaches. Supply-chain provenance and reproducible builds can help verify how a released artifact was produced [1, 5]. DNS traffic analysis can help identify some forms of command-and-control activity after installation [6]. The literature does not establish how these approaches would perform together in the group's simplified lab. This motivates a question that separates detection **before installation** from detection **after installation**.

## 3. Scope and subquestions

The proposed study concerns the group's **controlled Mininet/Docker PoC**, not the actual SolarWinds infrastructure or a complete SUNBURST reproduction.

1. **Pre-release integrity:** Can an independently generated reference artifact or trusted provenance policy distinguish the tampered V3 release from an approved release, even when both pass ordinary signature checks?
2. **Post-installation visibility:** Can DNS logging reliably reveal the PoC's check-in and CNAME handoff, and can a stated detection rule distinguish this traffic from benign lab traffic?
3. **Complementarity:** Which stages are visible to build verification, which to DNS monitoring, and what remains undetected when either defense is used alone?

## 4. Proposed evaluation

This section describes **future experiments**, not results already obtained.

| Experiment | Proposed setup | Observable outcome |
|---|---|---|
| Baseline | Run an approved update through the PoC | Artifact hash, signature status, DNS/HTTP logs |
| Tampered signed update | Run the PoC's malicious V3 release | Whether existing signature verification accepts it |
| Artifact verification | Compare released V3 with a trusted independently built or approved reference artifact | Match/mismatch; whether the tampered release is flagged |
| DNS monitoring | Capture DNS queries and CNAME responses for benign and tampered runs | Check-in visibility; alerts, missed events, false positives |
| Combined controls | Apply both checks to the same labeled runs | Which attack stages each control detects and whether the combination adds coverage |

If the group cannot implement independent reproducible builds, an **approved-reference artifact comparison** can serve as a narrower lab demonstration. It must not be described as proof of reproducible-build security. Likewise, simply recording DNS traffic establishes visibility, not anomaly-detection accuracy; accuracy requires a defined rule and benign comparison traffic.

Possible metrics are the number of detected tampered releases, the proportion of labeled malicious check-ins flagged, false-positive alerts on benign runs, and the attack stage at which an alert occurs. No numerical results are claimed here.

## 5. Expected contribution and limits

The proposed study would show whether upstream artifact checks and downstream DNS observation cover different parts of a signed-update attack in the group's environment. It could also identify gaps that remain after both controls are applied.

The PoC uses a predefined check-in routine and simplified DNS behavior. It does not implement SUNSPOT's source-file replacement, SUNBURST's original DGA, or later-stage malware. Results from this lab therefore could not be generalized directly to real SolarWinds infections. The present assignment supplies a **research question and test plan**, not an experimental validation.

## 6. Connection to Task 8 literature

- **[1] in-toto (2019):** motivates checking the authorized build and release steps, rather than relying only on the final signature.
- **[3] Ladisa et al. (2023):** provides a taxonomy for placing preventive safeguards at supply-chain attack points.
- **[4] Gokkaya et al. (2026):** motivates selecting controls based on the risks and stages being addressed.
- **[5] Benedetti et al. (2025):** motivates independent artifact rebuilding and comparison, subject to trusted inputs and reproducible tooling.
- **[6] Manasrah et al. (2022):** motivates DNS-based detection, while its DGA-specific evaluation does not directly establish detection of the PoC's fixed-domain check-in.

The full bibliographic details for [1]–[6], including the malicious-package study [2], are in `tasks/task08-papers/task08-papers.md`.

---

**Written by:** Emna Guesmi
