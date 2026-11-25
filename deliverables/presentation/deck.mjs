export const meta = {
  title: "APT29 and the SolarWinds Supply-Chain Compromise",
  subtitle: "From SUNSPOT to a controlled recreation in Mininet and Docker",
  event: "CDCI Assignment 1",
  date: "27 November 2026",
  aspect: "16 / 9",
};

export const slides = [
  {
    kind: "title",
    kicker: "Tracking an APT group",
    title: "APT29 and the SolarWinds Supply\u2011Chain Compromise",
    claim: "A backdoor reached 18,000 customers inside a correctly signed update. What did the signature prove?",
    subtitle: "From SUNSPOT to a controlled recreation in Mininet and Docker",
    meta: ["CDCI Assignment 1", "27 November 2026"],
    note: `Target timing: 30 seconds.

Open with the fact. In December 2020 a backdoor reached SolarWinds customers inside a correctly signed Orion update. The supplier built it, the supplier signed it, and customers installed it.

Then the question the talk answers: if every check passes, what did the check prove?

Transition: who the group is, in fifty seconds.`,
  },
  {
    kind: "bullets",
    kicker: "THE ACTOR",
    title: "One group, many names",
    lead: "APT29 works for Russia's Foreign Intelligence Service. Microsoft calls it Midnight Blizzard or NOBELIUM, Mandiant used UNC2452 for SolarWinds, and older reporting says Cozy Bear or The Dukes. Its infrastructure runs on services targets already trust: Twitter in 2015, Constant Contact in 2021, Teams tenants in 2023.",
    items: [
      { head: "At least 2008", text: "Five Eyes agencies date SVR cyber operations to 2008 and list APT29 among the names used for them." },
      { head: "2013 to 2019", text: "Operation Ghost targets foreign ministries in at least three European countries and an EU embassy in Washington." },
      { head: "2015 to 2016", text: "Cozy Bear is on the DNC network from summer 2015; Fancy Bear arrives separately in April 2016." },
      { head: "2023 to 2025", text: "TeamCity exploitation in 2023, then phishing against German parties, diplomats and more than 100 organisations." },
    ],
    note: `Target timing: 80 seconds.

Say the names once, then the pattern: a long-running espionage group that keeps returning to governments and suppliers.

Do not linger on the DNC. One sentence, then move.

The infrastructure point is one line and it pays off later: the group uses services the target already permits.

Transition: the incident itself.`,
  },
  {
    kind: "stats",
    kicker: "THE INCIDENT",
    title: "One update reached 18,000 customers",
    stats: [
      { value: "18,000", label: "customers downloaded the affected Orion builds" },
      { value: "<100", label: "estimated by SolarWinds to have been compromised" },
      { value: "9", label: "U.S. federal agencies reported compromised" },
    ],
    statement: "Downloading the update proves exposure. It does not prove intrusion.",
    note: `Target timing: 70 seconds.

These three numbers are routinely conflated. Up to about 18,000 customers downloaded the affected builds. SolarWinds estimated fewer than 100 were compromised, and nine federal agencies were among them.

Make the distinction explicit: exposure is not intrusion, and neither is the same as a backdoor that was never switched on.

Transition: how the backdoor got into the build.`,
  },
  {
    kind: "steps",
    kicker: "STAGE 1: BUILD",
    title: "SUNSPOT edits the build, not the repository",
    steps: [
      { head: "Wait", text: "The implant runs as taskhostsvc.exe on the build server, kept alive by a scheduled task." },
      { head: "Watch", text: "It waits for MsBuild.exe and reads the build command line from process memory." },
      { head: "Swap", text: "InventoryManager.cs is replaced with a modified copy; the original is kept as a .bk file." },
      { head: "Restore", text: "The original returns when the build exits. Source control never shows the change." },
    ],
    statement: "The repository is clean, the signature is valid, and the customer cannot tell.",
    note: `Target timing: 120 seconds.

CrowdStrike's analysis is the source. The detail that matters is the restore: the repository looked untouched, so a code review would have found nothing.

Say the consequence out loud and then stop for a beat: the repository is clean, the signature is valid, and the customer has no way to tell.

Skip the MD5 aside unless someone asks how the build stayed consistent.

Transition: the result was signed and shipped.`,
  },
  {
    kind: "steps",
    kicker: "STAGE 2: INSTALLATION",
    title: "The backdoor waits before it acts",
    steps: [
      { head: "12 to 14 days", text: "SUNBURST waits until the plugin file is old enough to outlast a sandbox." },
      { head: "Domain check", text: "It requires an Active Directory domain and stops if the domain looks like a SolarWinds test lab." },
      { head: "Tool check", text: "Running processes are compared against a list of analysis tools." },
      { head: "First contact", text: "It builds a subdomain under avsvmcloud[.]com with a domain generation algorithm (DGA)." },
    ],
    note: `Target timing: 90 seconds.

Each check defeats a different observer: the delay defeats sandboxes, the domain check defeats analyst machines, the tool list defeats endpoint security.

Name the acronym once: DGA, domain generation algorithm. You will need it on the next slide.

Transition: the coordinator decided what happened next.`,
  },
  {
    kind: "table",
    kicker: "STAGE 3: MODE SELECTION",
    title: "The DNS answer is the instruction",
    head: ["Response", "Mode", "Effect"],
    rows: [
      ["A record in a disable range", "3, Truncate", "The implant stops for good."],
      ["A record in a passive range", "4, New", "It keeps checking in and encodes the victim domain."],
      ["A record in an active range", "5, Append", "It enables command and control."],
      ["CNAME to another host", "handoff", "The named server becomes the HTTPS control host."],
    ],
    statement: "The operator chose each victim here, which is why fewer than 100 of 18,000 were compromised. Our lab resolves the CNAME but posts to the bare IP.",
    note: `Target timing: 150 seconds.

This is the slide people remember. The coordinator does not send commands over DNS. It sends an address range, and the range selects a mode. A CNAME response supplies the host for the next stage.

Mandiant says the malware required a CNAME because it could not use a raw address. Our lab resolves the CNAME but then posts to the bare IP, which the real implant could not do. Say the difference here, before anyone finds it later.

Transition: once the coordinator switched it on, this is what the traffic looked like.`,
  },
  {
    kind: "bullets",
    kicker: "STAGE 4: OPERATIONS",
    title: "Control traffic that looked like telemetry",
    lead: "Active traffic imitated the Orion Improvement Program (OIP): telemetry-shaped JSON with commands hidden in the response body. Messages up to 10,000 bytes were wrapped as JSON; larger ones were sent unmodified.",
    items: [
      { head: "Commands", text: "Process execution, file transfer, registry access and reboot." },
      { head: "Loaders", text: "TEARDROP ran in memory and opened a file named gracious_truth.jpg; Raindrop was a second loader for the same purpose." },
      { head: "Hands-on control", text: "Cobalt Strike Beacon, in at least one case started through a debugger hijack on dllhost.exe." },
      { head: "Objective", text: "AdFind, DCSync, and a stolen SAML signing certificate used to mint tokens for Microsoft 365." },
    ],
    note: `Target timing: 120 seconds.

The channel is the point: it looked like the product's own telemetry, so signature matching had nothing to work with.

The second stage exists to break the link between the backdoor and the tool. Golden SAML bypassed MFA because the cloud service trusted the token's signer.

Do not explain SAML unless asked. One sentence: they stole the certificate that signs login tokens.

Transition: the bill.`,
  },
  {
    kind: "cards",
    kicker: "VICTIMS AND IMPACT",
    title: "Three customers, three kinds of loss",
    cards: [
      { head: "Mimecast", text: "Encrypted credentials for about 31,000 customers, and 58, 50 and 76 percent of three source-code areas. USD 0.8 million in incident costs and a USD 990,000 SEC penalty." },
      { head: "U.S. Department of Justice", text: "Microsoft 365 accounts in 27 U.S. Attorneys' offices; at least 80 percent of employees in four New York districts. Access treated as covering all mail from May to December 2020." },
      { head: "Check Point", text: "Two infected Orion servers, activity from July to October 2020, two compromised accounts and attempted lateral movement. A USD 995,000 SEC penalty over its disclosures." },
    ],
    statement: "Mimecast and Check Point were penalised for how they described the incident, not for being breached.",
    note: `Target timing: 90 seconds.

Pick one number per card and let the slide carry the rest. Mimecast held other companies' credentials and a certificate that was used against five customers. DOJ treated every mailbox in the affected accounts as read. Check Point could not establish the full scope.

Then the sentence that matters: the penalties were about disclosure, not about the breach.

Transition: which leaves the question we built the lab around.`,
  },
  {
    kind: "quote",
    kicker: "THE QUESTION WE TESTED",
    title: "A valid signature answers a narrower question",
    quote: "The client installs the backdoor because every check passes.",
    support: "Not because a check was bypassed. The catalogue digest, the RSA signature and the component digest all verify. The failure is in what the signature is asked to prove.",
    note: `Target timing: 90 seconds.

This is the pivot. We did not rebuild SUNBURST; we rebuilt the trust failure around it. A supplier signs a package that carries code, and a client verifies it correctly.

If someone asks whether we broke the verification, the answer is no, and that is the point.

Slow down here. Everything after this slide depends on the room accepting this sentence.

Transition: so we built the smallest thing that could prove the claim.`,
  },
  {
    kind: "figure",
    kicker: "THE LAB",
    title: "One network, one victim, one capture point",
    caption: "Every victim packet crosses the bridge; tcpdump records DNS, the updater and the receiver. The rules read the capture, not the service logs.",
    svg: `<svg viewBox="0 0 1136 330" role="img" aria-label="Diagram: the victim host reaches switch s1 only through the sensor bridge, which captures DNS, update and upload traffic; three services sit on the switch, and the web apps run outside the Mininet wire.">
  <defs>
    <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0,0 L8,4 L0,8 z" fill="#17212b"/>
    </marker>
  </defs>

  <rect x="2" y="86" width="176" height="94" fill="#fffdf8" stroke="#17212b" stroke-width="2"/>
  <text x="90" y="122" text-anchor="middle" font-size="19" font-weight="600" fill="#17212b">victim</text>
  <text x="90" y="148" text-anchor="middle" font-size="14" fill="#5a5449">orion-01 · 10.0.0.5</text>
  <text x="90" y="168" text-anchor="middle" font-size="14" fill="#5a5449">no direct link to s1</text>

  <line x1="178" y1="133" x2="238" y2="133" stroke="#17212b" stroke-width="2" marker-end="url(#arrow)"/>

  <rect x="242" y="54" width="196" height="158" fill="#fffdf8" stroke="#b42318" stroke-width="2"/>
  <text x="340" y="86" text-anchor="middle" font-size="19" font-weight="600" fill="#17212b">sensor · br0</text>
  <text x="340" y="112" text-anchor="middle" font-size="14" fill="#5a5449">bridge in the wire</text>
  <text x="340" y="136" text-anchor="middle" font-size="14" fill="#5a5449">tcpdump → c2-traffic.pcap</text>
  <text x="340" y="160" text-anchor="middle" font-size="14" fill="#5a5449">rules, flows, intervals</text>
  <text x="340" y="190" text-anchor="middle" font-size="13" font-weight="600" fill="#b42318">CAPTURE POINT</text>

  <line x1="438" y1="133" x2="498" y2="133" stroke="#17212b" stroke-width="2" marker-end="url(#arrow)"/>

  <rect x="502" y="98" width="112" height="72" fill="#fffdf8" stroke="#17212b" stroke-width="2"/>
  <text x="558" y="126" text-anchor="middle" font-size="18" font-weight="600" fill="#17212b">s1 switch</text>
  <text x="558" y="148" text-anchor="middle" font-size="14" fill="#5a5449">10.0.0.0/24</text>

  <line x1="614" y1="120" x2="694" y2="70" stroke="#17212b" stroke-width="2" marker-end="url(#arrow)"/>
  <line x1="614" y1="133" x2="694" y2="133" stroke="#17212b" stroke-width="2" marker-end="url(#arrow)"/>
  <line x1="614" y1="148" x2="694" y2="198" stroke="#17212b" stroke-width="2" marker-end="url(#arrow)"/>

  <rect x="698" y="34" width="406" height="62" fill="#fffdf8" stroke="#17212b" stroke-width="2"/>
  <text x="722" y="60" font-size="17" font-weight="600" fill="#17212b">updater · 10.0.0.2:8000</text>
  <text x="722" y="82" font-size="14" fill="#5a5449">catalogue, package, signature</text>

  <rect x="698" y="102" width="406" height="62" fill="#fffdf8" stroke="#17212b" stroke-width="2"/>
  <text x="722" y="128" font-size="17" font-weight="600" fill="#17212b">DNS coordinator · 10.0.0.3:53</text>
  <text x="722" y="150" font-size="14" fill="#5a5449">mode by A record, CNAME handoff</text>

  <rect x="698" y="170" width="406" height="62" fill="#fffdf8" stroke="#17212b" stroke-width="2"/>
  <text x="722" y="196" font-size="17" font-weight="600" fill="#17212b">receiver · 10.0.0.4:9000</text>
  <text x="722" y="218" font-size="14" fill="#5a5449">OIP-shaped POST, tasking</text>

  <rect x="2" y="250" width="432" height="60" fill="#f2ecdf" stroke="#cfc6b4" stroke-width="1"/>
  <text x="24" y="272" font-size="14" font-weight="600" fill="#17212b">pipeline · client · attacker console</text>
  <text x="24" y="292" font-size="14" font-weight="600" fill="#17212b">presenter · defender</text>
  <text x="24" y="310" font-size="12" fill="#5a5449">localhost:8080–8084, outside the Mininet wire</text>

  <line x1="218" y1="250" x2="218" y2="180" stroke="#5a5449" stroke-width="1.5" stroke-dasharray="4 4"/>
  <line x1="218" y1="180" x2="242" y2="180" stroke="#5a5449" stroke-width="1.5" stroke-dasharray="4 4"/>
</svg>`,
    note: `Target timing: 90 seconds.

Orient the room in one pass, left to right: the victim, the bridge, the switch, then the three services. The victim has no route to the switch except through the sensor.

That design choice is the argument. Every detection claim is about the wire, not about logs the lab wrote for itself.

The bottom box is the web interface: five small apps outside the Mininet network.

Transition: here is the install the lab produced.`,
  },
  {
    kind: "checks",
    kicker: "EVIDENCE",
    title: "Every check passed",
    lead: "The manifest declares the component, and the pipeline signed exactly those bytes, so the digest describes the file it names. The client history records found, downloaded, verified, installed, then the registered component.",
    checks: [
      { label: "Catalogue digest", detail: "The package matches the digest published in the catalogue." },
      { label: "RSA signature", detail: "Verified with openssl against a pinned public key the client cannot write." },
      { label: "Component digest", detail: "The extracted module matches the SHA-256 declared in the manifest: 28cbdfb0…61810." },
    ],
    statement: "Then the installer registered orion-improvement-program and started it.",
    note: `Target timing: 140 seconds.

Walk the three checks in order. The key is pinned and the client cannot write it, so there is no local bypass.

The component digest is the one to point at: 28cbdfb0, ending 61810. The client history shows found, downloaded, verified, installed, then the registered component.

If asked for proof: the package and manifest are in tasks/task05-poc, and the playbook and runbook describe how to produce the capture and sensor state. No run output is committed, so do not claim one is.

Transition: and here is what we did not build.`,
  },
  {
    kind: "table",
    kicker: "SCOPE",
    title: "Implemented, represented, or absent",
    head: ["Kill-chain phase", "In the lab", "Status"],
    rows: [
      ["Reconnaissance", "Nothing", "Not modelled"],
      ["Weaponization", "A prebuilt V3 package pins a component digest", "Represented"],
      ["Delivery", "Signed package, stable channel, HTTP download", "Implemented"],
      ["Exploitation", "No vulnerability; the client trusts the signed package", "Not applicable"],
      ["Installation", "Installer registers the component and starts it", "Implemented, reduced"],
      ["Command and control", "Encoded check-in, mode by answer, CNAME for resolution, POST", "Implemented, reduced"],
      ["Actions on objectives", "One optional, benign shell command and its output", "Implemented, reduced"],
    ],
    statement: "The lab reproduces the trust path and the check-in, not the actor's code.",
    note: `Target timing: 70 seconds.

This is the honesty slide, and it is deliberately brief. Weaponization is represented, not performed: there is no build system. Reconnaissance is absent. Exploitation is not applicable because there is no vulnerability.

Delivery and installation are implemented and run when the presenter drives them. Tasking is reduced: one process, one command, no persistence.

Transition: so what did the defender see?`,
  },
  {
    kind: "bullets",
    kicker: "DETECTION",
    title: "Seven rules, six tied to this lab",
    lead: "The sensor decodes the check-in label, measures the interval, records first contact and flags the upload. Five rules are reachable in a demo; the self-test exercises the other two. None was tested against a benign baseline.",
    items: [
      { head: "What can be recovered", text: "The check-in is decodable and periodic once captured, and the upload is visible on the wire." },
      { head: "What proves less than it looks", text: "Six of seven rules key on lab constants: the check-in suffix, a periodicity threshold, or the POST path, agent and destination. Only first-contact is generic, and it fires on the benign update." },
      { head: "The signal we did not implement", text: "Mandiant rates a CNAME resolution above a decoded label; none of our rules alerts on the CNAME response." },
      { head: "The honest limit", text: "No benign baseline was run, so the rule set shows what can be recovered, not what a defender should prioritise." },
    ],
    note: `Target timing: 120 seconds.

Do not oversell. Five of seven rules are reachable, and none has been run against benign traffic.

The checksum rule proves the lab's encoder ran, nothing more. Three rules depend on constants we chose.

Then the concession that buys credibility: Mandiant says the CNAME answer is the stronger signal, and our rules watch the label instead.

Transition: what would have helped.`,
  },
  {
    kind: "table",
    kicker: "COUNTERMEASURES",
    title: "The strongest controls are the hardest to deploy",
    head: ["Control", "Effect", "Difficulty"],
    rows: [
      ["Build pipeline isolation", "High", "High"],
      ["Reproducible builds", "High", "Very high"],
      ["Independent artefact verification", "High", "High"],
      ["HSM-protected signing keys", "Low", "Medium"],
      ["DNS anomaly detection", "Medium", "Medium"],
      ["EDR", "Medium", "Medium"],
    ],
    statement: "Ratings are our judgement on a four-point scale. Three controls act before the signature exists.",
    note: `Target timing: 90 seconds.

Group the table in three: the first three act before signing, the signing key protects a step the attackers did not need to break, and the last two act after installation.

The ratings are our judgement on a three-point scale, not measurements. Say that once.

The line that matters: the controls with the most effect are the ones that require rebuilding someone else's process.

Transition: that is where the research stops.`,
  },
  {
    kind: "cards",
    kicker: "LITERATURE",
    title: "Six papers, two defensive layers",
    cards: [
      { head: "Before release", tag: "in-toto (2019) · SoK (2023) · reproducible packaging (2025)", text: "Provenance checks record which steps ran; independent rebuilds give a comparison point. Neither proves the code is benign." },
      { head: "After installation", tag: "Backstabber's Knife (2020) · taxonomy (2026) · DGA detection (2022)", text: "Trusted distribution carries malicious code; DNS query-name analysis detects generated domains, but not our fixed-domain check-in." },
    ],
    statement: "No paper tests provenance verification and DNS monitoring together on a signed update.",
    note: `Target timing: 40 seconds.

Six papers, all since 2019. Two check the build, two describe the attack surface, two watch the network. None does both.

Do not read the venues. Point at the tags and move.

Transition: which is the gap the research question comes from.`,
  },
  {
    kind: "quote",
    kicker: "RESEARCH QUESTION",
    title: "What we would measure next",
    quote: "Which stages can independent build verification and DNS monitoring identify in a signed-update lab, and how many false positives does each control produce?",
    support: "The lab verifies the vendor's signature and has DNS visibility. It has no independent provenance check and no benign baseline. No results are claimed yet.",
    note: `Target timing: 40 seconds.

Ask it in one breath, not as a reading. Then separate the two halves: what can be seen before release, and what can be seen after installation.

Be explicit that the lab has the vendor's signature check, not independent provenance. Those are different controls and the distinction matters.

This is a plan, not a result. Say so.

Transition: so what does a signature actually prove?`,
  },
  {
    kind: "refs",
    kicker: "SOURCES",
    title: "Further reading",
    items: [
      "Mandiant. SUNBURST Additional Technical Details. 24 December 2020.",
      "CrowdStrike. SUNSPOT: An Implant in the Build Process. 11 January 2021.",
      "FireEye/Mandiant. Highly Evasive Attacker Leverages SolarWinds Supply Chain. 13 December 2020.",
      "Microsoft. Deep dive into the Solorigate second-stage activation. 20 January 2021.",
      "CISA. AA20-352A, Advanced Persistent Threat Compromise. 17 December 2020.",
      "SEC. In the Matter of Mimecast Limited, Release 33-11322. 22 October 2024.",
      "GAO. Cybersecurity: Federal Response to SolarWinds and Microsoft Exchange Incidents. 2022.",
      "SEC. In the Matter of Check Point Software Technologies. 2024.",
      "DOJ. Statement on the intrusion into the O365 email environment. 2022.",
      "Torres-Arias et al. in-toto. USENIX Security 2019.",
      "Ladisa et al. SoK: Attacks on Open-Source Software Supply Chains. IEEE S&P 2023.",
      "Benedetti et al. Reproducible packaging in open-source ecosystems. ICSE 2025.",
      "Manasrah et al. DGA-based botnet detection using DNS traffic. 2022.",
    ],
    footnote: "Full list with URLs in deliverables/report/main.pdf, References.",
    note: `Fifteen seconds, or skip entirely.

Point at the slide and say the full list is in the report. Do not read it.

The six papers and the SEC and DOJ documents are in the reference list of the report.`,
  },
  {
    kind: "close",
    kicker: "CLOSE",
    title: "Signatures answer the wrong question",
    lines: [
      "SUNSPOT changed one file during the build; the supplier signed the result and customers installed it.",
      "The lab reproduces the trust failure, the check-in and the mode selection. It stops before the intrusion.",
      "A signature tells you who signed it. It cannot tell you what the build contained.",
    ],
    note: `Target timing: 0 seconds.

Close on the last line and then stop. Do not add a summary.

If there is time, add the boundary in one sentence before it: no second stage, no lateral movement, no collection.

Invite questions about the lab, the detection limits, or the literature.`,
  },
];
