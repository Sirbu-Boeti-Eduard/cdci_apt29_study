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
    claim: "An update carrying a backdoor reached as many as 18,000 customers. What did the signature prove?",
    subtitle: "From SUNSPOT to a controlled recreation in Mininet and Docker",
    team: [
      "SÎRBU BOEȚI Eduard Cristian · FLORESCU Georgiana-Iuliana",
      "BAZGA Mihai-Carol · GUESMI Emna · MĂCIUCĂ Teodor-Alexandru",
    ],
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
    lead: "APT29 is attributed to Russia's Foreign Intelligence Service. Microsoft calls it Midnight Blizzard or NOBELIUM, Mandiant used UNC2452 for SolarWinds, and older reporting says Cozy Bear or The Dukes.",
    items: [
      { head: "At least 2008", text: "Five Eyes agencies date SVR cyber operations to 2008 and list APT29 among the names used for them." },
      { head: "2013 to 2019", text: "Operation Ghost targets foreign ministries in at least three European countries and an EU embassy in Washington." },
      { head: "2015 to 2016", text: "Cozy Bear is on the DNC network from summer 2015; Fancy Bear arrives separately in April 2016." },
      { head: "2023 to 2025", text: "TeamCity exploitation in 2023, then phishing against German parties, diplomats and more than 100 organisations." },
    ],
    note: `Target timing: 50 seconds.

Say the names once, then the pattern: a long-running espionage group that keeps returning to governments and suppliers.

Do not linger on the DNC. One sentence, then move.

Transition: the services it uses to hide in plain sight.`,
  },
  {
    kind: "bullets",
    kicker: "ONLINE PRESENCE",
    title: "Infrastructure that borrows trust",
    lead: "APT29 rarely needs its own domain to look legitimate. It uses services the target already permits.",
    items: [
      { head: "Twitter, 2015", text: "HAMMERTOSS generated a new handle each day and read commands from a tweet that pointed to an image." },
      { head: "Constant Contact, 2021", text: "A compromised USAID account sent phishing to about 3,000 accounts at more than 150 organisations." },
      { head: "Embassy websites, 2023", text: "Polish authorities traced embassy-themed mail to a compromised site and an ENVYSCOUT script." },
      { head: "Teams, 2023", text: "New onmicrosoft.com tenants posed as support and pushed users to approve an Authenticator prompt." },
    ],
    statement: "No public source names a specific wallet. The advisory record confirms cryptocurrency use, not an address.",
    note: `Target timing: 50 seconds.

This is the Task 3 online-presence material, condensed. The pattern matters more than the individual lures: each one arrives through a service the target already allows.

Twitter was the command channel in 2015. Constant Contact carried the 2021 USAID phishing. A compromised embassy website carried ENVYSCOUT in 2023. Teams carried the 2023 credential phishing.

Close the wallet question directly: the advisory says cryptocurrency bought the infrastructure, but no source names an address or payment. Do not invent one.

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
    note: `Target timing: 50 seconds.

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
    note: `Target timing: 100 seconds.

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
    note: `Target timing: 80 seconds.

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
    note: `Target timing: 130 seconds.

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
    note: `Target timing: 100 seconds.

The channel is the point: it looked like the product's own telemetry, so signature matching had nothing to work with.

The second stage exists to break the link between the backdoor and the tool. Golden SAML bypassed MFA because the cloud service trusted the token's signer.

Do not explain SAML unless asked. One sentence: they stole the certificate that signs login tokens.

Transition: the record behind the chain.`,
  },
  {
    kind: "table",
    kicker: "TTPs, TOOLS AND INDICATORS",
    title: "The record behind the chain",
    head: ["Area", "What the record shows"],
    rows: [
      ["Techniques", "Supply-chain compromise (T1195.002), code signing (T1553.002), DGA (T1568.002), DNS and web C2 (T1071.004, T1071.001), SAML forgery (T1606.002)."],
      ["Tools", "SUNSPOT ran in the build; SUNBURST shipped in Orion; TEARDROP and Raindrop loaded Cobalt Strike; AdFind and Mimikatz supported access and collection."],
      ["Vulnerabilities and apps", "None in Orion. Citrix, Pulse Secure, Fortinet, Zimbra and TeamCity belong to other campaigns; AD FS, Microsoft 365 and Teams supported cloud access and phishing."],
      ["Protocols and indicators", "DNS check-in with an A-record mode and a CNAME handoff, OIP-shaped HTTP(S), and SAML. Key indicators are avsvmcloud[.]com, the SUNBURST and SUNSPOT hashes, and Orion builds 2019.4 HF5, 2020.2 and 2020.2 HF1."],
    ],
    statement: "The tools explain the chain. The CVEs show the group's other way in.",
    note: `Target timing: 60 seconds.

This is the Task 2 material: TTPs, tools, vulnerabilities, protocols and indicators. Do not read the table. Point at one row per beat.

Techniques: supply-chain compromise and code signing carry the incident; DGA, DNS and web C2 carry the check-in; SAML forgery carries the cloud access.

Tools: SUNSPOT is the build implant, SUNBURST the backdoor, TEARDROP and Raindrop the loaders, Cobalt Strike the hands-on tool, AdFind and Mimikatz the discovery and credential tools.

Vulnerabilities: the Orion chain had none. The CVEs in the table are the group's other route into networks. Say that clearly so the table does not imply Orion was patched into safety.

Protocols and indicators: DNS for check-in and mode, HTTP(S) for the telemetry-shaped channel, SAML for forged tokens. The domain, hashes and affected builds are the indicators a defender can key on.

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
    note: `Target timing: 70 seconds.

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
    note: `Target timing: 80 seconds.

This is the pivot. We did not rebuild SUNBURST; we rebuilt the trust failure around it. A supplier signs a package that carries code, and a client verifies it correctly. The lab's build performs a dependency-confusion swap, not SUNSPOT's source-file replacement, but the signed package still comes from the supplier's own pipeline.

If someone asks whether we broke the verification, the answer is no, and that is the point.

Slow down here. Everything after this slide depends on the room accepting this sentence.

Transition: so we built the smallest thing that could prove the claim.`,
  },
  {
    kind: "figure",
    kicker: "THE LAB",
    title: "One network, one victim, one capture point",
    caption: "Every victim packet crosses the bridge; tcpdump records DNS, the updater and the receiver. The rules read the capture, not the service logs.",
    svg: `<svg viewBox="0 0 900 260" role="img" aria-label="Lab topology: victim, capture bridge, switch and three services">
  <title>Lab topology</title>
  <defs>
    <marker id="arrow" markerWidth="8" markerHeight="8" refX="7.5" refY="4" orient="auto">
      <path d="M0,0 L8,4 L0,8 z" fill="#17212b"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="900" height="260" fill="#ffffff"/>

  <rect x="16" y="94" width="150" height="72" fill="#ffffff" stroke="#17212b" stroke-width="1.6"/>
  <text x="91" y="120" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="17" font-weight="bold" fill="#17212b">victim</text>
  <text x="91" y="140" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="13.5" fill="#444">orion-01</text>
  <text x="91" y="157" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="13.5" fill="#444">10.0.0.5</text>

  <line x1="168" y1="130" x2="209" y2="130" stroke="#17212b" stroke-width="1.6" marker-end="url(#arrow)"/>

  <rect x="212" y="88" width="150" height="84" fill="#ffffff" stroke="#b42318" stroke-width="1.8"/>
  <text x="287" y="122" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="17" font-weight="bold" fill="#17212b">sensor · br0</text>
  <text x="287" y="148" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="12" font-weight="bold" letter-spacing="1.2" fill="#b42318">CAPTURE POINT</text>

  <line x1="364" y1="130" x2="405" y2="130" stroke="#17212b" stroke-width="1.6" marker-end="url(#arrow)"/>

  <rect x="408" y="104" width="100" height="52" fill="#ffffff" stroke="#17212b" stroke-width="1.6"/>
  <text x="458" y="126" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="17" font-weight="bold" fill="#17212b">s1</text>
  <text x="458" y="145" text-anchor="middle" font-family="Helvetica, Arial, sans-serif" font-size="13" fill="#444">10.0.0.0/24</text>

  <line x1="510" y1="130" x2="557" y2="56" stroke="#17212b" stroke-width="1.6" marker-end="url(#arrow)"/>
  <line x1="510" y1="130" x2="557" y2="130" stroke="#17212b" stroke-width="1.6" marker-end="url(#arrow)"/>
  <line x1="510" y1="130" x2="557" y2="204" stroke="#17212b" stroke-width="1.6" marker-end="url(#arrow)"/>

  <rect x="560" y="28" width="320" height="56" fill="#ffffff" stroke="#17212b" stroke-width="1.6"/>
  <text x="580" y="52" font-family="Helvetica, Arial, sans-serif" font-size="16" font-weight="bold" fill="#17212b">updater</text>
  <text x="580" y="70" font-family="Helvetica, Arial, sans-serif" font-size="13.5" fill="#444">10.0.0.2:8000</text>

  <rect x="560" y="102" width="320" height="56" fill="#ffffff" stroke="#17212b" stroke-width="1.6"/>
  <text x="580" y="126" font-family="Helvetica, Arial, sans-serif" font-size="16" font-weight="bold" fill="#17212b">DNS coordinator</text>
  <text x="580" y="144" font-family="Helvetica, Arial, sans-serif" font-size="13.5" fill="#444">10.0.0.3:53</text>

  <rect x="560" y="176" width="320" height="56" fill="#ffffff" stroke="#17212b" stroke-width="1.6"/>
  <text x="580" y="200" font-family="Helvetica, Arial, sans-serif" font-size="16" font-weight="bold" fill="#17212b">receiver</text>
  <text x="580" y="218" font-family="Helvetica, Arial, sans-serif" font-size="13.5" fill="#444">10.0.0.4:9000</text>
</svg>`,
    note: `Target timing: 70 seconds.

Orient the room in one pass, left to right: the victim, the bridge, the switch, then the three services. The victim has no route to the switch except through the sensor.

That design choice is the argument. Every detection claim is about the wire, not about logs the lab wrote for itself.

Transition: here is the install the lab produced.`,
  },
  {
    kind: "checks",
    kicker: "EVIDENCE",
    title: "Every check passed",
    lead: "The build generates the manifest after the install hook runs, so it pins the swapped file and the pipeline signs exactly those bytes. The client history records found, downloaded, verified, installed, then the registered component.",
    checks: [
      { label: "Catalogue digest", detail: "The package matches the digest published in the catalogue." },
      { label: "RSA signature", detail: "Verified with openssl against a pinned public key the client cannot write." },
      { label: "Component digest", detail: "The extracted module matches the SHA-256 declared in the manifest: 28cbdfb0…61810." },
    ],
    statement: "Then the installer registered orion-improvement-program and started it.",
    note: `Target timing: 120 seconds.

Walk the three checks in order. The key is pinned and the client cannot write it, so there is no local bypass.

The component digest is the one to point at: 28cbdfb0, ending 61810, the hash of the file the install hook left in the workspace. The approved source component hashes to 55f86d90; the build log shows the public 2.0.0 won and the manifest pins 28cb after the hook. The client history shows found, downloaded, verified, installed, then the registered component.

If asked for proof: the signed package and manifest are part of the lab, and a run produces the capture and sensor state. No run output is stored, so do not claim one is.

Transition: and here is what we did not build.`,
  },
  {
    kind: "table",
    kicker: "SCOPE",
    title: "What runs, what is reduced, what is absent",
    head: ["Kill-chain phase", "In the lab", "Status"],
    rows: [
      ["Reconnaissance", "Nothing", "Not modelled"],
      ["Weaponization", "Higher public orion-compat replaces the component before signing", "Performed, reduced"],
      ["Delivery", "Signed package, stable channel, HTTP download", "Implemented"],
      ["Exploitation", "No vulnerability; the client trusts the signed package", "Not applicable"],
      ["Installation", "Installer registers the component and starts it", "Implemented, reduced"],
      ["Command and control", "Encoded check-in, mode by answer, CNAME for resolution, POST", "Implemented, reduced"],
      ["Actions on objectives", "One optional benign shell command, plus a decoy-file read", "Implemented, reduced"],
    ],
    statement: "The lab reproduces the trust path and the check-in, not the actor's code.",
    note: `Target timing: 60 seconds.

This is the scope slide, and it is deliberately brief. Weaponization is performed, but reduced: the build trusts a higher public dependency and runs its install hook, which is dependency confusion, not SUNSPOT's source-file swap. Reconnaissance is absent. Exploitation is not applicable because there is no vulnerability.

Delivery and installation are implemented and run during the demo. Tasking is reduced: one process, one command, no persistence.

Transition: so what did the defender see?`,
  },
  {
    kind: "bullets",
    kicker: "DETECTION",
    title: "Eight rules on the wire",
    lead: "The sensor works from the capture, not from service logs. Eight rules cover the check-in label, the beacon cadence, the upload and first contact.",
    items: [
      { head: "Check-in label", text: "Decodes to host, user, uid, mode and checksum. The checksum separates a valid record from a lookalike." },
      { head: "Beacon cadence", text: "Successive queries hold a four-second interval. The interval rule fires after the fourth query." },
      { head: "Upload", text: "An Improvement Program POST to a non-global address. The optional collect task pushes the upload above 4 KB." },
      { head: "Host context", text: "A separate /proc sensor follows the component and its descendants, and records the shell a task starts." },
    ],
    statement: "The capture shows a decodable, periodic check-in and a telemetry upload.",
    note: `Target timing: 90 seconds.

Walk the Blue Team view bottom-up: updater first contact, which is benign and shows the rule working; coordinator first contact; decoded check-ins; interval statistics after four queries; then the POST.

The rules read the capture. The host table is a separate /proc sensor and shows the component and its child process.

If you ran collect, the upload crosses 4 KB and T5-EXFIL-001 appears. The point is that the beacon is visible before any task is sent.

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
    note: `Target timing: 70 seconds.

Group the table in three: the first three act before signing, the signing key protects a step the attackers did not need to break, and the last two act after installation.

The ratings are our judgement on a four-point scale, not measurements. Say that once.

The line that matters: the controls with the most effect are the ones that require rebuilding someone else's process.

Transition: that is where the research stops.`,
  },
  {
    kind: "cards",
    kicker: "LITERATURE",
    title: "Six papers, three views",
    cards: [
      { head: "Before release", tag: "in-toto (2019) · reproducible packaging (2025)", text: "Provenance checks record which steps ran; independent rebuilds give a comparison point. Neither proves the code is benign." },
      { head: "Attack surface", tag: "Backstabber's Knife (2020) · SoK (2023) · Gokkaya (2026)", text: "Trusted distribution carries malicious code; taxonomies and risk reviews map the controls, but they do not test them here." },
      { head: "After installation", tag: "DGA detection (2022)", text: "DNS query-name analysis detects generated domains, but not our fixed-domain check-in." },
    ],
    statement: "No paper tests provenance verification and DNS monitoring together on a signed update.",
    note: `Target timing: 30 seconds.

Six papers, all since 2019. Two check build integrity, three map the attack surface and controls, one watches DNS. None tests build verification and DNS monitoring together.

Do not read the venues. Point at the tags and move.

Transition: which is the gap the research question comes from.`,
  },
  {
    kind: "quote",
    kicker: "RESEARCH QUESTION",
    title: "What we would measure next",
    quote: "Which stages can independent build verification and DNS monitoring identify in a signed-update lab, and how many false positives does each control produce?",
    support: "The lab verifies the vendor's signature and has DNS visibility. It has no independent provenance check and no benign baseline. No results are claimed yet.",
    note: `Target timing: 30 seconds.

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
