export const meta = {
  title: "APT29 and the SolarWinds Supply-Chain Compromise",
  subtitle: "From SUNSPOT to a controlled recreation in Mininet and Docker",
  event: "CDCI Assignment 1",
  date: "November 2026",
  aspect: "16 / 9",
};

export const slides = [
  {
    kind: "title",
    kicker: "CDCI Assignment 1",
    title: "APT29 and the SolarWinds Supply-Chain Compromise",
    subtitle: "From SUNSPOT to a controlled recreation in Mininet and Docker",
    meta: ["Tracking an APT group", "November 2026"],
    note: `Target timing: 40 seconds.

Open with the fact, not the title. In December 2020 a backdoor reached SolarWinds customers inside a correctly signed Orion update. Nothing in the delivery path was broken: the supplier built it, the supplier signed it, customers installed it.

Say that the talk covers the actor, the incident, the public evidence of victims and infrastructure, our recreation in Mininet and Docker, and the literature behind it.

Transition: start with who APT29 is.`,
  },
  {
    kind: "bullets",
    kicker: "THE ACTOR",
    title: "One group, many names",
    lead: "APT29 works for Russia's Foreign Intelligence Service. Microsoft calls it Midnight Blizzard or NOBELIUM, Mandiant used UNC2452 for SolarWinds, older reporting says Cozy Bear or The Dukes.",
    items: [
      { head: "At least 2008", text: "Five Eyes agencies date SVR cyber operations to 2008 and list APT29 among the names used for them." },
      { head: "2013 to 2019", text: "Operation Ghost targets foreign ministries in at least three European countries and an EU embassy in Washington." },
      { head: "2015 to 2016", text: "Cozy Bear is on the DNC network from summer 2015; Fancy Bear arrives separately in April 2016." },
      { head: "2020 onward", text: "COVID-19 vaccine research, TeamCity in 2023, then phishing against diplomats and parties in 2024 and 2025." },
    ],
    note: `Target timing: 70 seconds.

The naming matters because the same activity appears under different labels in different reports. Say the names once, then move on.

Use the timeline to show this is a long-running espionage group, not a one-off. The DNC point is worth one sentence: CrowdStrike found two separate actors and no evidence they worked together.

Transition: the operation itself.`,
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
    statement: "Receiving the update proves exposure. It does not prove intrusion.",
    note: `Target timing: 50 seconds.

These three numbers are routinely conflated. Up to about 18,000 customers downloaded the affected builds. SolarWinds estimated fewer than 100 were actually compromised, and nine U.S. federal agencies were reported among them.

Make the distinction explicit, because it is the difference between a supply-chain exposure and a campaign.

Transition: how the update got the backdoor.`,
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
    note: `Target timing: 75 seconds.

CrowdStrike's analysis is the source. The important detail is that the repository looked untouched. The malicious code was compiled by SolarWinds' own build process, so it inherited the supplier's legitimacy.

Mention that the implant checked MD5 hashes before and after the swap, which is why the build produced a consistent artifact.

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
      { head: "First contact", text: "It builds a subdomain under avsvmcloud[.]com with a domain generation algorithm." },
    ],
    note: `Target timing: 70 seconds.

The dormancy is a detection evasion measure, and each check defeats a different observer: the delay defeats sandboxes, the domain check defeats analyst machines, the tool list defeats endpoint security.

The first check-in encodes a user identifier and the victim's internal domain. That is how the operators knew which organisation each infection belonged to.

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
    statement: "The malware required a CNAME because it could not use a raw address.",
    note: `Target timing: 70 seconds.

This is the part people remember. The coordinator does not send commands over DNS. It sends an address range, and the range selects a mode. A CNAME response supplies the host for the next stage.

Mandiant's point, which we return to in the detection slide, is that the CNAME is the stronger signal: a decoded domain only proves the backdoor was there.

Transition: what the active channel looked like.`,
  },
  {
    kind: "bullets",
    kicker: "STAGE 4: OPERATIONS",
    title: "Control traffic that looked like telemetry",
    lead: "Active traffic imitated the Orion Improvement Program: JSON under 10,000 bytes with userId, sessionID and a steps array, and commands hidden in the response body.",
    items: [
      { head: "Tasking", text: "Process execution, file transfer, registry access and reboot." },
      { head: "Second stage", text: "TEARDROP ran in memory and read its payload from a file disguised as an image; Raindrop did the same job differently." },
      { head: "Cobalt Strike", text: "Beacon gave the operators hands-on control, in at least one case started through an IFEO value on dllhost.exe." },
      { head: "Objective", text: "AdFind, DCSync and forged SAML tokens reached Microsoft 365 mailboxes." },
    ],
    note: `Target timing: 75 seconds.

The channel is the interesting part: it looked like the product's own telemetry, so signature matching had nothing to work with.

The second stage is where the campaign became an intrusion. The loaders exist to break the link between the backdoor and the tool, so discovering one did not reveal the other. Golden SAML then bypassed MFA because the cloud service trusted the forged token.

Transition: the public footprint of the group.`,
  },
  {
    kind: "cards",
    kicker: "ONLINE PRESENCE",
    title: "Trusted services instead of actor-owned sites",
    cards: [
      { head: "HAMMERTOSS, 2015", text: "A new Twitter handle each day pointed to an image on GitHub; the hashtag carried the offset and part of the key." },
      { head: "USAID, 2021", text: "A compromised Constant Contact account sent phishing to about 3,000 accounts at more than 150 organisations." },
      { head: "Teams, 2023", text: "New onmicrosoft.com domains inside compromised tenants posed as support and asked users to enter a code in the authenticator prompt." },
      { head: "Infrastructure", text: "Bought with false identities and cryptocurrency through resellers. No public report names a wallet." },
    ],
    note: `Target timing: 60 seconds.

The pattern across ten years is the same: use a service the target already permits. Twitter, Constant Contact, Teams, Dropbox, Microsoft Graph.

Say plainly that no government or vendor report names a specific wallet or payment. The advisory confirms cryptocurrency is used for infrastructure, not that a traceable wallet exists.

Transition: the cost to the victims.`,
  },
  {
    kind: "cards",
    kicker: "VICTIMS AND IMPACT",
    title: "Three customers, three kinds of loss",
    cards: [
      { head: "Mimecast", text: "A certificate used against five customers' cloud platforms, credentials for about 31,000 customers, and 58 to 76 percent of three code areas. USD 0.8 million in incident costs and a USD 990,000 SEC penalty." },
      { head: "U.S. Department of Justice", text: "Microsoft 365 accounts in 27 U.S. Attorneys' offices; at least 80 percent of employees in four New York districts. Access treated as covering all mail from May to December 2020." },
      { head: "Check Point", text: "Two infected Orion servers, activity from July to October 2020, two compromised accounts and attempted lateral movement. A USD 995,000 SEC penalty over its disclosures." },
    ],
    note: `Target timing: 75 seconds.

Two costs recur: incident response and disclosure risk. Mimecast and Check Point were penalised for how they described the incident, not for being breached.

For a managed service provider the exposure reaches customers whose credentials sat in the environment, which is why the certificate mattered beyond Mimecast.

Transition: why we rebuilt the trust path.`,
  },
  {
    kind: "quote",
    kicker: "THE QUESTION WE TESTED",
    title: "A valid signature answers a narrower question",
    quote: "The client installs the backdoor because every check passes.",
    support: "Not because a check was bypassed. The catalog digest, the RSA signature and the component digest all verify. The failure is in what the signature is asked to prove.",
    note: `Target timing: 55 seconds.

This is the thesis of the recreation. We did not rebuild SUNBURST. We rebuilt the trust failure around it: a supplier signs a package that carries code, and a client verifies it correctly.

If someone asks whether we broke the signature verification, the answer is no, and that is the point.

Transition: the lab that shows it.`,
  },
  {
    kind: "bullets",
    kicker: "THE LAB",
    title: "One network, one victim, one capture point",
    lead: "A Mininet network inside a Docker container, with five small web apps for the supplier, client, operator, presenter and defender.",
    items: [
      { head: "Pipeline", text: "Validates the manifest, checks every declared digest, and signs the package with the supplier key." },
      { head: "Delivery", text: "A stable update channel serves the catalog, the package and the signature over HTTP." },
      { head: "Victim", text: "The client verifies the catalog, the RSA signature and the component digest, then starts the declared component." },
      { head: "Visibility", text: "The victim's only link to the switch crosses a bridge, so tcpdump captures every packet." },
    ],
    note: `Target timing: 70 seconds.

Describe the topology in one pass: updater, DNS coordinator and receiver on one switch; the victim reaches it only through the bridge.

The key design choice is the sensor. It reads the capture file, not the application logs, so every detection claim is about the wire.

Transition: what actually ran.`,
  },
  {
    kind: "table",
    kicker: "WHAT RAN",
    title: "Executed, represented, or absent",
    head: ["Kill-chain phase", "In the lab", "Status"],
    rows: [
      ["Reconnaissance", "Nothing", "Not modelled"],
      ["Weaponization", "A prebuilt V3 package pins a component digest", "Represented"],
      ["Delivery", "Signed package, stable channel, HTTP download", "Executed"],
      ["Exploitation", "Client verifies and installs V3", "Executed"],
      ["Installation", "Installer registers the component and starts it", "Executed, reduced"],
      ["Command and control", "Encoded check-in, mode by answer, CNAME, POST", "Executed, reduced"],
      ["Actions on objectives", "One shell command and its output", "Executed, reduced"],
    ],
    note: `Target timing: 60 seconds.

Be precise about the word represented. The V3 package exists as an artifact, but there is no build system, so SUNSPOT's swap and restore is not performed.

Everything from delivery onward ran. Installation and tasking are reduced: one process, one command, no persistence.

Transition: show the verification result.`,
  },
  {
    kind: "checks",
    kicker: "EVIDENCE",
    title: "Every check passed",
    checks: [
      { label: "Catalog digest", detail: "The package matches the digest published in the catalog." },
      { label: "RSA signature", detail: "Verified with openssl against a pinned public key the client cannot write." },
      { label: "Component digest", detail: "The extracted module matches the SHA-256 declared in the manifest." },
    ],
    statement: "Then the installer registered orion-improvement-program and started it.",
    note: `Target timing: 65 seconds.

Walk the three checks in order. The signature key is pinned and not writable from the client, so there is no local tampering.

The result is a clean install of a malicious build. The client history shows found, downloaded, verified, installed and the registered component.

If asked for evidence: sample-v3-malicious.zip, the manifest, the capture at /tmp/task05-poc/capture/c2-traffic.pcap, and the sensor state file.

Transition: what the defender saw.`,
  },
  {
    kind: "bullets",
    kicker: "DETECTION",
    title: "Seven rules, five that can fire",
    lead: "The sensor decodes the check-in label, measures the interval, records first contact and flags the telemetry upload. Two rules need conditions a single-host lab does not produce.",
    items: [
      { head: "What works", text: "The check-in is decodable and periodic once captured, and the upload is visible on the wire." },
      { head: "What does not", text: "One rule imports the implant's own encoder, so a valid checksum proves the lab ran, not that an unknown implant exists." },
      { head: "The stronger signal", text: "Mandiant treats CNAME resolution as stronger evidence than a decoded DGA label." },
      { head: "The honest claim", text: "The lab shows what can be recovered from traffic, not what a defender should prioritise." },
    ],
    note: `Target timing: 75 seconds.

Do not oversell the rules. Five of seven can fire; the other two need a hand-made lookalike and a second source address.

The checksum rule is the one to caveat: it uses the same encoder as the payload, so it cannot distinguish our implant from an unknown one.

Mandiant's note cuts against our own rule set. Say that. It is more credible than claiming the rules would find SUNBURST.

Transition: what would have helped.`,
  },
  {
    kind: "table",
    kicker: "COUNTERMEASURES",
    title: "The strongest controls are the hardest to deploy",
    head: ["Control", "Effect", "Difficulty"],
    rows: [
      ["Build pipeline isolation", "High", "High"],
      ["Reproducible builds", "High for tampering", "Very high"],
      ["Independent artifact verification", "High", "High"],
      ["HSM-protected signing keys", "Low here", "Medium"],
      ["DNS anomaly detection", "High for visibility", "Medium"],
      ["EDR", "Medium", "Low to medium"],
    ],
    statement: "A customer cannot verify a build it did not perform.",
    note: `Target timing: 65 seconds.

Group the controls by where they act: before signing, at the customer, after installation.

The pattern is uncomfortable. The controls that would have caught the substitution sit before signing, and they are the ones that require rebuilding infrastructure and process.

Say the limit: the ratings are our assessment, not measured results. The lab did not test these controls.

Transition: the literature.`,
  },
  {
    kind: "cards",
    kicker: "LITERATURE",
    title: "Six papers, two defensive layers",
    cards: [
      { head: "Before release", text: "in-toto verifies build steps and artifact flow; reproducible builds give a comparison point; two taxonomies place the controls." },
      { head: "After installation", text: "DNS query-name analysis detects generated domains; malicious-package research shows how trusted distribution carries code and hides execution." },
      { head: "The gap", text: "No paper tests provenance verification and DNS monitoring together on a signed-update workflow in a lab." },
    ],
    note: `Target timing: 60 seconds.

Name the venues briefly: USENIX Security, IEEE S&P, ICSE, DIMVA, JISA and JKSU-CIS. All within the last seven years.

The two layers do different jobs. A signature identifies the signer; provenance addresses the build; DNS shows behaviour after installation. None of the papers tests the pair together.

Transition: the question that follows.`,
  },
  {
    kind: "quote",
    kicker: "RESEARCH QUESTION",
    title: "What we would measure next",
    quote: "Which stages of a compromised but legitimately signed software-update workflow can independent build-artifact verification and DNS activity monitoring identify in a controlled Mininet and Docker lab, and how many false positives does each control produce?",
    support: "Sub-questions separate detection before release from detection after installation, and ask what remains invisible when either control is used alone. The lab has DNS visibility, no artifact verification, and no benign baseline. No results are claimed yet.",
    note: `Target timing: 55 seconds.

Read the question once, slowly. Then say what it separates: detection before the artifact is released, and detection after it is installed.

The evaluation would run approved and tampered updates, compare artifacts, and label benign and malicious DNS traffic before quoting any detection rate.

Say clearly that this is a proposal. The assignment supplies the question and the plan, not the results.

Transition: close.`,
  },
  {
    kind: "close",
    kicker: "CLOSE",
    title: "Signatures answer the wrong question",
    lines: [
      "SUNSPOT changed one file during the build; the supplier signed the result and customers installed it.",
      "Our lab reproduces that trust failure, the DNS check-in and the mode selection, and stops before the intrusion.",
      "The controls that would help act before the signature exists, which is why they are hard to deploy.",
    ],
    note: `Target timing: 35 seconds.

Close on the single sentence: a signature proves who signed the artifact, not that the build was clean.

Then the honest boundary: no second stage, no lateral movement, no collection. The lab shows the trust path.

Thank the audience and invite questions on the lab, the detection limits or the literature.`,
  },
];
