# Task 5 demo runbook

Short version of the live demo in `tasks/task05-poc`. [playbook.md](./playbook.md) explains how the lab works.

## Before the session

1. Bring the stack up from `tasks/task05-poc`, as described in *Start and control* in the playbook.
2. Wait until the dashboard lists every service as running.
3. Open Dashboard, Package Index, Build & Release, Orion Network Manager, Operator Console and Blue Team, in that order. The Attack story ribbon on the dashboard tracks the run from Build to Response; it lights a phase as each event lands.
4. Reset once. Confirm client V2, coordinator `PASSIVE`, tap `forwarding`, empty tables, and an empty Package Index.
5. Rehearse one dependency publish and pipeline run, then reset again. Never start with V3 already published; the pipeline refuses a second run until the channel is reset.
6. If anyone edited `registry/payload/orion_support.py`, rebuild the registry image; the package archive is generated from that file. There is no separate sample zip to rebuild.
7. Check the tap is forwarding and the packet count is moving. Zoom the browser so the tables read from the back row.

## Steps

1. **Frame it.** On the dashboard, say the customer verifies a signed update correctly and still installs a backdoor, because the supplier's build put one inside the package the supplier signed. Add that the packets, signatures and commands are real, and that the implant is a Python reimplementation of documented behaviour, not the original binary.
2. **Baseline.** Client tab: V2, clean history, no registered components. Nothing looks wrong yet, and nothing will later either.
3. **Publish the dependency and run the pipeline.** Package Index: publish `orion-compat` `2.0.0`; the internal index has `1.4.2`, so the public package is now the higher version. Build & Release: choose **Stable · mandatory** and click **Run release pipeline**. The stages fill in order: checkout, build, manifest, package, sign, publish. The build log says `resolved orion-compat 2.0.0 from the public index (internal 1.4.2)`, the install hook changes `orion_support.py`, and the manifest is generated afterwards and pins the changed hash. Say the source is clean and the signed artifact is not. Signing and publishing are pipeline jobs; there is nothing else to click.
4. **Delivery.** Client: after the pipeline publishes, the status reads `V3 will install in 20s`. Use the countdown to explain the build and the trust path, then watch found, downloaded, verified, installed, and one line naming the component. Say the catalog digest, the RSA signature and the component digest all passed. That is the claim of the lab, so do not rush it. If V3 does not appear, check the countdown and the next poll.
5. **Check-in.** Operator: open a decoded row. Mode 4 then 5, with host, user, uid and checksum. Say the label is base32 over an XOR'd record, the coordinator decoded it and answered with the activation address, and the CNAME handoff supplied the C2 host. Read the hostname off the screen and use that name; if it says `victim`, say `victim`. No rows means the coordinator is not `ACTIVE` or the component did not start.
6. **C2.** Show the POST: one per interval to `/swip/upd/orion.improvementprogram.asmx`, an `Orion/2020.2.4` agent string, Improvement Program fields. Nothing in it names a command. The giveaways are the bare private address and a Windows agent string sent from a Linux host. Say the lab uses plain HTTP so the room can see the body.
7. **Task.** All beacons, type `id; sleep 1; uname -a`, send. The sleep keeps the shell alive long enough for the host sensor to see it. The exit code and output return in the next upload. Say it is deliberately benign and guarded against destructive commands. For the data beat, send `collect customers.csv` instead; it expands to `base64 -w0` on the decoy file, the result upload is large enough for `T5-EXFIL-001`, and the host table shows the `base64` child.
8. **Detect.** Blue Team, bottom-up: first contact with the updater, which is benign and shows the rule working, then coordinator first contact, decoded check-ins, interval statistics after four queries, and the POST. Expand one event for the hex excerpt and pcap link. The sensor reads the capture, not the service logs. The Host processes table is the separate `/proc` sensor: it shows the component and the shell it started. If you collected, the large upload is `T5-EXFIL-001` and the port-9000 bytes jump. The ribbon's Detection phase may already be lit before you send the task; that is the point, the beacon itself is the tell.
9. **Contain.** Press **block** under resolver. The console goes quiet, the implant sends one final mode-3 check-in and exits. Optionally restore and use **isolate** for the second mechanism. Do not press **APPLY** while blocked; the lab refuses it and says why.
10. **Close.** One sentence on what the lab shows and one on what it does not: the build resolves a higher public version, the signature only proves who signed, and dependency confusion is simulated; the real incident was SUNSPOT, and encryption and the follow-on intrusion are not modelled.

If time is short, cut step 7 and the second mechanism in step 9. Never cut step 4.

## 60-second version

Reset, publish `orion-compat 2.0.0` in the Package Index, run the pipeline, use the 20-second countdown to set up the delivery, watch the install, open one decoded check-in, block the suffix. Say the build sentence, the delivery sentence and the detection sentence.

## Questions to expect

| Question | Answer |
| --- | --- |
| Is this real SUNBURST? | No. It reimplements the behaviour Mandiant described: encoded check-in, mode byte, CNAME handoff, Improvement Program shape. |
| Did you run the actor's tools? | Not in this segment. The chain follows documented techniques. Tool detonation is separate work. |
| Why Python, not a DLL? | The lab is Linux. What is reproduced is a component arriving inside a signed package, not the file format. |
| Is the detection real? | The rules read packets, but the checksum rule uses the implant's encoder and the key is fixed. The honest claim is that the traffic is decodable and periodic once captured. |
| Why a 4-second beacon? | Compression. The interval rule fires on the fourth query instead of the fourth day. |
| Is the build compromise real? | The public index and install hook are real in the lab, but this is dependency confusion, not SUNSPOT. The real incident was SUNSPOT; the property is a build that trusts code outside the source repository. |
| What is dependency confusion? | The build resolves `orion-compat` from an internal index and a public index and picks the highest version. Publishing `2.0.0` publicly beats the internal `1.4.2`; the public package's install hook runs in the build. |
| Why did the build choose 2.0.0? | The resolver compares versions from both indexes and takes the highest. There is no lockfile, hash pin, or namespace scoping. |
| What is missing? | The public index is simulated; the resolver and install hook are real. No reconnaissance, no encryption, no persistence, no lateral movement. |
| What does collect do? | It expands `collect customers.csv` to `base64 -w0` on the fake file in the victim, and the base64 result returns in the telemetry block. The large upload trips `T5-EXFIL-001`. |
| Can the tap see process creation? | No. The tap sees packets; the Host processes table reads `/proc` for the component and its children. A short command can finish between polls, so the demo uses `id; sleep 1; uname -a`. |

## What not to claim

- That the demo recreates SUNBURST. It recreates documented behaviour.
- That this is exactly SUNSPOT. The lab uses dependency confusion to expose the same trust boundary: the build trusts code the source repository does not control.
- That these rules would find the real implant. Two depend on lab knowledge and two more cannot fire with a single host.
- That the client's verification was bypassed. It passed, correctly, and that is the point.
- That the traffic looks like Orion without adding that this is plain HTTP inside a lab.

## If something breaks

| Symptom | Do this |
| --- | --- |
| No V3 on the client after publish | Wait for the 20s countdown; check Generation and the publish message |
| Build resolves 1.4.2, not 2.0.0 | Publish `orion-compat 2.0.0` in Package Index; check the pipeline log |
| Package Index empty after reset | Expected; publish the package before running the pipeline |
| Build refused | V3 is already published or a run is in progress; reset or wait |
| V3 installed, no check-in | Apply `ACTIVE`, then check the component inventory; reset if it is absent |
| Check-ins decoded, no beacon | Confirm the coordinator is `selected`; reset |
| No alerts at all | Reset and read the tap error |
| Mode change refused | A resolver block is active; clear it in Blue Team or reset |
| Reset reports one failed half | Read which half failed and reset again; the other half did run |
| Command queued, no result | Apply `ACTIVE` and send again |

Reset between rehearsals and after the talk, through the dashboard. Restarting containers is not enough: the release volume keeps V3 and the client reinstalls it on the next poll.
