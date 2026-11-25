# Task 5 demo runbook

Short version of the live demo in `tasks/task05-poc`. [playbook.md](./playbook.md) explains how the lab works.

## Before the session

1. Bring the stack up from `tasks/task05-poc`, as described in *Start and control* in the playbook.
2. Wait until the dashboard lists every service as running.
3. Open Dashboard, Build & Release, Orion Network Manager, Operator Console and Blue Team, in that order.
4. Reset once. Confirm client V2, coordinator `PASSIVE`, tap `forwarding`, empty tables.
5. Rehearse one build and publish, then reset again. Never start with V3 already published; the pipeline refuses a second build or publish until the channel is reset.
6. If anyone edited `pipeline/payload/orion_support.py`, the build picks it up automatically. Rebuild `sample-v3-malicious.zip` only if you plan to use the upload path; a stale digest is rejected there.
7. Check the tap is forwarding and the packet count is moving. Zoom the browser so the tables read from the back row.

## Steps

1. **Frame it.** On the dashboard, say the customer verifies a signed update correctly and still installs a backdoor, because the supplier's build put one inside the package the supplier signed. Add that the packets, signatures and commands are real, and that the implant is a Python reimplementation of documented behaviour, not the original binary.
2. **Baseline.** Client tab: V2, clean history, no registered components. Nothing looks wrong yet, and nothing will later either.
3. **Build and publish.** Build & Release: click **Build from source**. The log shows the source hash, the `service-compat` step changing `orion_support.py`, and the manifest pinning the changed hash. Say the source is clean and the signed artifact is not. Sign it, choose **Stable · mandatory**, publish. The upload path still works with `sample-v3-malicious.zip` if you want the older story.
4. **Delivery.** Client: found, downloaded, verified, installed, and one line naming the component. Say the catalog digest, the RSA signature and the component digest all passed. That is the claim of the lab, so do not rush it. If V3 does not appear, wait three seconds for the next poll.
5. **Check-in.** Operator: open a decoded row. Mode 4 then 5, with host, user, uid and checksum. Say the label is base32 over an XOR'd record, the coordinator decoded it and answered with the activation address, and the CNAME handoff supplied the C2 host. Read the hostname off the screen and use that name; if it says `victim`, say `victim`. No rows means the coordinator is not `ACTIVE` or the component did not start.
6. **C2.** Show the POST: one per interval to `/swip/upd/orion.improvementprogram.asmx`, an `Orion/2020.2.4` agent string, Improvement Program fields. Nothing in it names a command. The giveaways are the bare private address and a Windows agent string sent from a Linux host. Say the lab uses plain HTTP so the room can see the body.
7. **Task.** All beacons, type `id; uname -a`, send. The exit code and output return in the next upload. Say it is deliberately benign and guarded against destructive commands.
8. **Detect.** Blue Team, bottom-up: first contact with the updater, which is benign and shows the rule working, then coordinator first contact, decoded check-ins, interval statistics after four queries, and the POST. Expand one event for the hex excerpt and pcap link. The sensor reads the capture, not the service logs.
9. **Reveal the build.** Build & Release: click **Verify against source**. It rebuilds without the build step and reports that the artifact's component hash differs from the source. Say: the signature is valid; the build is not.
10. **Contain.** Press **block** under resolver. The console goes quiet, the implant sends one final mode-3 check-in and exits. Optionally restore and use **isolate** for the second mechanism. Do not press **APPLY** while blocked; the lab refuses it and says why.
11. **Close.** One sentence on what the lab shows and one on what it does not: build-time injection is simulated by a scripted step; encryption and the follow-on intrusion are not modelled.

If time is short, cut step 7 and the second mechanism in step 10. Never cut step 4.

## 60-second version

Reset, build, sign, publish, watch the install, open one decoded check-in, verify the build, block the suffix. Say the build sentence, the delivery sentence and the detection sentence.

## Questions to expect

| Question | Answer |
| --- | --- |
| Is this real SUNBURST? | No. It reimplements the behaviour Mandiant described: encoded check-in, mode byte, CNAME handoff, Improvement Program shape. |
| Did you run the actor's tools? | Not in this segment. The chain follows documented techniques. Tool detonation is separate work. |
| Why Python, not a DLL? | The lab is Linux. What is reproduced is a component arriving inside a signed package, not the file format. |
| Is the detection real? | The rules read packets, but the checksum rule uses the implant's encoder and the key is fixed. The honest claim is that the traffic is decodable and periodic once captured. |
| Why a 4-second beacon? | Compression. The interval rule fires on the fourth query instead of the fourth day. |
| Is the build compromise real? | No. The build step is scripted; the real build host is not attacked. What is real is the order: the manifest is generated after the swap, so every downstream check passes. |
| What is missing? | Build-time injection is simulated by a scripted step; no reconnaissance, no encryption, no persistence, no lateral movement. |

## What not to claim

- That the demo recreates SUNBURST. It recreates documented behaviour.
- That the build environment is genuinely compromised. The swap is a scripted build step; the point is that the manifest is written after it.
- That these rules would find the real implant. Two depend on lab knowledge and two more cannot fire with a single host.
- That the client's verification was bypassed. It passed, correctly, and that is the point.
- That the traffic looks like Orion without adding that this is plain HTTP inside a lab.

## If something breaks

| Symptom | Do this |
| --- | --- |
| No V3 on the client after publish | Wait three seconds, check Generation, read the publish message |
| Build refused | V3 is already published; reset the channel first |
| Verify reports a match | The artifact came from the upload path; build from source again |
| V3 installed, no check-in | Apply `ACTIVE`, then check the component inventory; reset if it is absent |
| Check-ins decoded, no beacon | Confirm the coordinator is `selected`; reset |
| No alerts at all | Reset and read the tap error |
| Mode change refused | A resolver block is active; clear it in Blue Team or reset |
| Reset reports one failed half | Read which half failed and reset again; the other half did run |
| Command queued, no result | Apply `ACTIVE` and send again |

Reset between rehearsals and after the talk, through the dashboard. Restarting containers is not enough: the release volume keeps V3 and the client reinstalls it on the next poll.
