# IR-GPS research notes

These notes back the design decisions in IR-GPS. Figures are paraphrased from the cited sources. Nothing here is a measurement of your environment.

## 1. The problem: the clock

The case for a time-first incident tool rests on how little time defenders have.

| Finding | Figure | Source |
|---|---|---|
| Average eCrime breakout time (initial access to first lateral movement), 2025 | 29 minutes, down from 48 in 2024 | CrowdStrike 2026 Global Threat Report |
| Fastest observed breakout | 27 seconds | CrowdStrike 2026 Global Threat Report |
| Detections that involved no malware | 82% | CrowdStrike 2026 Global Threat Report |
| Fastest data exfiltration after access in one case | about 4 minutes | CrowdStrike 2026 Global Threat Report |
| Global median attacker dwell time, 2025 | 14 days, up from 11 | Mandiant M-Trends 2026 |
| Median hand-off from an access broker to a secondary group, 2025 | 22 seconds, versus more than 8 hours in 2022 | Mandiant M-Trends 2026 |
| Average time to identify and contain a breach | 241 days, a nine-year low | IBM Cost of a Data Breach 2025 |
| Average breach cost | USD 4.44M globally, USD 10.22M in the US | IBM Cost of a Data Breach 2025 |

**What this means for the product.** Most attacker activity is short hops through trusted identities and tools, not malware you can quarantine. A responder needs an answer to "how long until the crown jewels, and what slows it most" in seconds. That is the Breach ETA and the ranked next move.

**Design consequence.** The sample timings are tuned to the 29 minute eCrime average. The Settings screen offers four attacker pace profiles (cautious 2.5x, average 1x, hands-on fast 0.4x, automated 0.1x) that scale every hop, so the same graph can be replayed against a slow espionage actor or a machine-speed one.

## 2. What already exists

Honest summary: attack-path prediction is an established product category. IR-GPS does not claim to have invented it.

- **Attack-path graphs for posture.** BloodHound (identity paths), XM Cyber and Wiz (exposure and cloud paths) map how an attacker could reach critical assets, mainly to prioritise fixes before an incident.
- **Vendor path prediction.** Trend Micro's Vision One Attack Path Prediction builds entry point, lateral movement and target assets from exposure data and refreshes daily. Its documentation describes the output as risk events to remediate, not a live countdown. Symantec also markets an incident prediction capability (reviewed in the first research pass, not re-checked for this version).
- **ATT&CK coverage maps.** ATT&CK Navigator shows technique coverage as a static layer.
- **SOAR.** Playbook automation runs predefined steps. It does not recompute routes as you act.

**The gap IR-GPS targets.** I did not find a tool that, during an incident, combines (a) a breach ETA from the current foothold, (b) containment moves ranked by delay gained against business impact, and (c) a route that recalculates the moment you act, framed as navigation. That is a narrower claim than "never built before". It is an opinion from a limited search, not a market survey, so treat it as a positioning hypothesis to test with practitioners.

## 3. Standards the platform aligns to

- **NIST SP 800-61 Rev. 3** (April 2025) restructures incident response around the Cybersecurity Framework 2.0 functions. Playbook steps in IR-GPS carry CSF 2.0 Respond and Recover category codes (RS.AN analysis, RS.MA management, RS.MI mitigation, RS.CO communication, RC.RP recovery plan execution, RC.CO recovery communication, ID.IM improvement).
- **MITRE ATT&CK.** Every attacker move is tagged with a technique ID and tactic. The matrix has been revised recently (the Defense Evasion tactic was split in a recent release), so tactic labels in your own data should be checked against the current version. The sample environment was corrected for this.
- **Regulatory clocks.** Deadlines are computed from the time the responder becomes aware:
  - UK GDPR and the ICO: notify within 72 hours of becoming aware where a personal-data breach risks people's rights and freedoms.
  - NIS2 Article 23: early warning within 24 hours, incident notification within 72 hours, final report one month after the notification.
  - UK Cyber Security and Resilience Bill: proposed 24 hour initial and 72 hour full reports for in-scope entities. These are marked as proposed in the UI because the Bill's status can change.
  - Whether an incident is notifiable is a legal judgement. The tool shows the clocks, not the decision.

## 4. Detection content

Hunt guidance is written for Microsoft environments (Defender XDR, Sentinel, Entra), matching the sample Northwind estate: Windows Security events (4624, 4769, 5145, 7045), Entra sign-in and risk events, email and URL tables. Queries are starter examples. Thresholds and table names must be tuned, and Microsoft's Azure-portal experience for Sentinel is scheduled to retire on 31 March 2027, so check the current portal location before relying on screenshots in older guides.

## 5. Model design decisions

| Decision | Reasoning |
|---|---|
| Edge cost = minutes + 25 x (-ln p) | Prefers routes that are both quick and likely to work. A 50% hop costs about 17 extra minutes of "effort". |
| Control multiplies time by 2.2 and success by 0.5 | A simple, explainable effect size that is easy to calibrate per control. |
| Multi-source Dijkstra via a virtual source | Handles several known footholds in one pass. |
| Yen's k-shortest paths (k = 3) | Shows the detour after a main road is blocked. |
| Containment score = (delay + 60 x crown jewels saved) / (1 + 0.5 x business impact) | Rewards buying time and saving crown jewels while penalising disruptive actions. |
| Exposure score over a 2 hour horizon | Keeps the 0 to 100 score sensitive to control changes. With a longer cap, most scenarios looked identical. |
| Severity from live ETA (SEV1 at 15 minutes or less or breached, SEV2 up to 60, SEV3 beyond, SEV4 contained) | Matches the countdown on screen. |
| Scenario dwell | The attacker usually acted before the alert. Dwell replays that, then resets the clock to T+00:00, so earlier compromises appear as pre-alert telemetry. |

## 6. What version 2 adds, and why

| Gap found | Addition |
|---|---|
| A single screen is a demo, not a workflow | Nine screens: Dashboard, Navigator, Incidents, Playbooks, Hunt, Posture, Assets, Reports, Settings |
| No way to see the value of a response | Dashboard projection: unmanaged replay versus guided response with a configurable reaction lag |
| ETA alone does not drive hardening work | Posture advisor prices every control in ETA and average exposure across all scenarios |
| Responders need next actions, not only routes | Playbooks aligned to NIST CSF 2.0, with per-incident progress |
| Analysts need to find the attacker mid-path | Hunt guide per technique on the predicted route, with source tables and starter KQL |
| Notification deadlines are easy to miss | Regulatory clocks per incident with countdowns and done flags |
| Hard-coded sample data | Assets editor: calibrate times and odds, add assets, paths, scenarios, import and export JSON |
| Findings need to leave the tool | Markdown incident report, executive summary, CSV exports, JSON backup |

## 7. What version 2.1 adds: uncertainty, calibration, validation

A single ETA ("15 min") invites false precision. Version 2.1 keeps that number, labelled as the fastest path if every step works first time, and adds what a responder actually needs to decide with it.

| Gap found | Addition | Method |
|---|---|---|
| One number hides how unsure the model is | ETA as a likely range, plus breach chances at 15, 30 and 60 minutes | 1,500 simulated attacks. Each hop time is lognormal around the edge's minutes. The spread comes from the edge's own sigma, or from its confidence label (high 0.3, medium 0.5, low 0.7). One shared pace factor per run models a fast or slow operator. The attacker retries a failed step (geometric, capped at 12) or, as an option, makes a single attempt. Each run takes the quickest route through its own sampled graph. A seeded generator makes results repeatable. |
| Which assumption matters? | "What drives the ETA" | One-at-a-time sensitivity with common random numbers: attacker pace (x0.5, x2), control effectiveness, and the time and success of every edge used in at least 5% of runs. Ranked by swing in the median. |
| Why does this step say 10 minutes? | "Why this number?" on every step | States the starting estimate, pace, controls in effect, the value used, the spread, and the evidence (prior, some data, calibrated). |
| The numbers are illustrative | Calibration from your own timings | A lognormal fit pulled toward the prior by 3 pseudo-observations for time and 4 for success, so one data point cannot swing the model. Spread never falls below 0.2. Three observations earn "some data", eight "calibrated". The prior is kept on the edge, so refitting is idempotent and restoring is exact. |
| Is the model any good? | Validation against public incident timelines | Six documented stretches (for example the Ryuk speed run: 50 minutes from the first beacons to beacons on the domain controllers, counted as two hops). The model draws that many hops from this environment's post-foothold steps and checks whether the real duration falls inside P10 to P90. It also reports band width, bias, and a split between single-step and multi-step stretches. |

**What the validation can and cannot say.** The stretches and hop counts are my transcription of public reports, with the basis for each hop count listed on the Evidence tab. Six rows is anecdote, not validation, and the screen says so until there are twelve. A wide band is easy to hit, so a high hit rate alone proves little: the screen shows band width beside it. In the sample run the model's bands are about ten times wide, and single documented steps ran several times faster than the model's median hop, which is expected because a modelled hop includes operator overhead. One stretch (Cobalt Strike start to administrative credentials, four minutes) falls below P10, and the check is built so it can fail: tests prove it flags a model ten times too fast or too slow, and a tight retry-free model that misses nearly everything.

**Wait before a human takes over.** Ten public ransomware intrusions show a median of about two hours from first execution to hands-on-keyboard, with the quickest at ten minutes and the slowest at thirty hours. The model's clock starts at your alert, so this wait is not in the ETA, and a quiet first hour proves little.

**Vendor benchmarks** (CrowdStrike, ReliaQuest, Sophos, Barracuda, Splunk, Palo Alto Unit 42) are listed as context, not as tests. They are medians and averages across different populations and definitions, so they cannot be compared one for one with a path-level ETA.

## 8. Limits and next research

- Timings and probabilities are illustrative until calibrated. The calibration tool exists; what is missing is real purple-team data to feed it.
- Validation needs more than six rows. Twelve is the stated minimum for any claim, and the hop counts should be checked against the reports by someone other than me.
- The ranges assume independent hop times apart from the shared pace factor. Real intrusions have correlated delays (a quiet weekend, a slow operator), which the shared factor only partly covers.
- The graph is supplied by the user. Importers for BloodHound, Entra and Azure Resource Graph exports would remove the manual step.
- Live alert ingestion (for example from Microsoft Sentinel) would seed footholds automatically.
- Validate the "navigation" framing and the ranking formula with working incident responders before presenting it as proven.

## Sources

- The DFIR Report, Ryuk speed run: https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/
- The DFIR Report, Ryuk in 5 hours: https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
- The DFIR Report, Ryuk's return: https://thedfirreport.com/2020/10/08/ryuks-return/
- The DFIR Report, Quantum ransomware: https://thedfirreport.com/2022/04/25/quantum-ransomware/
- The DFIR Report, Word to lateral movement in 1 hour: https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/
- The DFIR Report, IcedID to XingLocker: https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
- The DFIR Report, BazarLoader to Conti: https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/
- Dark Reading on CrowdStrike breakout time: https://www.darkreading.com/cyber-risk/attackers-now-need-just-29-minutes-to-own-a-network
- ReliaQuest, 2026 Annual Cyber Threat Report: https://reliaquest.com/blog/2026-annual-cyber-threat-report/
- Help Net Security on Sophos median time: https://www.helpnetsecurity.com/2025/04/03/breach-median-time/
- Black Hat MEA on Barracuda ransomware speed: https://insights.blackhatmea.com/a-ransomware-speed-record-three-hours-to-disaster/
- Splunk, time to ransom: https://ransomware.org/blog/time-to-ransom-is-declining-and-thats-very-bad/
- Palo Alto Unit 42, stages of a ransomware attack: https://www.paloaltonetworks.com/resources/ebooks/stages-of-a-ransomware-attack
- CrowdStrike, 2026 Global Threat Report press release, 24 Feb 2026: https://ir.crowdstrike.com/news-releases/news-release-details/2026-crowdstrike-global-threat-report-ai-accelerates-adversaries
- CrowdStrike, Global Threat Report page: https://www.crowdstrike.com/global-threat-report.html
- Google Cloud, M-Trends 2026: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026
- Help Net Security, M-Trends 2026 summary: https://www.helpnetsecurity.com/2026/03/24/mandiant-m-trends-2026/
- IBM, Cost of a Data Breach 2025 summary: https://www.ibm.com/think/x-force/2025-cost-of-a-data-breach-navigating-ai
- IBM newsroom, 30 Jul 2025: https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls
- Trend Micro, Attack Path Prediction documentation: https://docs.trendmicro.com/documentation/article/trend-vision-one-attack-path-predict
- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- MITRE ATT&CK: https://attack.mitre.org/
- ICO, report a personal data breach: https://ico.org.uk/for-organisations/report-a-breach/
- NIS2 Directive (EUR-Lex): https://eur-lex.europa.eu/eli/dir/2022/2555/oj
- UK Cyber Security and Resilience Bill: https://www.gov.uk/government/collections/cyber-security-and-resilience-bill
