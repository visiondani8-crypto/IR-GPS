/*!
 * Public incident timing data used to sanity-check the model.
 *
 * Everything here is transcribed by hand from the linked public reports and rounded the way the reports round it.
 * Treat each number as approximate: reports often give only a few timestamps, and some hop counts below are
 * my reading of the narrative, not a figure the report states (each is marked in `hopsBasis`).
 * Open the links and check before you rely on any single row. Add your own cases in the same shape.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.IRGPSValData = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var REPORT = 'The DFIR Report';

  // Whole intrusions with documented elapsed times (minutes from T0, T0 = first malware execution).
  var cases = [
    {
      id: 'ryuk-speed', name: 'Ryuk speed run', family: 'Ryuk', published: '2020-11-05', source: REPORT,
      url: 'https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/', ttr: 180,
      t0: 'Victim runs the Bazar loader from a phishing link',
      milestones: [
        { t: 0, label: 'Bazar loader runs' }, { t: 5, label: 'Domain discovery (under 5 min)', bound: 'max' }, { t: 10, label: 'Cobalt Strike beacons' },
        { t: 60, label: 'Beacons on domain controllers (after Zerologon)' }, { t: 120, label: 'Ryuk deployment begins' }, { t: 180, label: 'Whole environment encrypted' }
      ]
    },
    {
      id: 'ryuk-5h', name: 'Ryuk in 5 hours', family: 'Ryuk', published: '2020-10-18', source: REPORT,
      url: 'https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/', ttr: 300,
      t0: 'Bazar loader executed after a phishing email',
      milestones: [
        { t: 0, label: 'Bazar loader runs' }, { t: 120, label: 'Zerologon used (under 2 h)', bound: 'max' }, { t: 250, label: 'RDP to backup server, deployment begins (about 4 h 10)' },
        { t: 270, label: 'Enterprise-wide RDP distribution (about 4.5 h)' }, { t: 300, label: 'Attack complete (about 5 h)' }
      ]
    },
    {
      id: 'ryuk-return', name: "Ryuk's return", family: 'Ryuk', published: '2020-10-08', source: REPORT,
      url: 'https://thedfirreport.com/2020/10/08/ryuks-return/', ttr: 1740,
      t0: 'Initial execution of the Bazar loader',
      milestones: [{ t: 0, label: 'Bazar loader runs' }, { t: 1560, label: 'About 3 h left to respond if the first day of recon was missed' }, { t: 1740, label: 'Domain-wide ransomware (29 h)' }]
    },
    {
      id: 'quantum', name: 'Quantum ransomware', family: 'Quantum', published: '2022-04-25', source: REPORT,
      url: 'https://thedfirreport.com/2022/04/25/quantum-ransomware/', ttr: 224,
      t0: 'IcedID payload executed',
      milestones: [{ t: 0, label: 'IcedID runs' }, { t: 120, label: 'Hands-on-keyboard begins (about 2 h)' }, { t: 224, label: 'Domain-wide encryption (3 h 44)' }]
    },
    {
      id: 'word-lateral', name: 'Word to lateral movement', family: 'IcedID', published: '2021-06-20', source: REPORT,
      url: 'https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/', ttr: null,
      t0: 'IcedID loader run from a macro document',
      milestones: [{ t: 0, label: 'IcedID runs' }, { t: 35, label: 'Cobalt Strike beacon (within 35 min)', bound: 'max' }, { t: null, label: 'About 5 min after discovery: SMB lateral movement with a domain admin' }, { t: null, label: 'Over 1 h on file servers over RDP; no impact observed' }]
    },
    {
      id: 'xinglocker', name: 'IcedID to XingLocker', family: 'XingLocker', published: '2021-10-18', source: REPORT,
      url: 'https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/', ttr: 1440,
      t0: 'Initial compromise by IcedID',
      milestones: [{ t: 0, label: 'IcedID compromise' }, { t: 120, label: 'Cobalt Strike beacon downloaded' }, { t: 124, label: 'Administrative credentials stolen (within 4 min of beacon)' }, { t: 1440, label: 'Ransomware (title: 24 hours)' }]
    },
    {
      id: 'conti-32h', name: 'BazarLoader to Conti', family: 'Conti', published: '2021-09-13', source: REPORT,
      url: 'https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/', ttr: 1920,
      t0: 'Initial beachhead BazarLoader executed',
      milestones: [{ t: 0, label: 'BazarLoader runs' }, { t: 1920, label: 'Domain-wide encryption (about 32 h)' }]
    }
  ];

  // Documented stretches of an intrusion, with how many distinct hops (new host or privilege boundary) the report describes in them.
  // These are the rows the model is tested against.
  var phases = [
    { id: 'p1', caseId: 'ryuk-speed', label: 'Beacons deployed to domain controllers reached', minutes: 50, hops: 2, fidelity: 'approx',
      hopsBasis: 'Zerologon to domain admin, then beacons placed on the domain controllers. Minutes = about 60 minus about 10.' },
    { id: 'p2', caseId: 'ryuk-speed', label: 'Domain controllers reached to everything encrypted', minutes: 120, hops: 3, fidelity: 'approx',
      hopsBasis: 'Backup, file and deployment servers; then other servers; then workstations. Minutes = about 180 minus about 60.' },
    { id: 'p3', caseId: 'ryuk-5h', label: 'Phish executed to everything encrypted', minutes: 300, hops: 5, fidelity: 'approx',
      hopsBasis: 'Primary DC via Zerologon, second DC, RDP pivot to the primary DC, backup server, mass deployment. Includes reconnaissance time.' },
    { id: 'p4', caseId: 'quantum', label: 'Hands-on-keyboard to everything encrypted', minutes: 104, hops: 4, fidelity: 'approx',
      hopsBasis: 'First server over WMI and RDP, other servers over RDP, pivot from a domain controller, PsExec and WMI deployment. Minutes = 224 minus about 120.' },
    { id: 'p5', caseId: 'word-lateral', label: 'Discovery to SMB lateral movement with admin credentials', minutes: 5, hops: 1, fidelity: 'approx',
      hopsBasis: 'One move: services created over ADMIN$ and IPC$. Report says about 5 minutes after discovery.' },
    { id: 'p6', caseId: 'xinglocker', label: 'Cobalt Strike start to administrative credentials', minutes: 4, hops: 1, fidelity: 'explicit',
      hopsBasis: 'One step: LSASS credential theft, then searching for domain controllers. Report says within four minutes.' }
  ];

  // How long after the first execution did a human take over? (minutes; bound "max" = the report says "within")
  var dwell = [
    { id: 'd1', caseId: 'ryuk-speed', minutes: 10, label: 'Ryuk speed run', basis: 'Cobalt Strike beacons within 10 minutes', bound: 'max', url: 'https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/' },
    { id: 'd2', caseId: 'word-lateral', minutes: 35, label: 'Word to lateral movement', basis: 'Cobalt Strike beacon within 35 minutes', bound: 'max', url: 'https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/' },
    { id: 'd3', minutes: 60, label: 'Diavol (BazarLoader)', basis: 'Idle for one hour, then Cobalt Strike beacons', url: 'https://thedfirreport.com/2021/12/13/diavol-ransomware/' },
    { id: 'd4', minutes: 90, label: 'Sodinokibi (IcedID)', basis: 'IcedID reached two Cobalt Strike servers after about 1.5 h', url: 'https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/' },
    { id: 'd5', caseId: 'quantum', minutes: 120, label: 'Quantum', basis: 'Hands-on-keyboard about 2 h after infection', url: 'https://thedfirreport.com/2022/04/25/quantum-ransomware/' },
    { id: 'd6', caseId: 'xinglocker', minutes: 120, label: 'XingLocker', basis: 'Next stage instructed two hours after compromise', url: 'https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/' },
    { id: 'd7', minutes: 120, label: 'Nokoyawa (macro)', basis: 'Cobalt Strike beacons about 2 h after the malware ran', url: 'https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/' },
    { id: 'd8', minutes: 180, label: 'Nokoyawa (HTML smuggling)', basis: 'Beaconing to Cobalt Strike about 3 h after execution', url: 'https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/' },
    { id: 'd9', minutes: 960, label: 'IcedID (ISO)', basis: 'First Cobalt Strike beacon about 16 h after execution', url: 'https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/' },
    { id: 'd10', minutes: 1800, label: 'Dagon Locker (IcedID)', basis: 'Cobalt Strike about 30 h after inactivity', url: 'https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/' }
  ];

  // Aggregate figures from vendor reports. Scopes differ from the model's ETA (which starts at your alert), so these are context, not tests.
  var benchmarks = [
    { id: 'b1', org: 'CrowdStrike', report: '2026 Global Threat Report (2025 data)', metric: 'Average breakout time (first foothold to lateral movement)', minutes: 29, extra: 'Fastest 27 seconds', kind: 'breakout',
      url: 'https://www.darkreading.com/cyber-risk/attackers-now-need-just-29-minutes-to-own-a-network', reliability: 'secondary report of the vendor figure' },
    { id: 'b2', org: 'ReliaQuest', report: '2026 Annual Cyber-Threat Report (2025 data)', metric: 'Average breakout time', minutes: 34, extra: 'Fastest 4 minutes; fastest exfiltration 6 minutes after entry', kind: 'breakout',
      url: 'https://reliaquest.com/blog/2026-annual-cyber-threat-report/', reliability: 'vendor page' },
    { id: 'b3', org: 'Sophos', report: '2025 Active Adversary Report (2024 data, 400+ cases)', metric: 'Median time from initial action to first attempt on Active Directory', minutes: 660, extra: 'Median start to exfiltration 72.98 h; exfiltration to detection 2.7 h', kind: 'to-ad',
      url: 'https://www.helpnetsecurity.com/2025/04/03/breach-median-time/', reliability: 'secondary report of the vendor figure' },
    { id: 'b4', org: 'Barracuda', report: 'Managed XDR Global Threat Report (Feb 2026)', metric: 'Fastest observed ransomware case, compromise to full encryption (Akira)', minutes: 180, extra: 'A single case, not a typical value', kind: 'to-ransom',
      url: 'https://insights.blackhatmea.com/a-ransomware-speed-record-three-hours-to-disaster/', reliability: 'secondary report of the vendor figure' },
    { id: 'b5', org: 'Splunk', report: 'Ransomware encryption study (10 strains)', metric: 'Median time to encrypt once ransomware is running', minutes: 43, extra: 'Range about 4 minutes to 3.5 hours', kind: 'encrypt',
      url: 'https://ransomware.org/blog/time-to-ransom-is-declining-and-thats-very-bad/', reliability: 'secondary report of the vendor figure' },
    { id: 'b6', org: 'Palo Alto Unit 42', report: 'Incident Response Report 2026', metric: 'Fastest quarter of intrusions reached exfiltration within', minutes: 72, extra: '1.2 hours, down from 4.8 hours the year before', kind: 'to-exfil',
      url: 'https://www.paloaltonetworks.com/resources/ebooks/stages-of-a-ransomware-attack', reliability: 'vendor page' }
  ];

  return { cases: cases, phases: phases, dwell: dwell, benchmarks: benchmarks };
});
