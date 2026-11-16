/*!
 * Reference content: detection guidance per ATT&CK technique, response playbooks (aligned to the
 * NIST CSF 2.0 categories used by SP 800-61 Rev. 3), regulatory clocks, adversary speed profiles.
 * Starter queries are examples: tune thresholds and table names to your environment before use.
 */
(function (root) {
  'use strict';
  var R = String.raw;

  var detect = {
    'T1566.001': {
      src: 'Email security logs (EmailEvents, EmailAttachmentInfo) and EDR process events',
      look: 'Office or PDF readers spawning cmd, PowerShell or wscript. Macro or script attachments from first-seen senders. The same attachment hash delivered to several mailboxes.',
      kql: R`// Defender XDR advanced hunting
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where FileType in~ ("doc", "docm", "xls", "xlsm", "iso", "lnk", "one", "html")
| summarize Recipients = dcount(RecipientEmailAddress), Msgs = count() by SenderFromAddress, SHA256
| where Recipients > 3`
    },
    'T1566.002': {
      src: 'Email URL logs (EmailUrlInfo), proxy and DNS logs, sign-in logs',
      look: 'Clicks to newly registered domains followed by a sign-in from a new IP or ASN. One URL domain sent to many recipients.',
      kql: R`// Defender XDR advanced hunting
EmailUrlInfo
| where Timestamp > ago(24h)
| summarize Recipients = dcount(NetworkMessageId) by UrlDomain
| where Recipients > 3
| order by Recipients desc`
    },
    'T1133': {
      src: 'VPN gateway logs and Entra SigninLogs',
      look: 'Impossible travel, new device passing MFA, logins from hosting or anonymiser ASNs, a host that starts beaconing right after a VPN login.',
      kql: R`SigninLogs
| where TimeGenerated > ago(24h) and ResultType == 0
| summarize Countries = dcount(tostring(LocationDetails.countryOrRegion)), IPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where Countries > 1`
    },
    'T1021.002': {
      src: 'Windows Security 5140/5145 (share access), service creation 7045, EDR network events',
      look: 'Admin shares (C$, ADMIN$) touched from workstations. Service creation immediately afterwards. One source reaching many servers.',
      kql: R`SecurityEvent
| where EventID == 5145 and ShareName in (@"\\*\ADMIN$", @"\\*\C$")
| summarize Targets = dcount(Computer) by IpAddress, SubjectUserName, bin(TimeGenerated, 15m)
| where Targets > 3`
    },
    'T1021.001': {
      src: 'Windows Security 4624 (LogonType 10), 4778/4779, TerminalServices logs',
      look: 'Workstation-to-workstation RDP. One account fanning out to several hosts. RDP from servers that never initiate it.',
      kql: R`SecurityEvent
| where EventID == 4624 and LogonType == 10
| summarize Targets = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 1h)
| where Targets > 3`
    },
    'T1558.003': {
      src: 'Domain controller Security log, event 4769',
      look: 'Many service-ticket requests with RC4 encryption (0x17) from one account or host, for service accounts the requester never normally uses.',
      kql: R`SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize Requests = count(), Services = dcount(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where Services > 5`
    },
    'T1539': {
      src: 'Entra SigninLogs, non-interactive sign-ins, Identity Protection risk events',
      look: 'A session token replayed from a new IP or ASN. Anomalous Token and Attacker in the Middle detections. A new MFA method registered shortly after sign-in.',
      kql: R`AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where RiskEventType in ("anomalousToken", "attackerinTheMiddle", "tokenIssuerAnomaly")
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, IpAddress, Location`
    },
    'T1078': {
      src: 'Windows 4624/4648 and database audit logs',
      look: 'Logons to finance or database systems by accounts that are not the application service account, from unusual workstations or off-hours.',
      kql: R`SecurityEvent
| where EventID == 4624 and LogonType in (3, 10)
| summarize Logons = count(), Hosts = dcount(Computer) by Account, bin(TimeGenerated, 1h)
| where Hosts > 5`
    },
    'T1021.004': {
      src: 'Linux auth logs / Syslog, bastion and CI runner logs',
      look: 'Interactive SSH from a developer workstation straight to a CI runner, outside deployment windows or with a key not used before.',
      kql: R`Syslog
| where Facility in ("auth", "authpriv") and SyslogMessage has "Accepted"
| summarize Logons = count() by HostName, bin(TimeGenerated, 1h)`
    },
    'T1528': {
      src: 'GitHub audit log (token and OAuth events), Entra AuditLogs',
      look: 'Personal access tokens or OAuth grants created from new IPs. Bulk repository clones. Token use from networks unrelated to CI.',
      kql: ''
    },
    'T1078.002': {
      src: 'Windows 4624 and 4768/4769',
      look: 'A service account (svc-*) used interactively or from a workstation.',
      kql: R`SecurityEvent
| where EventID == 4624 and Account has "svc-" and LogonType in (2, 10, 11)
| project TimeGenerated, Account, Computer, LogonType, IpAddress`
    },
    'T1003.006': {
      src: 'Domain controller Security log, event 4662',
      look: 'Directory replication rights exercised by an account that is not a domain controller.',
      kql: R`SecurityEvent
| where EventID == 4662
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
| where SubjectUserName !endswith "$"
| project TimeGenerated, SubjectUserName, SubjectDomainName, Computer, Properties`
    },
    'T1552.001': {
      src: 'EDR file-read telemetry and file-share auditing (4663)',
      look: 'Reads of scripts, configs or text files that contain passwords, followed by a logon with the discovered account.',
      kql: ''
    },
    'T1550.002': {
      src: 'Windows 4624 (LogonType 3, NTLM), Credential Guard events',
      look: 'NTLM network logons for privileged accounts from hosts that normally authenticate with Kerberos.',
      kql: R`SecurityEvent
| where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
| where Account !endswith "$"
| summarize Hosts = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 1h)
| where Hosts > 3`
    },
    'T1098': {
      src: 'Windows 4728/4732/4738 and Entra AuditLogs',
      look: 'Changes to the Entra Connect sync account, new credentials on service principals, privileged group membership changes.',
      kql: R`AuditLogs
| where OperationName in ("Add service principal credentials", "Add member to role")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources`
    },
    'T1005': {
      src: 'Backup platform audit logs, database audit logs, EDR',
      look: 'Restores or exports of database backups outside the change window. The backup account logging on interactively.',
      kql: ''
    },
    'T1530': {
      src: 'Azure Storage logs (StorageBlobLogs), Defender for Storage',
      look: 'Large reads of backup containers from unfamiliar IPs or identities.',
      kql: R`StorageBlobLogs
| where TimeGenerated > ago(24h) and OperationName == "GetBlob"
| summarize Reads = count(), Bytes = sum(ResponseBodySize) by CallerIpAddress, AccountName, bin(TimeGenerated, 1h)
| where Bytes > 1073741824`
    },
    'T1556': {
      src: 'Entra AuditLogs, Entra Connect Health, logons on the sync server',
      look: 'Changes to federation or domain authentication settings, new pass-through agents, unexpected sync-account activity.',
      kql: R`AuditLogs
| where OperationName in ("Set federation settings on domain", "Set domain authentication")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources`
    },
    'T1078.004': {
      src: 'Entra SigninLogs, AuditLogs and PIM activity',
      look: 'Owner or Contributor assigned or activated outside the approval flow. Role changes soon after a risky sign-in.',
      kql: R`AuditLogs
| where Category == "RoleManagement"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources`
    },
    'T1555.006': {
      src: 'Key Vault diagnostic logs (AzureDiagnostics)',
      look: 'Bursts of SecretGet or SecretList from a new caller IP or identity, especially right after a role assignment.',
      kql: R`AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName in ("SecretGet", "SecretList", "KeyGet")
| summarize Reads = count() by CallerIPAddress, Resource, bin(TimeGenerated, 15m)
| where Reads > 20`
    }
  };

  var playbooks = [
    {
      id: 'pb-phish-ad', name: 'Phishing to AD takeover', summary: 'Malicious attachment or link leads to credential theft, lateral movement and domain compromise.',
      steps: [
        { id: 'pa1', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Preserve the alert and the user report. Capture the EDR timeline before isolation changes the host state.' },
        { id: 'pa2', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Identify patient zero: delivery time, who opened it, what executed (Office or PDF child processes, script engines).' },
        { id: 'pa3', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Scope the campaign: search all mailboxes for the same sender, subject and attachment hash.' },
        { id: 'pa4', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Check for credential entry or macro execution. Look for 4624 type 3/10 logons and 5145 admin-share access from the host.' },
        { id: 'pa5', phase: 'Analyze', code: 'RS.MA', role: 'Incident commander', text: 'Set severity from the Navigator ETA and confirm which crown jewels are within reach.' },
        { id: 'pa6', phase: 'Mitigate', code: 'RS.MI', role: 'IT', text: 'Isolate patient zero with EDR network containment. Keep it powered on to preserve memory.' },
        { id: 'pa7', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'Disable the user, revoke refresh tokens, reset the password. Assume saved browser credentials are exposed.' },
        { id: 'pa8', phase: 'Mitigate', code: 'RS.MI', role: 'Analyst', text: 'Purge the message from every mailbox and block the sender domain, URL and file hash.' },
        { id: 'pa9', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'Rotate Kerberoastable service accounts reachable from the host (move to gMSA). If DCSync is suspected, reset krbtgt twice.' },
        { id: 'pa10', phase: 'Mitigate', code: 'RS.MI', role: 'IT', text: 'Block the lateral paths the Navigator ranks highest (SMB, RDP) between workstation and server networks.' },
        { id: 'pa11', phase: 'Recover', code: 'RC.RP', role: 'IT', text: 'Reimage patient zero from a known-good image. Do not restore from a backup taken after compromise.' },
        { id: 'pa12', phase: 'Recover', code: 'RC.RP', role: 'Analyst', text: 'Hunt for persistence: scheduled tasks, services, run keys, new local admins, mail rules.' },
        { id: 'pa13', phase: 'Recover', code: 'RC.RP', role: 'IT', text: 'Re-enable accounts and hosts in stages with heightened monitoring for 14 days.' },
        { id: 'pa14', phase: 'Communicate', code: 'RS.CO', role: 'Legal / DPO', text: 'Record the time you became aware. Decide whether personal data is affected and which notification clocks apply.' },
        { id: 'pa15', phase: 'Communicate', code: 'RS.CO', role: 'Incident commander', text: 'Brief leadership on a fixed cadence (for example every 60 minutes) while crown jewels are in reach.' },
        { id: 'pa16', phase: 'Improve', code: 'ID.IM', role: 'Incident commander', text: 'Hold a blameless review within 5 working days. Feed new detections and control gaps into the Hardening view.' }
      ]
    },
    {
      id: 'pb-token', name: 'Token theft / AiTM (cloud identity)', summary: 'A stolen session token or adversary-in-the-middle phish gives the attacker a signed-in cloud identity.',
      steps: [
        { id: 'tk1', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Pull sign-in and non-interactive sign-in logs. Find the session where the token was replayed (new IP or ASN, different device).' },
        { id: 'tk2', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Check Identity Protection for Anomalous Token and Attacker in the Middle detections.' },
        { id: 'tk3', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'List inbox rules, forwarding, OAuth consents and MFA methods created after the suspicious sign-in.' },
        { id: 'tk4', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Establish what the session touched (mailbox, SharePoint, Azure roles). Export audit logs before making changes.' },
        { id: 'tk5', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'Revoke all refresh tokens and sessions (for example Revoke-MgUserSignInSession) and reset the password.' },
        { id: 'tk6', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'Remove attacker-registered MFA methods and malicious inbox rules. Revoke suspicious OAuth grants.' },
        { id: 'tk7', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'Require compliant devices and token protection in Conditional Access for the affected apps and roles.' },
        { id: 'tk8', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'If the identity held Azure roles, review assignments and Key Vault access logs. Rotate any secret it could read.' },
        { id: 'tk9', phase: 'Recover', code: 'RC.RP', role: 'Identity', text: 'Confirm the user signs in only with a phishing-resistant method (FIDO2 or passkey).' },
        { id: 'tk10', phase: 'Recover', code: 'RC.RP', role: 'Analyst', text: 'Monitor the account and its devices for 14 days.' },
        { id: 'tk11', phase: 'Communicate', code: 'RS.CO', role: 'Legal / DPO', text: 'Decide whether mailbox or file data containing personal data was accessed. Start clocks from the time of awareness.' },
        { id: 'tk12', phase: 'Communicate', code: 'RS.CO', role: 'Incident commander', text: 'Notify the user\'s manager and any partners whose data was reachable.' },
        { id: 'tk13', phase: 'Improve', code: 'ID.IM', role: 'Incident commander', text: 'Add adversary-in-the-middle detections. Move high-risk roles to phishing-resistant MFA.' }
      ]
    },
    {
      id: 'pb-devci', name: 'Developer / CI compromise', summary: 'A hijacked developer session or workstation exposes source code, CI secrets and cloud credentials.',
      steps: [
        { id: 'dv1', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Identify the developer session from VPN logs and device compliance. Decide hands-on-keyboard versus automation.' },
        { id: 'dv2', phase: 'Analyze', code: 'RS.AN', role: 'Engineering', text: 'List secrets reachable from the workstation and CI: tokens, deploy keys, SSH keys, service principals.' },
        { id: 'dv3', phase: 'Analyze', code: 'RS.AN', role: 'Engineering', text: 'Review recent commits, workflow files and release artifacts for unauthorized changes.' },
        { id: 'dv4', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Check Key Vault and storage access logs for reads by the CI identity.' },
        { id: 'dv5', phase: 'Mitigate', code: 'RS.MI', role: 'IT', text: 'Isolate the workstation, kill VPN sessions and force MFA re-enrolment.' },
        { id: 'dv6', phase: 'Mitigate', code: 'RS.MI', role: 'Engineering', text: 'Revoke personal access tokens, OAuth app grants and SSH keys. Rotate CI deploy tokens. Prefer OIDC federation over stored secrets.' },
        { id: 'dv7', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'Rotate every Key Vault secret the CI identity could read, then remove its standing access.' },
        { id: 'dv8', phase: 'Mitigate', code: 'RS.MI', role: 'Engineering', text: 'Freeze releases and pin dependencies until artifact integrity is verified.' },
        { id: 'dv9', phase: 'Recover', code: 'RC.RP', role: 'Engineering', text: 'Rebuild CI runners from clean images. Verify signed artifacts before redeploying.' },
        { id: 'dv10', phase: 'Recover', code: 'RC.RP', role: 'IT', text: 'Re-issue developer credentials backed by hardware keys.' },
        { id: 'dv11', phase: 'Communicate', code: 'RS.CO', role: 'Legal / DPO', text: 'Assess exposure of source code, customer data or secrets. Start notification clocks if personal data is involved.' },
        { id: 'dv12', phase: 'Communicate', code: 'RS.CO', role: 'Incident commander', text: 'Inform downstream consumers if a released artifact may be affected.' },
        { id: 'dv13', phase: 'Improve', code: 'ID.IM', role: 'Engineering', text: 'Add branch protection, required reviews and secret scanning. Shorten token lifetimes.' }
      ]
    },
    {
      id: 'pb-ransom', name: 'Ransomware precursor', summary: 'Hands-on-keyboard activity against Tier-0 and backups before encryption.',
      steps: [
        { id: 'rw1', phase: 'Analyze', code: 'RS.AN', role: 'Incident commander', text: 'Treat any domain-admin or backup-account misuse as pre-ransomware. Confirm Tier-0 exposure.' },
        { id: 'rw2', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Identify initial access and hands-on activity. Capture memory from affected hosts if possible.' },
        { id: 'rw3', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Check backup integrity and whether backup consoles or storage were touched.' },
        { id: 'rw4', phase: 'Analyze', code: 'RS.AN', role: 'Analyst', text: 'Look for mass share enumeration, shadow-copy deletion and security-tool tampering.' },
        { id: 'rw5', phase: 'Mitigate', code: 'RS.MI', role: 'IT', text: 'Isolate affected hosts and block lateral protocols. Disable compromised and Tier-0 accounts.' },
        { id: 'rw6', phase: 'Mitigate', code: 'RS.MI', role: 'IT', text: 'Take backups offline or lock them immutable before anything else.' },
        { id: 'rw7', phase: 'Mitigate', code: 'RS.MI', role: 'Identity', text: 'Once access is cut, reset krbtgt twice and rotate service and admin credentials.' },
        { id: 'rw8', phase: 'Mitigate', code: 'RS.CO', role: 'Incident commander', text: 'Engage the cyber insurer, legal counsel and, where appropriate, the NCSC or national CSIRT and law enforcement.' },
        { id: 'rw9', phase: 'Recover', code: 'RC.RP', role: 'IT', text: 'Rebuild identity first (domain controllers), then servers, then workstations. Validate backups in an isolated network.' },
        { id: 'rw10', phase: 'Recover', code: 'RC.RP', role: 'IT', text: 'Restore in order of business impact. Keep enhanced monitoring on restored systems.' },
        { id: 'rw11', phase: 'Communicate', code: 'RS.CO', role: 'Legal / DPO', text: 'Start clocks at awareness. Prepare an early warning or ICO notification with what is known.' },
        { id: 'rw12', phase: 'Communicate', code: 'RC.CO', role: 'Incident commander', text: 'Agree one spokesperson and a holding statement for customers and staff.' },
        { id: 'rw13', phase: 'Improve', code: 'ID.IM', role: 'Incident commander', text: 'Run a review focused on time-to-contain. Feed measured times back into Assets calibration.' }
      ]
    }
  ];

  var scenarioPlaybook = { 'phish-hr': 'pb-phish-ad', 'dev-token': 'pb-devci', 'exec-aitm': 'pb-token' };

  var clocks = {
    uk: [
      { id: 'uk-gdpr', label: 'ICO breach notification', hours: 72, ref: 'UK GDPR Art. 33', note: 'Needed if the breach is likely to risk individuals\' rights and freedoms. Record the decision either way.' },
      { id: 'csr-24', label: 'Initial notification', hours: 24, ref: 'UK Cyber Security and Resilience Bill (proposed)', note: 'Proposed duty for in-scope entities. Check current status of the Bill.', proposed: true },
      { id: 'csr-72', label: 'Full incident report', hours: 72, ref: 'UK Cyber Security and Resilience Bill (proposed)', note: 'Proposed duty for in-scope entities.', proposed: true }
    ],
    eu: [
      { id: 'eu-gdpr', label: 'Supervisory authority notification', hours: 72, ref: 'GDPR Art. 33', note: 'Needed if the breach is likely to risk individuals\' rights and freedoms.' },
      { id: 'nis2-24', label: 'Early warning', hours: 24, ref: 'NIS2 Art. 23', note: 'Significant incidents only. Goes to your CSIRT or competent authority.' },
      { id: 'nis2-72', label: 'Incident notification', hours: 72, ref: 'NIS2 Art. 23', note: 'Updates the early warning with severity, impact and indicators.' },
      { id: 'nis2-fin', label: 'Final report', hours: 72 + 720, ref: 'NIS2 Art. 23', note: 'Due one month after the incident notification (approximated as 30 days).' }
    ]
  };

  var speedProfiles = [
    { id: 'slow', label: 'Cautious operator', factor: 2.5, note: 'Low-and-slow tradecraft, similar to espionage actors.' },
    { id: 'ecrime', label: 'eCrime average', factor: 1, note: 'Sample timings are tuned to roughly this pace. CrowdStrike reports a 29 minute average breakout time for 2025.' },
    { id: 'fast', label: 'Hands-on, fast', factor: 0.4, note: 'Experienced operator moving with purpose.' },
    { id: 'auto', label: 'Automated / AI-assisted', factor: 0.1, note: 'Hops in seconds to minutes. The fastest recorded breakout was 27 seconds (CrowdStrike 2026).' }
  ];

  // Illustrative history so the dashboard table is not empty on first run. Flagged as sample in the UI.
  var sampleIncidents = [
    { daysAgo: 2, title: 'Phishing foothold in HR', scenarioId: 'phish-hr', severity: 'SEV1', status: 'Contained', owner: 'Daniel', eta: 15, ttc: 10 },
    { daysAgo: 6, title: 'Developer VPN session hijack', scenarioId: 'dev-token', severity: 'SEV1', status: 'Contained', owner: 'Daniel', eta: 13, ttc: 8 },
    { daysAgo: 13, title: 'Executive adversary-in-the-middle', scenarioId: 'exec-aitm', severity: 'SEV2', status: 'Closed', owner: 'Daniel', eta: 43, ttc: 11 },
    { daysAgo: 21, title: 'Backup account Kerberoast attempt', scenarioId: 'phish-hr', severity: 'SEV2', status: 'Closed', owner: 'Daniel', eta: 31, ttc: 14 }
  ];

  var tacticOrder = ['Initial Access', 'Credential Access', 'Lateral Movement', 'Privilege Escalation', 'Persistence', 'Collection'];

  function attackUrl(tid) { return 'https://attack.mitre.org/techniques/' + String(tid).replace('.', '/') + '/'; }

  var ref = { detect: detect, playbooks: playbooks, scenarioPlaybook: scenarioPlaybook, clocks: clocks, speedProfiles: speedProfiles, sampleIncidents: sampleIncidents, tacticOrder: tacticOrder, attackUrl: attackUrl };
  if (typeof module === 'object' && module.exports) module.exports = ref;
  else root.IRG_REF = ref;
})(typeof self !== 'undefined' ? self : this);
