/*!
 * Sample environment: a fictional hybrid (on-prem AD + Azure/Entra + GitHub) company, "Northwind Logistics".
 * Edges are attacker moves mapped to MITRE ATT&CK. Times/probabilities are illustrative defaults,
 * not measurements. Replace with your own environment via Import JSON.
 */
(function (root) {
  'use strict';

  // x: 0-1000, y: 0-620. Lanes (left to right): Entry, Endpoints, Identity, Servers, Data & Cloud
  var nodes = [
    // Entry
    { id: 'mail-gw', label: 'Email Gateway', type: 'gateway', zone: 'Entry', x: 70, y: 150, businessImpact: 6 },
    { id: 'vpn-gw', label: 'VPN Gateway', type: 'gateway', zone: 'Entry', x: 70, y: 400, businessImpact: 7 },
    // Endpoints
    { id: 'ws-hr-07', label: 'WS-HR-07', type: 'workstation', zone: 'Endpoints', x: 235, y: 70, businessImpact: 1 },
    { id: 'ws-exec-01', label: 'WS-EXEC-01', type: 'workstation', zone: 'Endpoints', x: 235, y: 210, businessImpact: 3 },
    { id: 'ws-fin-03', label: 'WS-FIN-03', type: 'workstation', zone: 'Endpoints', x: 235, y: 350, businessImpact: 2 },
    { id: 'ws-dev-12', label: 'WS-DEV-12', type: 'workstation', zone: 'Endpoints', x: 235, y: 500, businessImpact: 2 },
    // Identity
    { id: 'svc-backup', label: 'svc-backup (account)', type: 'identity', zone: 'Identity', x: 440, y: 70, businessImpact: 3 },
    { id: 'admin-jump', label: 'Admin Jump Host', type: 'server', zone: 'Identity', x: 440, y: 190, businessImpact: 4 },
    { id: 'dc-01', label: 'Domain Controller', type: 'server', zone: 'Identity', x: 440, y: 290, crown: true, businessImpact: 10, tier0: true },
    { id: 'entra-sync', label: 'Entra Connect', type: 'server', zone: 'Identity', x: 440, y: 500, businessImpact: 5 },
    // Servers
    { id: 'srv-file-01', label: 'File Server', type: 'server', zone: 'Servers', x: 640, y: 70, businessImpact: 6 },
    { id: 'srv-backup-01', label: 'Backup Server', type: 'server', zone: 'Servers', x: 640, y: 190, businessImpact: 5 },
    { id: 'srv-app-erp', label: 'ERP App Server', type: 'server', zone: 'Servers', x: 640, y: 390, businessImpact: 8 },
    { id: 'srv-ci', label: 'CI Runner', type: 'server', zone: 'Servers', x: 640, y: 500, businessImpact: 4 },
    // Data & Cloud
    { id: 'db-customer', label: 'Customer DB', type: 'data', zone: 'Data & Cloud', x: 880, y: 90, crown: true, businessImpact: 9 },
    { id: 'db-fin', label: 'Finance DB', type: 'data', zone: 'Data & Cloud', x: 880, y: 210, crown: true, businessImpact: 9 },
    { id: 'az-storage', label: 'Azure Blob Backups', type: 'cloud', zone: 'Data & Cloud', x: 880, y: 320, businessImpact: 5 },
    { id: 'idp', label: 'Entra ID (IdP)', type: 'cloud', zone: 'Data & Cloud', x: 780, y: 520, businessImpact: 9 },
    { id: 'az-sub-owner', label: 'Azure Subscription Owner', type: 'cloud', zone: 'Data & Cloud', x: 880, y: 440, businessImpact: 6 },
    { id: 'az-keyvault', label: 'Azure Key Vault', type: 'cloud', zone: 'Data & Cloud', x: 950, y: 570, crown: true, businessImpact: 8 },
    { id: 'gh-repo', label: 'GitHub Source Repos', type: 'saas', zone: 'Data & Cloud', x: 800, y: 600, crown: true, businessImpact: 6 }
  ];

  function E(from, to, tid, tname, tactic, minutes, p, remedy, controls, impact) {
    return { from: from, to: to, tid: tid, tname: tname, tactic: tactic, minutes: minutes, p: p, remedy: remedy, controls: controls || [], impact: impact };
  }

  var edges = [
    // Initial access
    E('mail-gw', 'ws-hr-07', 'T1566.001', 'Spearphishing Attachment', 'Initial Access', 10, 0.5, 'Quarantine message and block sender/attachment hash', ['mail-filter'], 1),
    E('mail-gw', 'ws-exec-01', 'T1566.002', 'Spearphishing Link', 'Initial Access', 12, 0.4, 'Detonate and block the URL at the proxy', ['mail-filter'], 1),
    E('mail-gw', 'ws-fin-03', 'T1566.001', 'Spearphishing Attachment', 'Initial Access', 12, 0.4, 'Quarantine message and block sender/attachment hash', ['mail-filter'], 1),
    E('vpn-gw', 'ws-dev-12', 'T1133', 'External Remote Services', 'Initial Access', 15, 0.5, 'Force MFA re-enrolment and kill active VPN sessions', ['mfa'], 3),
    E('vpn-gw', 'srv-file-01', 'T1133', 'External Remote Services', 'Initial Access', 12, 0.4, 'Restrict VPN split-tunnel access to file servers', ['segmentation'], 3),
    // Endpoint lateral movement
    E('ws-hr-07', 'srv-file-01', 'T1021.002', 'SMB / Windows Admin Shares', 'Lateral Movement', 15, 0.6, 'Block SMB (445) from the workstation VLAN to servers', ['segmentation', 'edr'], 2),
    E('ws-hr-07', 'ws-fin-03', 'T1021.001', 'Remote Desktop Protocol', 'Lateral Movement', 20, 0.35, 'Block workstation-to-workstation RDP (3389)', ['segmentation'], 2),
    E('ws-hr-07', 'svc-backup', 'T1558.003', 'Kerberoasting', 'Credential Access', 25, 0.5, 'Rotate svc-backup password; enforce AES and gMSA', ['tiering'], 2),
    E('ws-exec-01', 'idp', 'T1539', 'Steal Web Session Cookie', 'Credential Access', 20, 0.5, 'Revoke refresh tokens and require re-auth', ['conditional-access'], 3),
    E('ws-fin-03', 'srv-app-erp', 'T1021.001', 'Remote Desktop Protocol', 'Lateral Movement', 10, 0.7, 'Remove direct RDP; require ERP client only', ['segmentation'], 3),
    E('ws-fin-03', 'db-fin', 'T1078', 'Valid Accounts', 'Privilege Escalation', 15, 0.5, 'Restrict DB logins to the ERP service account', ['pam'], 4),
    E('ws-dev-12', 'srv-ci', 'T1021.004', 'SSH', 'Lateral Movement', 15, 0.5, 'Require bastion and short-lived SSH certs for CI', ['segmentation'], 2),
    E('ws-dev-12', 'gh-repo', 'T1528', 'Steal Application Access Token', 'Credential Access', 25, 0.4, 'Revoke GitHub PATs and OAuth app grants', ['conditional-access'], 2),
    // Identity and privilege escalation
    E('svc-backup', 'srv-backup-01', 'T1078.002', 'Valid Accounts: Domain', 'Lateral Movement', 5, 0.85, 'Disable svc-backup interactive logon', ['tiering'], 2),
    E('svc-backup', 'dc-01', 'T1003.006', 'DCSync', 'Credential Access', 30, 0.4, 'Remove replication rights from non-DC principals', ['tiering', 'edr'], 4),
    E('srv-file-01', 'admin-jump', 'T1552.001', 'Credentials In Files', 'Credential Access', 30, 0.4, 'Purge credential files; enforce LAPS and a vault', ['pam'], 2),
    E('admin-jump', 'dc-01', 'T1021.001', 'RDP with Admin Credentials', 'Lateral Movement', 10, 0.8, 'Restrict Tier-0 logon to PAWs only', ['tiering', 'pam'], 4),
    // Domain dominance to data
    E('dc-01', 'db-fin', 'T1078.002', 'Valid Accounts: Domain', 'Lateral Movement', 10, 0.9, 'Rotate krbtgt twice and reset DB admin groups', [], 5),
    E('dc-01', 'db-customer', 'T1078.002', 'Valid Accounts: Domain', 'Lateral Movement', 10, 0.9, 'Rotate krbtgt twice and reset DB admin groups', [], 5),
    E('dc-01', 'srv-app-erp', 'T1550.002', 'Pass the Hash', 'Lateral Movement', 8, 0.85, 'Enable Credential Guard and restrict NTLM', ['edr'], 4),
    E('dc-01', 'entra-sync', 'T1098', 'Account Manipulation', 'Persistence', 15, 0.8, 'Rotate the Entra Connect sync account', ['tiering'], 3),
    // Servers and data
    E('srv-app-erp', 'db-fin', 'T1078', 'Valid Accounts (service)', 'Lateral Movement', 5, 0.9, 'Rotate ERP service account credentials', [], 4),
    E('srv-app-erp', 'db-customer', 'T1078', 'Valid Accounts (service)', 'Lateral Movement', 5, 0.8, 'Rotate ERP service account credentials', [], 4),
    E('srv-backup-01', 'db-customer', 'T1005', 'Data from Local System (backups)', 'Collection', 20, 0.6, 'Encrypt backup sets and restrict restore rights', ['pam'], 3),
    E('srv-backup-01', 'az-storage', 'T1530', 'Data from Cloud Storage', 'Collection', 10, 0.7, 'Rotate storage keys; enforce private endpoints', ['conditional-access'], 3),
    // Cloud
    E('entra-sync', 'idp', 'T1556', 'Modify Authentication Process', 'Credential Access', 20, 0.6, 'Reset sync account; enable Entra Connect hardening', ['conditional-access'], 4),
    E('idp', 'az-sub-owner', 'T1078.004', 'Valid Accounts: Cloud', 'Privilege Escalation', 15, 0.5, 'Require PIM approval for Owner and re-check CA policies', ['mfa', 'conditional-access', 'pam'], 3),
    E('az-sub-owner', 'az-keyvault', 'T1555.006', 'Credentials from Cloud Secrets', 'Credential Access', 5, 0.85, 'Switch Key Vault to RBAC with approval and alert on reads', [], 3),
    E('az-sub-owner', 'az-storage', 'T1530', 'Data from Cloud Storage', 'Collection', 5, 0.9, 'Rotate storage keys; remove broad Owner access', [], 3),
    // CI/CD
    E('srv-ci', 'gh-repo', 'T1552.001', 'Credentials In Files (deploy token)', 'Credential Access', 10, 0.7, 'Rotate CI deploy tokens and move to OIDC', ['pam'], 2),
    E('srv-ci', 'az-keyvault', 'T1555.006', 'Credentials from Cloud Secrets', 'Credential Access', 20, 0.5, 'Remove CI service principal read access to Key Vault', ['conditional-access'], 3)
  ];

  var controls = [
    { id: 'edr', label: 'EDR on endpoints and servers', desc: 'Slows and exposes credential theft and lateral execution.', enabled: true },
    { id: 'mfa', label: 'MFA everywhere', desc: 'Raises the cost of stolen passwords and VPN abuse.', enabled: true },
    { id: 'segmentation', label: 'Network segmentation', desc: 'Blocks SMB/RDP/SSH between zones.', enabled: false },
    { id: 'tiering', label: 'AD tiering / PAWs', desc: 'Keeps Tier-0 credentials off lower tiers.', enabled: false },
    { id: 'pam', label: 'Privileged access mgmt (PAM/PIM)', desc: 'Just-in-time admin and vaulted credentials.', enabled: false },
    { id: 'conditional-access', label: 'Conditional Access + token protection', desc: 'Binds sessions and tokens to compliant devices.', enabled: false },
    { id: 'mail-filter', label: 'Advanced email filtering', desc: 'Detonation and link rewriting before delivery.', enabled: true }
  ];

  var scenarios = [
    {
      id: 'phish-hr', name: 'Phishing foothold in HR',
      summary: 'Alert: macro-enabled attachment executed on WS-HR-07. Classic phish to AD takeover to cloud.',
      compromised: ['ws-hr-07'], dwell: 20
    },
    {
      id: 'dev-token', name: 'Developer VPN session hijack',
      summary: 'Alert: impossible-travel VPN login for a developer; WS-DEV-12 beaconing. Supply-chain and secrets risk.',
      compromised: ['ws-dev-12'], dwell: 12
    },
    {
      id: 'exec-aitm', name: 'Executive adversary-in-the-middle',
      summary: 'Alert: session token replay from a new ASN against Entra ID after an executive clicked a link.',
      compromised: ['ws-exec-01'], dwell: 15
    }
  ];

  var zones = [
    { name: 'Entry', x0: 0, x1: 150 }, { name: 'Endpoints', x0: 150, x1: 340 }, { name: 'Identity', x0: 340, x1: 540 },
    { name: 'Servers', x0: 540, x1: 740 }, { name: 'Data & Cloud', x0: 740, x1: 1000 }
  ];

  var env = { name: 'Northwind Logistics (sample)', zones: zones, nodes: nodes, edges: edges, controls: controls, scenarios: scenarios };

  if (typeof module === 'object' && module.exports) module.exports = env;
  else root.IRGPS_SAMPLE = env;
})(typeof self !== 'undefined' ? self : this);
