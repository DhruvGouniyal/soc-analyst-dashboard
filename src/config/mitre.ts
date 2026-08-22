/**
 * MITRE ATT&CK technique catalog.
 *
 * Centralized so technique ids and names never get hard-coded into components.
 * Detections reference these by id via `config/eventTypes.ts`.
 */

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
  /** Short analyst-facing note on what this looks like in practice. */
  summary: string;
}

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  T1110: {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    url: 'https://attack.mitre.org/techniques/T1110/',
    summary:
      'Adversaries systematically guess credentials to gain account access, producing bursts of failed authentications from a single origin.',
  },
  T1046: {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    url: 'https://attack.mitre.org/techniques/T1046/',
    summary:
      'Adversaries enumerate listening services to map the attack surface, typically by touching many ports in a short window.',
  },
  T1059: {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    url: 'https://attack.mitre.org/techniques/T1059/',
    summary:
      'Adversaries abuse shells and interpreters to execute commands, often spawned from an unexpected parent process.',
  },
  T1078: {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Defense Evasion',
    url: 'https://attack.mitre.org/techniques/T1078/',
    summary:
      'Adversaries use legitimate credentials to blend in, surfacing as logins from unusual sources or at unusual times.',
  },
  T1190: {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    url: 'https://attack.mitre.org/techniques/T1190/',
    summary:
      'Adversaries exploit weaknesses in internet-facing services, visible as malformed or injection-bearing requests.',
  },
  T1068: {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
    url: 'https://attack.mitre.org/techniques/T1068/',
    summary:
      'Adversaries exploit flaws to gain higher privileges, commonly surfacing as unexpected root transitions.',
  },
  T1048: {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    tactic: 'Exfiltration',
    url: 'https://attack.mitre.org/techniques/T1048/',
    summary:
      'Adversaries move data out over a protocol distinct from the primary channel, seen as anomalous sustained outbound volume.',
  },
  T1071: {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    url: 'https://attack.mitre.org/techniques/T1071/',
    summary:
      'Adversaries blend C2 traffic into normal application protocols to avoid standing out in flow data.',
  },
  T1204: {
    id: 'T1204',
    name: 'User Execution',
    tactic: 'Execution',
    url: 'https://attack.mitre.org/techniques/T1204/',
    summary:
      'Malicious payloads rely on a user running them, often detected by signature match on a written file.',
  },
};

export function getTechnique(id: string | null): MitreTechnique | null {
  if (!id) return null;
  return MITRE_TECHNIQUES[id] ?? null;
}
