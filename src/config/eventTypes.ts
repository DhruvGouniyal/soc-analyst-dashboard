/**
 * Detection catalog: everything the app knows about each event type.
 *
 * Components look up labels, MITRE mapping, and recommended actions here
 * rather than embedding strings, so adding a detection is a one-file change.
 */
import type { EventType, LogSource, Severity } from '@/types/security';

/**
 * Analyst actions offered on an alert. Each maps to a status transition that
 * the frontend applies immediately; a backend can later mirror the same verbs.
 */
export type AlertAction = 'block_ip' | 'investigate_host' | 'mark_resolved';

export interface AlertActionMeta {
  key: AlertAction;
  label: string;
  /** Status the event moves to when this action is taken. */
  transitionsTo: 'blocked' | 'investigating' | 'resolved';
  /** `true` renders the button in a destructive/primary treatment. */
  emphasis: boolean;
}

export const ALERT_ACTIONS: Record<AlertAction, AlertActionMeta> = {
  block_ip: { key: 'block_ip', label: 'Block IP', transitionsTo: 'blocked', emphasis: true },
  investigate_host: {
    key: 'investigate_host',
    label: 'Investigate Host',
    transitionsTo: 'investigating',
    emphasis: false,
  },
  mark_resolved: {
    key: 'mark_resolved',
    label: 'Mark Resolved',
    transitionsTo: 'resolved',
    emphasis: false,
  },
};

export interface EventTypeMeta {
  key: EventType;
  /** Full name shown in the detail panel. */
  label: string;
  /** Condensed name for dense feed rows. */
  shortLabel: string;
  /** MITRE ATT&CK technique id, resolved through `config/mitre.ts`. */
  mitre: string | null;
  /** Severity the detection emits absent other signals. */
  defaultSeverity: Severity;
  /** Which collector surfaces this detection. */
  logSource: LogSource;
  /** Analyst guidance shown alongside the action buttons. */
  guidance: string;
  actions: AlertAction[];
}

export const EVENT_TYPES: Record<EventType, EventTypeMeta> = {
  ssh_brute_force: {
    key: 'ssh_brute_force',
    label: 'SSH Brute Force Detected',
    shortLabel: 'SSH Brute Force',
    mitre: 'T1110',
    defaultSeverity: 'critical',
    logSource: 'auth.log',
    guidance:
      'Multiple failed SSH authentication attempts were detected from the same source within a short time window. Block the source and confirm no session succeeded.',
    actions: ['block_ip', 'investigate_host', 'mark_resolved'],
  },
  ssh_failed_auth: {
    key: 'ssh_failed_auth',
    label: 'Failed SSH Authentication',
    shortLabel: 'SSH Auth Failure',
    mitre: 'T1110',
    defaultSeverity: 'medium',
    logSource: 'auth.log',
    guidance:
      'A single failed SSH authentication. Benign in isolation; correlate against the source IP for a developing brute-force pattern.',
    actions: ['investigate_host', 'mark_resolved'],
  },
  successful_login: {
    key: 'successful_login',
    label: 'Successful Authentication',
    shortLabel: 'Login Success',
    mitre: 'T1078',
    defaultSeverity: 'low',
    logSource: 'auth.log',
    guidance:
      'An accepted login. Verify the source is expected — a success immediately following repeated failures indicates compromise.',
    actions: ['investigate_host', 'mark_resolved'],
  },
  port_scan: {
    key: 'port_scan',
    label: 'Port Scan Detected',
    shortLabel: 'Port Scan',
    mitre: 'T1046',
    defaultSeverity: 'high',
    logSource: 'suricata',
    guidance:
      'A single source touched many ports in a short window, consistent with service enumeration. Commonly precedes targeted exploitation.',
    actions: ['block_ip', 'investigate_host', 'mark_resolved'],
  },
  suspicious_login: {
    key: 'suspicious_login',
    label: 'Suspicious Login Attempt',
    shortLabel: 'Suspicious Login',
    mitre: 'T1078',
    defaultSeverity: 'medium',
    logSource: 'auth.log',
    guidance:
      'Authentication attempted with invalid or unexpected credentials. Review whether the account exists and whether the source is known.',
    actions: ['block_ip', 'investigate_host', 'mark_resolved'],
  },
  web_attack: {
    key: 'web_attack',
    label: 'Web Application Attack',
    shortLabel: 'Web Attack',
    mitre: 'T1190',
    defaultSeverity: 'high',
    logSource: 'suricata',
    guidance:
      'Request payload matched an injection or traversal signature. Confirm whether the application returned a 2xx, which would suggest the attempt landed.',
    actions: ['block_ip', 'investigate_host', 'mark_resolved'],
  },
  suspicious_process: {
    key: 'suspicious_process',
    label: 'Suspicious Process Execution',
    shortLabel: 'Suspicious Process',
    mitre: 'T1059',
    defaultSeverity: 'high',
    logSource: 'audit.log',
    guidance:
      'A shell or interpreter was spawned from an unexpected parent. Inspect the full process tree before clearing.',
    actions: ['investigate_host', 'mark_resolved'],
  },
  privilege_escalation: {
    key: 'privilege_escalation',
    label: 'Privilege Escalation Attempt',
    shortLabel: 'Privilege Escalation',
    mitre: 'T1068',
    defaultSeverity: 'critical',
    logSource: 'audit.log',
    guidance:
      'A process attempted to acquire elevated privileges outside normal administrative activity. Treat as hands-on-keyboard until disproven.',
    actions: ['investigate_host', 'mark_resolved'],
  },
  data_exfiltration: {
    key: 'data_exfiltration',
    label: 'Potential Data Exfiltration',
    shortLabel: 'Data Exfiltration',
    mitre: 'T1048',
    defaultSeverity: 'critical',
    logSource: 'netflow',
    guidance:
      'Sustained outbound transfer well above this host’s baseline. Identify the destination and the process holding the socket.',
    actions: ['block_ip', 'investigate_host', 'mark_resolved'],
  },
  new_connection: {
    key: 'new_connection',
    label: 'New Network Connection',
    shortLabel: 'New Connection',
    mitre: 'T1071',
    defaultSeverity: 'low',
    logSource: 'netflow',
    guidance:
      'A previously unseen outbound connection. Informational, but useful as corroborating context around a confirmed incident.',
    actions: ['investigate_host', 'mark_resolved'],
  },
  malware_signature: {
    key: 'malware_signature',
    label: 'Malware Signature Match',
    shortLabel: 'Malware Signature',
    mitre: 'T1204',
    defaultSeverity: 'critical',
    logSource: 'suricata',
    guidance:
      'File content matched a known-malicious signature. Isolate the host and preserve the artifact before remediation.',
    actions: ['block_ip', 'investigate_host', 'mark_resolved'],
  },
};

export const EVENT_TYPE_KEYS = Object.keys(EVENT_TYPES) as EventType[];

export function getEventTypeMeta(key: EventType): EventTypeMeta {
  return EVENT_TYPES[key];
}
