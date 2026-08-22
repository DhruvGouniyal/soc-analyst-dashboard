/**
 * Attack scenarios.
 *
 * A scenario is an ordered list of steps with offsets, so a burst of events
 * reads as one coherent story instead of unrelated noise: recon precedes
 * exploitation, failures precede the brute-force verdict, and the exfil only
 * follows a successful foothold.
 */
import type { EventType, Severity } from '@/types/security';
import { buildEvent, type EventContext } from './eventFactory';
import type { Rng } from './random';
import type { SecurityEvent } from '@/types/security';
import { ATTACKER_IP, EXTERNAL_SCANNER_IP, SECONDARY_ATTACKER_IP, VICTIM_IP } from './topology';

export interface ScenarioStep {
  eventType: EventType;
  /** Milliseconds after the scenario start. */
  offset: number;
  severity?: Severity;
  sourceIp?: string;
  destinationIp?: string;
  context?: EventContext;
}

export interface AttackScenario {
  id: string;
  name: string;
  /** Shown in the demo-mode timeline. */
  summary: string;
  steps: ScenarioStep[];
}

const SEC = 1000;

/** Scenario 1 — credential attack against SSH. */
export const SSH_BRUTE_FORCE: AttackScenario = {
  id: 'ssh-brute-force',
  name: 'SSH Brute Force',
  summary: 'Repeated credential guessing against the victim SSH service',
  steps: [
    { eventType: 'ssh_failed_auth', offset: 0, context: { username: 'root' } },
    { eventType: 'ssh_failed_auth', offset: 3 * SEC, context: { username: 'root' } },
    { eventType: 'suspicious_login', offset: 7 * SEC, context: { username: 'admin' } },
    { eventType: 'ssh_failed_auth', offset: 11 * SEC, context: { username: 'admin' } },
    {
      eventType: 'ssh_brute_force',
      offset: 16 * SEC,
      context: { attempts: 18, windowSeconds: 75, username: 'root' },
    },
  ],
};

/** Scenario 2 — network reconnaissance. */
export const PORT_SCAN_RECON: AttackScenario = {
  id: 'port-scan-recon',
  name: 'Port Scan Reconnaissance',
  summary: 'Service enumeration sweep across the victim host',
  steps: [
    { eventType: 'new_connection', offset: 0, sourceIp: ATTACKER_IP, destinationIp: VICTIM_IP },
    { eventType: 'port_scan', offset: 4 * SEC, context: { portCount: 23 } },
    { eventType: 'port_scan', offset: 9 * SEC, context: { portCount: 41 }, severity: 'high' },
  ],
};

/** Scenario 3 — authentication anomalies from an unexpected origin. */
export const SUSPICIOUS_AUTH: AttackScenario = {
  id: 'suspicious-auth',
  name: 'Suspicious Authentication',
  summary: 'Invalid account access attempts from a secondary source',
  steps: [
    { eventType: 'suspicious_login', offset: 0, sourceIp: SECONDARY_ATTACKER_IP, context: { username: 'postgres' } },
    { eventType: 'suspicious_login', offset: 5 * SEC, sourceIp: SECONDARY_ATTACKER_IP, context: { username: 'deploy' } },
    { eventType: 'ssh_failed_auth', offset: 9 * SEC, sourceIp: SECONDARY_ATTACKER_IP, context: { username: 'ubuntu' } },
  ],
};

/** Scenario 4 — exploitation of the public-facing web service. */
export const WEB_ATTACK: AttackScenario = {
  id: 'web-attack',
  name: 'Web Application Attack',
  summary: 'Injection and traversal attempts against the victim web service',
  steps: [
    { eventType: 'web_attack', offset: 0, sourceIp: EXTERNAL_SCANNER_IP },
    { eventType: 'web_attack', offset: 6 * SEC, sourceIp: EXTERNAL_SCANNER_IP },
    { eventType: 'web_attack', offset: 12 * SEC, sourceIp: EXTERNAL_SCANNER_IP, severity: 'critical' },
  ],
};

/** Scenario 5 — post-exploitation activity on the victim. */
export const POST_EXPLOIT: AttackScenario = {
  id: 'post-exploit',
  name: 'Suspicious Process Execution',
  summary: 'Interpreter spawned from a web process, followed by privilege escalation',
  steps: [
    { eventType: 'suspicious_process', offset: 0 },
    { eventType: 'suspicious_process', offset: 5 * SEC },
    { eventType: 'privilege_escalation', offset: 11 * SEC },
  ],
};

/** Scenario 6 — data leaving the environment. */
export const DATA_EXFIL: AttackScenario = {
  id: 'data-exfil',
  name: 'Data Exfiltration',
  summary: 'Large sustained outbound transfer from the compromised victim',
  steps: [
    { eventType: 'new_connection', offset: 0 },
    { eventType: 'data_exfiltration', offset: 7 * SEC, context: { bytes: 240_000_000, windowSeconds: 180 } },
    { eventType: 'data_exfiltration', offset: 15 * SEC, context: { bytes: 610_000_000, windowSeconds: 300 } },
  ],
};

export const ALL_SCENARIOS: AttackScenario[] = [
  SSH_BRUTE_FORCE,
  PORT_SCAN_RECON,
  SUSPICIOUS_AUTH,
  WEB_ATTACK,
  POST_EXPLOIT,
  DATA_EXFIL,
];

/**
 * Demo-mode script: a deliberately paced kill chain for presenting. Beats are
 * spaced so a narrator can talk over each stage without the feed racing ahead.
 */
export interface DemoBeat {
  /** Seconds from demo start. */
  at: number;
  label: string;
  steps: ScenarioStep[];
}

export const DEMO_SCRIPT: DemoBeat[] = [
  {
    at: 0,
    label: 'Reconnaissance — port scan',
    steps: [
      { eventType: 'new_connection', offset: 0 },
      { eventType: 'port_scan', offset: 1500, context: { portCount: 23 } },
    ],
  },
  {
    at: 5,
    label: 'Credential attack — SSH failures',
    steps: [
      { eventType: 'ssh_failed_auth', offset: 0, context: { username: 'root' } },
      { eventType: 'ssh_failed_auth', offset: 1200, context: { username: 'admin' } },
      { eventType: 'suspicious_login', offset: 2600, context: { username: 'oracle' } },
    ],
  },
  {
    at: 10,
    label: 'Detection — brute force confirmed',
    steps: [
      {
        eventType: 'ssh_brute_force',
        offset: 0,
        context: { attempts: 22, windowSeconds: 68, username: 'root' },
      },
    ],
  },
  {
    at: 15,
    label: 'Foothold — suspicious login succeeds',
    steps: [
      { eventType: 'successful_login', offset: 0, severity: 'high', context: { username: 'ubuntu' } },
      { eventType: 'suspicious_process', offset: 2000 },
    ],
  },
  {
    at: 20,
    label: 'Escalation — root transition and exfiltration',
    steps: [
      { eventType: 'privilege_escalation', offset: 0 },
      { eventType: 'data_exfiltration', offset: 2500, context: { bytes: 480_000_000, windowSeconds: 210 } },
    ],
  },
];

/** Total demo runtime in seconds, derived rather than hard-coded. */
export const DEMO_DURATION_SECONDS =
  Math.max(...DEMO_SCRIPT.map((beat) => beat.at + Math.max(...beat.steps.map((s) => s.offset)) / 1000)) + 4;

/** Turns a scenario into concrete events anchored at `startTime`. */
export function materializeScenario(
  scenario: AttackScenario,
  startTime: number,
  rng: Rng,
): SecurityEvent[] {
  return scenario.steps.map((step) =>
    buildEvent({
      eventType: step.eventType,
      timestamp: startTime + step.offset,
      rng,
      sourceIp: step.sourceIp,
      destinationIp: step.destinationIp,
      severity: step.severity,
      context: step.context,
    }),
  );
}
