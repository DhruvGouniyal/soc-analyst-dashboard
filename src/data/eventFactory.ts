/**
 * Builds `SecurityEvent` objects that hold together internally.
 *
 * Each detection type produces a description, supporting detail, and a raw log
 * line in the format the corresponding Ubuntu collector actually emits. That
 * matters beyond looks: it means the UI is already rendering the shape of real
 * data, so swapping in `UbuntuSecurityEventProvider` changes the source of the
 * text, not the structure around it.
 */
import { EVENT_TYPES } from '@/config/eventTypes';
import type { EventType, Protocol, SecurityEvent, Severity } from '@/types/security';
import { pick, randomInt, type Rng } from './random';
import {
  ATTACKER_IP,
  EXFIL_DESTINATION_IP,
  SCANNED_PORTS,
  SUSPICIOUS_PROCESSES,
  TARGET_USERNAMES,
  VICTIM_IP,
  WEB_ATTACK_PAYLOADS,
  hostIdForIp,
} from './topology';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** `Aug 22 11:41:02` — the syslog/auth.log prefix format. */
function syslogTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${MONTHS[d.getMonth()]} ${String(d.getDate()).padStart(2, ' ')} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

let sequence = 0;
function nextId(ts: number): string {
  sequence += 1;
  return `evt-${ts.toString(36)}-${sequence.toString(36)}`;
}

/** Scenario-supplied facts that make a burst of events tell one story. */
export interface EventContext {
  /** Failed-authentication count for brute force. */
  attempts?: number;
  /** Distinct ports touched by a scan. */
  portCount?: number;
  /** Account being targeted. */
  username?: string;
  /** Bytes moved, for exfiltration. */
  bytes?: number;
  /** Seconds the activity spanned. */
  windowSeconds?: number;
}

export interface EventSpec {
  eventType: EventType;
  timestamp: number;
  rng: Rng;
  sourceIp?: string;
  destinationIp?: string;
  /** Overrides the catalog default when a scenario escalates an event. */
  severity?: Severity;
  context?: EventContext;
}

interface Detail {
  description: string;
  detail: string;
  rawLog: string;
  destinationPort: number | null;
  protocol: Protocol;
  confidence: number;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1000) return `${(bytes / 1000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function buildDetail(spec: EventSpec, srcIp: string, dstIp: string, srcPort: number): Detail {
  const { eventType, timestamp, rng, context = {} } = spec;
  const ts = syslogTime(timestamp);
  const pid = randomInt(rng, 10000, 65000);
  const username = context.username ?? pick(rng, TARGET_USERNAMES);

  switch (eventType) {
    case 'ssh_brute_force': {
      const attempts = context.attempts ?? randomInt(rng, 12, 28);
      const window = context.windowSeconds ?? randomInt(rng, 45, 120);
      return {
        description: `${attempts} failed authentication attempts in ${window}s`,
        detail: `Repeated password failures against account "${username}" from a single source. Attempt rate is well above human interactive speed, indicating an automated tool.`,
        rawLog: `${ts} ubuntu-victim sshd[${pid}]: error: maximum authentication attempts exceeded for ${username} from ${srcIp} port ${srcPort} ssh2 [preauth]`,
        destinationPort: 22,
        protocol: 'SSH',
        confidence: randomInt(rng, 92, 99),
      };
    }

    case 'ssh_failed_auth':
      return {
        description: `Failed password for "${username}"`,
        detail: `A single SSH password failure. Correlate against ${srcIp} to determine whether this is part of a larger pattern.`,
        rawLog: `${ts} ubuntu-victim sshd[${pid}]: Failed password for ${username} from ${srcIp} port ${srcPort} ssh2`,
        destinationPort: 22,
        protocol: 'SSH',
        confidence: randomInt(rng, 70, 88),
      };

    case 'successful_login':
      return {
        description: `Accepted password for "${username}"`,
        detail: `Session established from ${srcIp}. Verify this login was expected — success directly after repeated failures indicates credential compromise.`,
        rawLog: `${ts} ubuntu-victim sshd[${pid}]: Accepted password for ${username} from ${srcIp} port ${srcPort} ssh2`,
        destinationPort: 22,
        protocol: 'SSH',
        confidence: randomInt(rng, 60, 80),
      };

    case 'port_scan': {
      const portCount = context.portCount ?? randomInt(rng, 15, 40);
      const sample = SCANNED_PORTS.slice(0, Math.min(6, SCANNED_PORTS.length)).join(', ');
      return {
        description: `${portCount} ports scanned`,
        detail: `Sequential connection attempts across ${portCount} ports (including ${sample}). Consistent with an nmap service sweep.`,
        rawLog: `{"timestamp":"${new Date(timestamp).toISOString()}","event_type":"alert","src_ip":"${srcIp}","dest_ip":"${dstIp}","proto":"TCP","alert":{"signature":"ET SCAN Nmap Scripting Engine Detected","category":"Attempted Information Leak","severity":2}}`,
        destinationPort: null,
        protocol: 'TCP',
        confidence: randomInt(rng, 85, 96),
      };
    }

    case 'suspicious_login':
      return {
        description: `Invalid SSH credentials for "${username}"`,
        detail: `Authentication attempted against an account that does not exist on this host, suggesting credential guessing rather than a mistyped password.`,
        rawLog: `${ts} ubuntu-victim sshd[${pid}]: Invalid user ${username} from ${srcIp} port ${srcPort}`,
        destinationPort: 22,
        protocol: 'SSH',
        confidence: randomInt(rng, 72, 90),
      };

    case 'web_attack': {
      const payload = pick(rng, WEB_ATTACK_PAYLOADS);
      return {
        description: payload.label,
        detail: `Request to ${payload.path} matched signature "${payload.signature}". Confirm the application response code to determine whether the attempt succeeded.`,
        rawLog: `{"timestamp":"${new Date(timestamp).toISOString()}","event_type":"alert","src_ip":"${srcIp}","dest_ip":"${dstIp}","proto":"TCP","http":{"url":"${payload.path}","status":403},"alert":{"signature":"${payload.signature}","severity":1}}`,
        destinationPort: 80,
        protocol: 'HTTP',
        confidence: randomInt(rng, 80, 95),
      };
    }

    case 'suspicious_process': {
      const proc = pick(rng, SUSPICIOUS_PROCESSES);
      return {
        description: proc.label,
        detail: `Process "${proc.cmd}" was spawned by ${proc.parent}, which does not normally launch interpreters. Review the full process tree before clearing.`,
        rawLog: `type=EXECVE msg=audit(${(timestamp / 1000).toFixed(3)}:${pid}): argc=3 a0="${proc.cmd.split(' ')[0]}" ppid_comm="${proc.parent}" uid=33`,
        destinationPort: null,
        protocol: 'TCP',
        confidence: randomInt(rng, 78, 93),
      };
    }

    case 'privilege_escalation':
      return {
        description: 'Unexpected root privilege transition',
        detail: `A process owned by www-data acquired uid=0 outside of any sudo session. This is a strong indicator of successful local exploitation.`,
        rawLog: `type=SYSCALL msg=audit(${(timestamp / 1000).toFixed(3)}:${pid}): arch=c000003e syscall=59 success=yes exit=0 auid=4294967295 uid=33 euid=0 comm="sh"`,
        destinationPort: null,
        protocol: 'TCP',
        confidence: randomInt(rng, 88, 97),
      };

    case 'data_exfiltration': {
      const bytes = context.bytes ?? randomInt(rng, 40_000_000, 800_000_000);
      return {
        description: `${formatBytes(bytes)} transferred outbound`,
        detail: `Sustained outbound transfer to ${dstIp} far exceeding this host's baseline. Identify the owning process and destination reputation before the transfer completes.`,
        rawLog: `flow: ${srcIp}:${srcPort} -> ${dstIp}:443 proto=TCP bytes_toserver=${bytes} duration=${context.windowSeconds ?? 180}s state=established`,
        destinationPort: 443,
        protocol: 'HTTPS',
        confidence: randomInt(rng, 74, 90),
      };
    }

    case 'new_connection':
      return {
        description: 'Outbound TCP connection established',
        detail: `First observed connection to this destination from ${srcIp}. Informational on its own; useful as corroboration around a confirmed incident.`,
        rawLog: `flow: ${srcIp}:${srcPort} -> ${dstIp}:443 proto=TCP state=new`,
        destinationPort: 443,
        protocol: 'TCP',
        confidence: randomInt(rng, 45, 65),
      };

    case 'malware_signature':
      return {
        description: 'Known-malicious file signature matched',
        detail: `Content written to /tmp matched a known payload signature. Preserve the artifact and isolate the host before remediation.`,
        rawLog: `{"timestamp":"${new Date(timestamp).toISOString()}","event_type":"alert","src_ip":"${srcIp}","dest_ip":"${dstIp}","alert":{"signature":"ET MALWARE Linux/Mirai Variant Download","category":"A Network Trojan was Detected","severity":1}}`,
        destinationPort: 80,
        protocol: 'HTTP',
        confidence: randomInt(rng, 90, 99),
      };
  }
}

/** Creates one fully-populated event. */
export function buildEvent(spec: EventSpec): SecurityEvent {
  const meta = EVENT_TYPES[spec.eventType];
  const srcIp =
    spec.sourceIp ?? (spec.eventType === 'data_exfiltration' || spec.eventType === 'new_connection' ? VICTIM_IP : ATTACKER_IP);
  const dstIp =
    spec.destinationIp ??
    (spec.eventType === 'data_exfiltration'
      ? EXFIL_DESTINATION_IP
      : spec.eventType === 'new_connection'
        ? EXFIL_DESTINATION_IP
        : VICTIM_IP);
  const srcPort = randomInt(spec.rng, 32768, 61000);
  const detail = buildDetail(spec, srcIp, dstIp, srcPort);

  return {
    id: nextId(spec.timestamp),
    timestamp: spec.timestamp,
    severity: spec.severity ?? meta.defaultSeverity,
    eventType: spec.eventType,
    sourceIp: srcIp,
    sourcePort: srcPort,
    destinationIp: dstIp,
    destinationPort: detail.destinationPort,
    protocol: detail.protocol,
    host: hostIdForIp(dstIp === VICTIM_IP ? VICTIM_IP : srcIp),
    description: detail.description,
    detail: detail.detail,
    status: 'new',
    mitreTechnique: meta.mitre,
    confidence: detail.confidence,
    logSource: meta.logSource,
    rawLog: detail.rawLog,
  };
}
