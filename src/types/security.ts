/**
 * Canonical security domain model.
 *
 * Every layer of the app — mock generator, detection/risk engine, and UI —
 * speaks these types. When the Ubuntu collectors come online, the new provider
 * only has to emit `SecurityEvent` objects shaped like this and nothing
 * downstream changes.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Analyst-driven lifecycle state of an event. */
export type EventStatus = 'new' | 'investigating' | 'blocked' | 'resolved';

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'SSH' | 'DNS';

/**
 * Origin of the signal. These map 1:1 onto the real artifacts the Ubuntu
 * victim will expose, so a collector can stamp events without inventing a
 * vocabulary.
 */
export type LogSource =
  | 'auth.log'
  | 'syslog'
  | 'audit.log'
  | 'suricata'
  | 'netflow'
  | 'process';

/**
 * Detection classes the engine can emit. Adding one requires adding its
 * metadata in `config/eventTypes.ts`, which keeps labels and MITRE mapping
 * from drifting apart.
 */
export type EventType =
  | 'ssh_brute_force'
  | 'ssh_failed_auth'
  | 'successful_login'
  | 'port_scan'
  | 'suspicious_login'
  | 'web_attack'
  | 'suspicious_process'
  | 'privilege_escalation'
  | 'data_exfiltration'
  | 'new_connection'
  | 'malware_signature';

export interface SecurityEvent {
  id: string;
  /** Epoch milliseconds. Numeric so bucketing and sorting stay cheap. */
  timestamp: number;
  severity: Severity;
  eventType: EventType;
  sourceIp: string;
  sourcePort: number | null;
  destinationIp: string;
  destinationPort: number | null;
  protocol: Protocol;
  /** References `Host.id`. */
  host: string;
  /** One-line analyst summary. */
  description: string;
  /** Optional supporting evidence, shown in the detail panel. */
  detail?: string;
  status: EventStatus;
  /** MITRE ATT&CK technique id, e.g. `T1110`. Null when unmapped. */
  mitreTechnique: string | null;
  /** Detection confidence, 0–100. */
  confidence: number;
  /** Which collector produced this. Drives future log drill-down. */
  logSource: LogSource;
  /**
   * Verbatim log line the detection fired on. The mock provider synthesizes
   * a realistic one; the Ubuntu provider will pass the real line through.
   */
  rawLog?: string;
}

export type HostStatus = 'online' | 'offline' | 'degraded';
export type NetworkState = 'normal' | 'elevated' | 'saturated';

export interface Host {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  role: 'victim' | 'attacker' | 'sensor';
  status: HostStatus;
  /** Percentage, 0–100. */
  cpu: number;
  /** Percentage, 0–100. */
  memory: number;
  network: NetworkState;
  lastSeen: number;
}

/**
 * Derived, never stored: aggregated per-source-IP activity computed from the
 * current event window by the metrics layer.
 */
export interface AttackSource {
  ip: string;
  eventCount: number;
  severityCounts: Record<Severity, number>;
  /** Most frequent event type from this source. */
  dominantThreat: EventType;
  firstSeen: number;
  lastSeen: number;
  /** 0–100, from the risk engine. */
  riskScore: number;
}

/** Host augmented with risk derived from its associated events. */
export interface HostWithRisk extends Host {
  riskScore: number;
  riskLevel: Severity;
  eventCount: number;
}

export interface SecurityKpis {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  /** Total events in the retained window. */
  totalEvents: number;
  /** Distinct source IPs with at least one unresolved high/critical event. */
  activeThreats: number;
  /** Subset of `activeThreats` that are still unacknowledged. */
  threatsRequiringAttention: number;
  /** Critical events in the last hour vs. the hour before. */
  criticalDeltaLastHour: number;
  /** Percentage change in high-severity volume, hour over hour. */
  highDeltaPercent: number;
}

export interface SecurityScore {
  /** 0–100, higher is safer. */
  score: number;
  /** Human-facing band derived from `score`. */
  band: 'critical' | 'elevated' | 'moderate' | 'good';
  label: string;
  /** Per-severity contribution to the deduction, for transparency in the UI. */
  breakdown: { severity: Severity; count: number; penalty: number }[];
}

export type TimeRangeKey = '1h' | '6h' | '24h' | '7d';

/** One x-axis bucket of the threat activity chart. */
export interface ActivityBucket {
  /** Bucket start, epoch ms. */
  t: number;
  label: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface EventFilters {
  severities: Severity[];
  /** Free-text search across IPs, description, host, and event type. */
  query: string;
  eventTypes: EventType[];
  hosts: string[];
  statuses: EventStatus[];
}

export type SortKey = 'timestamp' | 'severity';
export type SortDirection = 'asc' | 'desc';

/** Connection state of the underlying event provider. */
export type FeedStatus = 'connecting' | 'live' | 'error' | 'idle';

/** Which provider is feeding the dashboard. */
export type DataSourceMode = 'live' | 'demo';
