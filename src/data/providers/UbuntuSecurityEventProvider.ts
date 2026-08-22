/**
 * Ubuntu provider — the real integration point.
 *
 * This is deliberately *not* a fake: it is a complete HTTP + WebSocket client
 * for the SOC backend that simply has no server to talk to yet. Point
 * `VITE_SOC_API_URL` at the detection engine and it starts working; until then
 * it reports a clear error through the dashboard's error state rather than
 * inventing data.
 *
 * Expected backend contract
 * -------------------------
 *   GET  {baseUrl}/api/events?since=<epoch_ms>   -> { events: RawEvent[], hosts: RawHost[] }
 *   WS   {baseUrl}/ws/events                     -> stream of
 *          { type: 'event', payload: RawEvent }
 *          { type: 'hosts', payload: RawHost[] }
 *
 * `normalizeEvent` is the only place that needs to change if the backend's
 * field names differ from the dashboard's schema — keep the mapping here so
 * components never see backend-shaped data.
 */
import { EVENT_TYPES } from '@/config/eventTypes';
import type { EventType, Host, SecurityEvent, Severity } from '@/types/security';
import { HISTORY_WINDOW_MS } from '../backfill';
import type { InitialSnapshot, ProviderHandlers, SecurityEventProvider } from './types';

/** Loosely-typed payload as it arrives off the wire, before validation. */
type RawEvent = Record<string, unknown>;

const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30_000;

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function asSeverity(value: unknown): Severity {
  return value === 'critical' || value === 'high' || value === 'medium' || value === 'low'
    ? value
    : 'low';
}

function asEventType(value: unknown): EventType {
  return typeof value === 'string' && value in EVENT_TYPES ? (value as EventType) : 'new_connection';
}

/**
 * Maps a backend payload onto the dashboard schema. Falls back to catalog
 * defaults rather than throwing, so one malformed field can't blank the feed.
 */
export function normalizeEvent(raw: RawEvent): SecurityEvent {
  const eventType = asEventType(raw.eventType ?? raw.event_type);
  const meta = EVENT_TYPES[eventType];
  const rawTimestamp = raw.timestamp;

  return {
    id: asString(raw.id) || `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp:
      typeof rawTimestamp === 'number'
        ? rawTimestamp
        : typeof rawTimestamp === 'string'
          ? Date.parse(rawTimestamp)
          : Date.now(),
    severity: asSeverity(raw.severity),
    eventType,
    sourceIp: asString(raw.sourceIp ?? raw.src_ip, '0.0.0.0'),
    sourcePort: typeof raw.sourcePort === 'number' ? raw.sourcePort : null,
    destinationIp: asString(raw.destinationIp ?? raw.dest_ip, '0.0.0.0'),
    destinationPort: typeof raw.destinationPort === 'number' ? raw.destinationPort : null,
    protocol: (asString(raw.protocol, 'TCP').toUpperCase() as SecurityEvent['protocol']) ?? 'TCP',
    host: asString(raw.host, 'unknown'),
    description: asString(raw.description, meta.label),
    detail: typeof raw.detail === 'string' ? raw.detail : undefined,
    status: raw.status === 'investigating' || raw.status === 'blocked' || raw.status === 'resolved'
      ? raw.status
      : 'new',
    mitreTechnique: typeof raw.mitreTechnique === 'string' ? raw.mitreTechnique : meta.mitre,
    confidence: asNumber(raw.confidence, 75),
    logSource: (asString(raw.logSource, meta.logSource) as SecurityEvent['logSource']) ?? meta.logSource,
    rawLog: typeof raw.rawLog === 'string' ? raw.rawLog : undefined,
  };
}

function normalizeHost(raw: RawEvent): Host {
  return {
    id: asString(raw.id, asString(raw.hostname, 'unknown')),
    hostname: asString(raw.hostname, 'unknown'),
    ip: asString(raw.ip, '0.0.0.0'),
    os: asString(raw.os, 'Unknown'),
    role: raw.role === 'attacker' || raw.role === 'sensor' ? raw.role : 'victim',
    status: raw.status === 'offline' || raw.status === 'degraded' ? raw.status : 'online',
    cpu: asNumber(raw.cpu),
    memory: asNumber(raw.memory),
    network: raw.network === 'elevated' || raw.network === 'saturated' ? raw.network : 'normal',
    lastSeen: asNumber(raw.lastSeen, Date.now()),
  };
}

export class UbuntuSecurityEventProvider implements SecurityEventProvider {
  readonly id = 'ubuntu';
  readonly label = 'Ubuntu Collector';

  private socket: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private reconnectAttempt = 0;
  private stopped = false;

  constructor(private readonly baseUrl: string) {}

  async loadInitial(): Promise<InitialSnapshot> {
    const since = Date.now() - HISTORY_WINDOW_MS;
    const response = await fetch(`${this.baseUrl}/api/events?since=${since}`);
    if (!response.ok) {
      throw new Error(`Backend returned ${response.status} ${response.statusText}`);
    }
    const body = (await response.json()) as { events?: RawEvent[]; hosts?: RawEvent[] };
    return {
      events: (body.events ?? []).map(normalizeEvent).sort((a, b) => a.timestamp - b.timestamp),
      hosts: (body.hosts ?? []).map(normalizeHost),
    };
  }

  connect(handlers: ProviderHandlers): () => void {
    this.stopped = false;
    this.openSocket(handlers);
    return () => this.disconnect();
  }

  private openSocket(handlers: ProviderHandlers): void {
    if (this.stopped) return;
    handlers.onStatus('connecting');

    const wsUrl = this.baseUrl.replace(/^http/, 'ws') + '/ws/events';
    let socket: WebSocket;
    try {
      socket = new WebSocket(wsUrl);
    } catch (error) {
      handlers.onStatus('error', error instanceof Error ? error.message : 'WebSocket unavailable');
      this.scheduleReconnect(handlers);
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      this.reconnectAttempt = 0;
      handlers.onStatus('live');
    };

    socket.onmessage = (message) => {
      try {
        const frame = JSON.parse(message.data as string) as { type?: string; payload?: unknown };
        if (frame.type === 'event' && frame.payload) {
          handlers.onEvent(normalizeEvent(frame.payload as RawEvent));
        } else if (frame.type === 'hosts' && Array.isArray(frame.payload)) {
          handlers.onHosts((frame.payload as RawEvent[]).map(normalizeHost));
        }
      } catch {
        // A single malformed frame should not tear down the stream.
      }
    };

    socket.onerror = () => {
      handlers.onStatus('error', 'Detection engine connection failed');
    };

    socket.onclose = () => {
      this.socket = null;
      if (!this.stopped) {
        handlers.onStatus('error', 'Detection engine disconnected');
        this.scheduleReconnect(handlers);
      }
    };
  }

  /** Exponential backoff, capped, so a downed backend isn't hammered. */
  private scheduleReconnect(handlers: ProviderHandlers): void {
    if (this.stopped || this.reconnectTimer) return;
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** this.reconnectAttempt, RECONNECT_MAX_MS);
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.openSocket(handlers);
    }, delay);
  }

  private disconnect(): void {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.socket?.close();
    this.socket = null;
  }
}
