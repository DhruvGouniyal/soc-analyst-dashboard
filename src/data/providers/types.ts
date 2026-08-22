/**
 * The contract every data source implements.
 *
 * This is the seam between the dashboard and the outside world. `MockSecurityEventProvider`
 * satisfies it today; `UbuntuSecurityEventProvider` will satisfy it over a
 * WebSocket/SSE connection to the detection engine. Nothing above this
 * interface knows which one is running.
 */
import type { FeedStatus, Host, SecurityEvent } from '@/types/security';

export interface InitialSnapshot {
  /** Historical backfill so the dashboard has context on first paint. */
  events: SecurityEvent[];
  hosts: Host[];
}

export interface ProviderHandlers {
  /** A single new detection arrived. */
  onEvent: (event: SecurityEvent) => void;
  /** Host telemetry refreshed. Always the full inventory, not a delta. */
  onHosts: (hosts: Host[]) => void;
  /** Transport state changed. Drives the LIVE/ERROR indicator in the header. */
  onStatus: (status: FeedStatus, message?: string) => void;
}

export interface SecurityEventProvider {
  readonly id: string;
  /** Shown in the UI so the analyst always knows where data is coming from. */
  readonly label: string;

  /**
   * Fetch the historical window. Rejecting here surfaces the dashboard's
   * error state.
   */
  loadInitial: () => Promise<InitialSnapshot>;

  /**
   * Open the live stream. Returns a teardown function; it must be safe to
   * call more than once.
   */
  connect: (handlers: ProviderHandlers) => () => void;
}
