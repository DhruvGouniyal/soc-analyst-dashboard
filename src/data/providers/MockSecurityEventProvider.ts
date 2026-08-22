/**
 * Mock provider — stands in for the Ubuntu detection engine.
 *
 * Emits a realistic ambient drip punctuated by coordinated scenario bursts,
 * plus host telemetry that random-walks rather than jumping. All timers are
 * tracked so `connect()`'s teardown fully stops the stream; leaking one would
 * keep events arriving after a mode switch.
 */
import type { Host } from '@/types/security';
import { buildEvent } from '../eventFactory';
import { createAmbientEvent, generateBackfill } from '../backfill';
import { createRng, drift, pick, randomInt, type Rng } from '../random';
import { ALL_SCENARIOS } from '../scenarios';
import { INITIAL_HOSTS } from '../topology';
import type { InitialSnapshot, ProviderHandlers, SecurityEventProvider } from './types';

export class MockSecurityEventProvider implements SecurityEventProvider {
  readonly id = 'mock';
  readonly label = 'Mock Generator';

  /** Seeded from the clock: the live stream should not be predictable. */
  private readonly liveRng: Rng = createRng(Date.now() & 0xffffffff);
  private hosts: Host[] = INITIAL_HOSTS.map((h) => ({ ...h }));
  private timers = new Set<ReturnType<typeof setTimeout>>();
  private stopped = false;

  async loadInitial(): Promise<InitialSnapshot> {
    // A real delay so the loading state is a live code path, not a dead branch.
    await new Promise((resolve) => setTimeout(resolve, 260));
    const now = Date.now();
    this.hosts = INITIAL_HOSTS.map((h) => ({ ...h, lastSeen: now }));
    return { events: generateBackfill(now), hosts: this.hosts.map((h) => ({ ...h })) };
  }

  connect(handlers: ProviderHandlers): () => void {
    this.stopped = false;
    handlers.onStatus('connecting');

    this.defer(() => {
      handlers.onStatus('live');
      this.scheduleAmbientEvent(handlers);
      this.scheduleHostTelemetry(handlers);
      this.scheduleScenarioBurst(handlers);
    }, 320);

    return () => this.disconnect();
  }

  private disconnect(): void {
    this.stopped = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
  }

  /** Registers a timer that the teardown is guaranteed to clear. */
  private defer(fn: () => void, delay: number): void {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      if (this.stopped) return;
      fn();
    }, delay);
    this.timers.add(timer);
  }

  /**
   * Single ambient events, 2–7s apart. Drawn from the same model as the
   * backfill so live traffic is continuous with the history behind it.
   */
  private scheduleAmbientEvent(handlers: ProviderHandlers): void {
    this.defer(() => {
      handlers.onEvent(createAmbientEvent(this.liveRng, Date.now()));
      this.scheduleAmbientEvent(handlers);
    }, randomInt(this.liveRng, 2000, 7000));
  }

  /**
   * Occasional coordinated bursts, so the feed shows recognizable attack
   * patterns instead of a uniform drip.
   */
  private scheduleScenarioBurst(handlers: ProviderHandlers): void {
    this.defer(() => {
      const scenario = pick(this.liveRng, ALL_SCENARIOS);
      for (const step of scenario.steps) {
        this.defer(() => {
          handlers.onEvent(
            buildEvent({
              eventType: step.eventType,
              timestamp: Date.now(),
              rng: this.liveRng,
              sourceIp: step.sourceIp,
              destinationIp: step.destinationIp,
              severity: step.severity,
              context: step.context,
            }),
          );
        }, step.offset);
      }
      this.scheduleScenarioBurst(handlers);
    }, randomInt(this.liveRng, 45_000, 90_000));
  }

  /** Host CPU/memory random-walk, refreshed every 3s. */
  private scheduleHostTelemetry(handlers: ProviderHandlers): void {
    this.defer(() => {
      const now = Date.now();
      this.hosts = this.hosts.map((host) => {
        const cpu = drift(this.liveRng, host.cpu, 6, 4, 97);
        const memory = drift(this.liveRng, host.memory, 3, 15, 95);
        return {
          ...host,
          cpu,
          memory,
          network: cpu > 85 ? 'saturated' : cpu > 62 ? 'elevated' : 'normal',
          lastSeen: now,
        };
      });
      handlers.onHosts(this.hosts.map((h) => ({ ...h })));
      this.scheduleHostTelemetry(handlers);
    }, 3000);
  }
}
