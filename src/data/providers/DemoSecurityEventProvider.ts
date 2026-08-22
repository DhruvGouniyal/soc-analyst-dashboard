/**
 * Demo provider — a scripted kill chain for presenting.
 *
 * Unlike the mock provider's randomized drip, this walks a fixed sequence
 * (recon → credential attack → detection → foothold → escalation) at a pace a
 * narrator can talk over. It keeps the same 24-hour backfill so charts and
 * KPIs retain context: the scripted attack layers on top of a populated
 * dashboard rather than starting from an empty one.
 *
 * The loop restarts after a pause so an unattended demo keeps running.
 */
import type { Host } from '@/types/security';
import { generateBackfill } from '../backfill';
import { buildEvent } from '../eventFactory';
import { createRng, drift, type Rng } from '../random';
import { DEMO_DURATION_SECONDS, DEMO_SCRIPT } from '../scenarios';
import { INITIAL_HOSTS } from '../topology';
import type { InitialSnapshot, ProviderHandlers, SecurityEventProvider } from './types';

/** Quiet gap between loops so the sequence reads as discrete runs. */
const LOOP_PAUSE_MS = 12_000;

export interface DemoProgress {
  /** Index into `DEMO_SCRIPT`, or -1 before the first beat fires. */
  beatIndex: number;
  /** How many times the script has completed. */
  cycle: number;
}

export class DemoSecurityEventProvider implements SecurityEventProvider {
  readonly id = 'demo';
  readonly label = 'Demo Sequence';

  private readonly rng: Rng = createRng(0xde3a0);
  private hosts: Host[] = INITIAL_HOSTS.map((h) => ({ ...h }));
  private timers = new Set<ReturnType<typeof setTimeout>>();
  private stopped = false;
  private cycle = 0;

  /** Lets the UI highlight the beat currently playing. */
  constructor(private readonly onProgress?: (progress: DemoProgress) => void) {}

  async loadInitial(): Promise<InitialSnapshot> {
    await new Promise((resolve) => setTimeout(resolve, 220));
    const now = Date.now();
    this.hosts = INITIAL_HOSTS.map((h) => ({ ...h, lastSeen: now }));
    return { events: generateBackfill(now), hosts: this.hosts.map((h) => ({ ...h })) };
  }

  connect(handlers: ProviderHandlers): () => void {
    this.stopped = false;
    this.cycle = 0;
    handlers.onStatus('connecting');

    this.defer(() => {
      handlers.onStatus('live');
      this.onProgress?.({ beatIndex: -1, cycle: 0 });
      this.runScript(handlers);
      this.scheduleHostTelemetry(handlers);
    }, 300);

    return () => this.disconnect();
  }

  private disconnect(): void {
    this.stopped = true;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
  }

  private defer(fn: () => void, delay: number): void {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      if (this.stopped) return;
      fn();
    }, delay);
    this.timers.add(timer);
  }

  /** Schedules one full pass of the script, then queues the next. */
  private runScript(handlers: ProviderHandlers): void {
    DEMO_SCRIPT.forEach((beat, beatIndex) => {
      this.defer(() => {
        this.onProgress?.({ beatIndex, cycle: this.cycle });
        for (const step of beat.steps) {
          this.defer(() => {
            handlers.onEvent(
              buildEvent({
                eventType: step.eventType,
                timestamp: Date.now(),
                rng: this.rng,
                sourceIp: step.sourceIp,
                destinationIp: step.destinationIp,
                severity: step.severity,
                context: step.context,
              }),
            );
          }, step.offset);
        }
      }, beat.at * 1000);
    });

    this.defer(
      () => {
        this.cycle += 1;
        this.onProgress?.({ beatIndex: -1, cycle: this.cycle });
        this.runScript(handlers);
      },
      DEMO_DURATION_SECONDS * 1000 + LOOP_PAUSE_MS,
    );
  }

  private scheduleHostTelemetry(handlers: ProviderHandlers): void {
    this.defer(() => {
      const now = Date.now();
      this.hosts = this.hosts.map((host) => {
        const cpu = drift(this.rng, host.cpu, 5, 6, 96);
        return {
          ...host,
          cpu,
          memory: drift(this.rng, host.memory, 3, 15, 95),
          network: cpu > 85 ? 'saturated' : cpu > 62 ? 'elevated' : 'normal',
          lastSeen: now,
        };
      });
      handlers.onHosts(this.hosts.map((h) => ({ ...h })));
      this.scheduleHostTelemetry(handlers);
    }, 3000);
  }
}
