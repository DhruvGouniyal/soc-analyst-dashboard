/**
 * Provider selection — the one place that decides where data comes from.
 *
 * Swapping the dashboard onto the real Ubuntu detection engine is a config
 * change, not a code change: set `VITE_SOC_API_URL` and the factory returns
 * `UbuntuSecurityEventProvider` instead of the mock. Everything above this
 * module is provider-agnostic.
 */
import type { DataSourceMode } from '@/types/security';
import { DemoSecurityEventProvider, type DemoProgress } from './DemoSecurityEventProvider';
import { MockSecurityEventProvider } from './MockSecurityEventProvider';
import { UbuntuSecurityEventProvider } from './UbuntuSecurityEventProvider';
import type { SecurityEventProvider } from './types';

/** Backend base URL, e.g. `http://10.139.116.20:8000`. Unset ⇒ mock data. */
const API_URL = import.meta.env.VITE_SOC_API_URL?.trim();

/** True when a real backend is configured. Surfaced in the UI banner. */
export const isBackendConfigured = Boolean(API_URL);

export interface ProviderOptions {
  /** Called by the demo provider as the script advances. */
  onDemoProgress?: (progress: DemoProgress) => void;
}

/**
 * Returns the provider for the requested mode.
 *
 * Demo mode always uses the scripted provider, even when a backend is
 * configured — a presentation should never depend on live attack traffic
 * arriving on cue.
 */
export function createProvider(mode: DataSourceMode, options: ProviderOptions = {}): SecurityEventProvider {
  if (mode === 'demo') {
    return new DemoSecurityEventProvider(options.onDemoProgress);
  }
  if (API_URL) {
    return new UbuntuSecurityEventProvider(API_URL);
  }
  return new MockSecurityEventProvider();
}

export type { SecurityEventProvider, InitialSnapshot, ProviderHandlers } from './types';
export type { DemoProgress } from './DemoSecurityEventProvider';
