/**
 * Context object and value shape for the security feed.
 *
 * Deliberately separate from both the provider component and the hook: React
 * Fast Refresh only preserves state for modules whose exports are all
 * components, so mixing a provider and a hook in one file forces a full app
 * remount on every edit. Splitting them keeps development state intact.
 */
import { createContext } from 'react';
import type { AlertAction } from '@/config/eventTypes';
import type { DemoProgress } from '@/data/providers';
import type { DataSourceMode, FeedStatus, Host, SecurityEvent } from '@/types/security';

export interface SecurityFeedValue {
  events: SecurityEvent[];
  hosts: Host[];
  status: FeedStatus;
  error: string | null;
  loading: boolean;
  mode: DataSourceMode;
  setMode: (mode: DataSourceMode) => void;
  providerLabel: string;
  /** True when a real backend URL is configured; false means mock data. */
  backendConfigured: boolean;
  demoProgress: DemoProgress | null;
  /** Freezes the feed so a row can be read without it scrolling away. */
  paused: boolean;
  setPaused: (paused: boolean) => void;
  /** Events withheld while paused. */
  bufferedCount: number;
  applyAction: (event: SecurityEvent, action: AlertAction) => void;
  retry: () => void;
}

export const SecurityFeedContext = createContext<SecurityFeedValue | null>(null);
