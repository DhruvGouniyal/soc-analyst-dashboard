/**
 * The single source of live state for the dashboard.
 *
 * Owns the provider lifecycle (load history → connect stream → tear down) and
 * exposes events, hosts, connection status, and analyst actions. Components
 * never touch a data provider directly, which is what allows the mock, demo,
 * and Ubuntu sources to be interchangeable.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { ALERT_ACTIONS, type AlertAction } from '@/config/eventTypes';
import { createProvider, isBackendConfigured, type DemoProgress } from '@/data/providers';
import { addEvent, blockSourceIp, initializeEvents, updateEventStatus } from '@/services/eventStore';
import type { DataSourceMode, FeedStatus, Host, SecurityEvent } from '@/types/security';
import { SecurityFeedContext, type SecurityFeedValue } from './securityFeedContext';

export function SecurityFeedProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [status, setStatus] = useState<FeedStatus>('idle');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState<DataSourceMode>('live');
  const [providerLabel, setProviderLabel] = useState('');
  const [demoProgress, setDemoProgress] = useState<DemoProgress | null>(null);
  const [paused, setPaused] = useState(false);
  const [bufferedCount, setBufferedCount] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);

  // Refs so the stream handler always sees current values without the effect
  // needing to re-subscribe (which would drop and rebuild the connection).
  const pausedRef = useRef(paused);
  const bufferRef = useRef<SecurityEvent[]>([]);

  useEffect(() => {
    pausedRef.current = paused;
    if (!paused && bufferRef.current.length > 0) {
      // Flush newest-first to preserve the collection's ordering invariant.
      const buffered = bufferRef.current;
      bufferRef.current = [];
      setBufferedCount(0);
      setEvents((current) => initializeEvents([...buffered, ...current]));
    }
  }, [paused]);

  useEffect(() => {
    let cancelled = false;
    let teardown: (() => void) | undefined;

    // A fresh instance per run keeps StrictMode's mount/unmount/remount cycle
    // from reusing a provider that has already been torn down.
    const provider = createProvider(mode, { onDemoProgress: setDemoProgress });

    setProviderLabel(provider.label);
    setLoading(true);
    setError(null);
    setStatus('connecting');
    setDemoProgress(null);
    bufferRef.current = [];
    setBufferedCount(0);

    provider
      .loadInitial()
      .then((snapshot) => {
        if (cancelled) return;
        setEvents(initializeEvents(snapshot.events));
        setHosts(snapshot.hosts);
        setLoading(false);

        teardown = provider.connect({
          onEvent: (event) => {
            if (pausedRef.current) {
              bufferRef.current = [event, ...bufferRef.current];
              setBufferedCount(bufferRef.current.length);
              return;
            }
            setEvents((current) => addEvent(current, event));
          },
          onHosts: setHosts,
          onStatus: (nextStatus, message) => {
            setStatus(nextStatus);
            setError(nextStatus === 'error' ? (message ?? 'Connection failed') : null);
          },
        });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setLoading(false);
        setStatus('error');
        setError(
          err instanceof Error
            ? err.message
            : 'Failed to load security events from the detection engine',
        );
      });

    return () => {
      cancelled = true;
      teardown?.();
    };
  }, [mode, reloadKey]);

  /**
   * Applies an analyst decision. Frontend-only for now, but it mutates the
   * same state the KPIs and security score read from, so the effect of working
   * the queue is visible immediately.
   */
  const applyAction = useCallback((event: SecurityEvent, action: AlertAction) => {
    const meta = ALERT_ACTIONS[action];
    setEvents((current) =>
      action === 'block_ip'
        ? blockSourceIp(current, event.sourceIp)
        : updateEventStatus(current, event.id, meta.transitionsTo),
    );
  }, []);

  const retry = useCallback(() => setReloadKey((key) => key + 1), []);

  const value = useMemo<SecurityFeedValue>(
    () => ({
      events,
      hosts,
      status,
      error,
      loading,
      mode,
      setMode,
      providerLabel,
      backendConfigured: isBackendConfigured,
      demoProgress,
      paused,
      setPaused,
      bufferedCount,
      applyAction,
      retry,
    }),
    [
      events,
      hosts,
      status,
      error,
      loading,
      mode,
      providerLabel,
      demoProgress,
      paused,
      bufferedCount,
      applyAction,
      retry,
    ],
  );

  return <SecurityFeedContext.Provider value={value}>{children}</SecurityFeedContext.Provider>;
}
