import { lazy, Suspense, useCallback, useMemo, useState } from 'react';
import { useClock } from '@/hooks/useClock';
import { useEventFilters } from '@/hooks/useEventFilters';
import { computeHostRisk, computeKpis, computeTopSources } from '@/services/metrics';
import { computeSecurityScore } from '@/services/riskEngine';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import type { SecurityEvent, Severity } from '@/types/security';
import { AlertDetailPanel } from '@/components/dashboard/AlertDetailPanel';
import { DemoTimeline } from '@/components/dashboard/DemoTimeline';
import { HostTable } from '@/components/dashboard/HostTable';
import { KpiRow } from '@/components/dashboard/KpiRow';
import { LiveEventFeed } from '@/components/dashboard/LiveEventFeed';
import { SecurityScoreCard } from '@/components/dashboard/SecurityScoreCard';
import { TopAttackSources } from '@/components/dashboard/TopAttackSources';
import { ErrorState, Skeleton } from '@/components/ui/States';
import AnimatedContent from '@/components/reactbits/AnimatedContent';

/**
 * The charting library is by far the heaviest dependency. Splitting it out
 * lets the shell, KPIs, and feed paint while it loads in parallel with the
 * initial event snapshot, so the deferral costs nothing in practice.
 */
const ThreatActivityChart = lazy(() =>
  import('@/components/dashboard/ThreatActivityChart').then((m) => ({
    default: m.ThreatActivityChart,
  })),
);

/**
 * Metric refresh cadence. Fast enough that relative ages stay honest, slow
 * enough that the dashboard is not recomputing aggregates at 1 Hz.
 */
const METRIC_TICK_MS = 2000;

export function DashboardPage() {
  const {
    events,
    hosts,
    loading,
    error,
    status,
    mode,
    demoProgress,
    paused,
    setPaused,
    bufferedCount,
    applyAction,
    retry,
  } = useSecurityFeed();

  const now = useClock(METRIC_TICK_MS);
  const filters = useEventFilters(events);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Derive the selected event from the live collection rather than holding a
  // snapshot, so an action taken in the panel is reflected there immediately.
  const selectedEvent = useMemo(
    () => events.find((event) => event.id === selectedId) ?? null,
    [events, selectedId],
  );

  const kpis = useMemo(() => computeKpis(events, now), [events, now]);
  const score = useMemo(() => computeSecurityScore(events, now), [events, now]);
  const sources = useMemo(() => computeTopSources(events, 5, now), [events, now]);
  const hostsWithRisk = useMemo(() => computeHostRisk(hosts, events, now), [hosts, events, now]);

  const { setQuery, toggleSeverity, toggleHost, filters: filterState } = filters;

  // A source is "pinned" when the search box holds exactly that IP.
  const activeIp = useMemo(() => {
    const query = filterState.query.trim();
    return sources.some((source) => source.ip === query) ? query : null;
  }, [filterState.query, sources]);

  const activeSeverity: Severity | null =
    filterState.severities.length === 1 ? filterState.severities[0]! : null;

  const handleSelectSource = useCallback(
    (ip: string) => setQuery(filterState.query.trim() === ip ? '' : ip),
    [setQuery, filterState.query],
  );

  const handleSelectEvent = useCallback(
    (event: SecurityEvent) => setSelectedId((current) => (current === event.id ? null : event.id)),
    [],
  );

  const handleBlock = useCallback(
    (ip: string) => {
      const target = events.find((event) => event.sourceIp === ip);
      if (target) applyAction(target, 'block_ip');
    },
    [events, applyAction],
  );

  // A failed initial load leaves nothing to render — surface it instead of an
  // empty dashboard that looks like "no threats".
  if (error && events.length === 0) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <ErrorState
          title="Cannot reach the detection engine"
          message={error}
          onRetry={retry}
          className="surface-card"
        />
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0">
      <div className="min-w-0 flex-1 overflow-y-auto">
        <div className="space-y-4 p-5 xl:p-6">
          {mode === 'demo' ? <DemoTimeline progress={demoProgress} /> : null}

          {/* Transport trouble after a successful load: warn, but keep the
              dashboard usable with the data already held. */}
          {error && events.length > 0 ? (
            <div
              role="status"
              className="flex items-center gap-2 rounded-[var(--radius-control)] border border-crit/40 bg-crit/10 px-4 py-2.5 text-[11.5px] text-crit"
            >
              <span className="font-medium">Stream interrupted:</span>
              <span className="text-fg-muted">{error}</span>
              <button
                type="button"
                onClick={retry}
                className="ml-auto rounded-full border border-crit/40 px-2.5 py-1 text-[11px] hover:bg-crit/15"
              >
                Reconnect
              </button>
            </div>
          ) : null}

          <div>
            <h2 className="label-caps mb-3">Security Overview</h2>
            <KpiRow
              kpis={kpis}
              loading={loading}
              activeSeverity={activeSeverity}
              onSelectSeverity={toggleSeverity}
            />
          </div>

          <AnimatedContent
            distance={26}
            duration={0.7}
            ease="power3.out"
            threshold={0.12}
            initialOpacity={0}
            className="grid grid-cols-1 gap-4 xl:grid-cols-3"
          >
            {/* The chart carries the most information, so it gets the width. */}
            <div className="xl:col-span-2">
              <Suspense
                fallback={
                  <Skeleton className="h-[340px] w-full" />
                }
              >
                <ThreatActivityChart events={events} loading={loading} now={now} />
              </Suspense>
            </div>
            <SecurityScoreCard score={score} loading={loading} />
          </AnimatedContent>

          <AnimatedContent
            distance={26}
            duration={0.7}
            ease="power3.out"
            threshold={0.1}
            initialOpacity={0}
            className="grid grid-cols-1 items-start gap-4 xl:grid-cols-3"
          >
            <TopAttackSources
              sources={sources}
              loading={loading}
              now={now}
              onSelectSource={handleSelectSource}
              activeIp={activeIp}
              onBlock={handleBlock}
            />
            <div className="xl:col-span-2">
              <LiveEventFeed
                filters={filters}
                hosts={hosts}
                loading={loading}
                selectedId={selectedId}
                onSelect={handleSelectEvent}
                allEvents={events}
                now={now}
                paused={paused}
                bufferedCount={bufferedCount}
                onResume={() => setPaused(false)}
                className="h-[600px]"
              />
            </div>
          </AnimatedContent>

          <HostTable
            hosts={hostsWithRisk}
            loading={loading}
            now={now}
            onSelectHost={toggleHost}
            activeHostId={filterState.hosts[0] ?? null}
          />

          <p className="px-1 pb-2 text-[11px] text-fg-dim">
            Connection: {status} · {events.length.toLocaleString('en-US')} events retained
          </p>
        </div>
      </div>

      <AlertDetailPanel
        event={selectedEvent}
        events={events}
        onClose={() => setSelectedId(null)}
        onAction={applyAction}
        now={now}
      />
    </div>
  );
}
