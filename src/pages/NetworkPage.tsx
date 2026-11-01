import { Network as NetworkIcon } from 'lucide-react';
import { useMemo } from 'react';
import { SEVERITY_STYLES } from '@/config/theme';
import { useClock } from '@/hooks/useClock';
import { cn } from '@/lib/cn';
import { deriveNetworkFlows, formatBytes, type FlowState, type NetworkFlow } from '@/services/derived';
import { relativeTime } from '@/services/time';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Panel } from '@/components/ui/Panel';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { EmptyState, Skeleton } from '@/components/ui/States';
import { Meter } from '@/components/ui/StatusBadge';

const STATE_META: Record<FlowState, { label: string; className: string }> = {
  established: { label: 'Established', className: 'text-fg-muted' },
  attempted: { label: 'Attempted', className: 'text-med' },
  blocked: { label: 'Blocked', className: 'text-low' },
};

const RENDER_LIMIT = 120;
const COLUMNS = ['Source', 'Destination', 'Port', 'Proto', 'State', 'Events', 'Volume', 'Last Seen', 'Severity'];

export function NetworkPage() {
  const { events, loading } = useSecurityFeed();
  const now = useClock(2000);
  const { flows, talkers } = useMemo(() => deriveNetworkFlows(events, now), [events, now]);
  const visible = flows.slice(0, RENDER_LIMIT);
  const maxBytes = Math.max(1, ...talkers.map((t) => t.bytes));

  return (
    <div className="h-full overflow-y-auto p-3">
      <div className="mb-2 grid grid-cols-1 gap-2 xl:grid-cols-3">
        <Panel title="Top Talkers" meta="By volume" flush className="xl:col-span-1">
          {loading ? (
            <div className="space-y-2 p-3">
              {Array.from({ length: 4 }, (_, i) => (
                <Skeleton key={i} className="h-9" />
              ))}
            </div>
          ) : talkers.length === 0 ? (
            <EmptyState title="No traffic observed" />
          ) : (
            <ul>
              {talkers.map((talker) => {
                const styles = SEVERITY_STYLES[talker.severity];
                return (
                  <li key={talker.ip} className="border-b border-line/60 px-3 py-2 last:border-b-0">
                    <div className="mb-1 flex items-center gap-2">
                      <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', styles.dot)} aria-hidden="true" />
                      <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-fg">{talker.ip}</span>
                      <span className="shrink-0 text-[11px] text-fg-muted tabular">{formatBytes(talker.bytes)}</span>
                    </div>
                    <Meter value={(talker.bytes / maxBytes) * 100} tone={styles.bar} className="h-1" />
                    <div className="mt-1 text-[10px] text-fg-dim tabular">
                      {talker.flows} flows · {talker.events} events
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>

        <Panel title="Active Flows" meta={loading ? undefined : `${flows.length} in last 24h`} flush className="xl:col-span-2">
          {loading ? (
            <div className="space-y-2 p-3">
              {Array.from({ length: 6 }, (_, i) => (
                <Skeleton key={i} className="h-7" />
              ))}
            </div>
          ) : visible.length === 0 ? (
            <EmptyState
              icon={<NetworkIcon className="h-5 w-5" />}
              title="No network flows"
              description="No connections have been observed in the retained window."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[680px] border-collapse">
                <thead>
                  <tr className="border-b border-line">
                    {COLUMNS.map((c) => (
                      <th key={c} scope="col" className="label-caps px-3 py-1.5 text-left whitespace-nowrap">
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {visible.map((flow) => (
                    <FlowRow key={flow.id} flow={flow} now={now} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

function FlowRow({ flow, now }: { flow: NetworkFlow; now: number }) {
  const state = STATE_META[flow.state];
  return (
    <tr className="border-b border-line/50 text-[11.5px] last:border-b-0 hover:bg-surface-hover">
      <td className="px-3 py-2 font-mono whitespace-nowrap text-fg-muted">{flow.sourceIp}</td>
      <td className="px-3 py-2 font-mono whitespace-nowrap text-fg-muted">{flow.destinationIp}</td>
      <td className="px-3 py-2 whitespace-nowrap text-fg-dim tabular">{flow.destinationPort ?? '—'}</td>
      <td className="px-3 py-2 whitespace-nowrap text-fg-dim">{flow.protocol}</td>
      <td className={cn('px-3 py-2 whitespace-nowrap', state.className)}>{state.label}</td>
      <td className="px-3 py-2 whitespace-nowrap text-fg-muted tabular">{flow.count}</td>
      <td className="px-3 py-2 whitespace-nowrap text-fg-muted tabular">{formatBytes(flow.bytes)}</td>
      <td className="px-3 py-2 whitespace-nowrap text-fg-dim tabular">{relativeTime(flow.lastSeen, now)}</td>
      <td className="px-3 py-2 whitespace-nowrap">
        <SeverityBadge severity={flow.severity} size="compact" />
      </td>
    </tr>
  );
}
