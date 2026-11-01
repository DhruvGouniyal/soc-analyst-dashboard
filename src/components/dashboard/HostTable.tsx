import { Server } from 'lucide-react';
import { HOST_STATUS_META, NETWORK_STATE_META, SEVERITY_STYLES, utilizationTone } from '@/config/theme';
import { SEVERITY_META } from '@/config/severity';
import { cn } from '@/lib/cn';
import { relativeTime } from '@/services/time';
import type { HostWithRisk } from '@/types/security';
import { Panel } from '@/components/ui/Panel';
import { EmptyState, Skeleton } from '@/components/ui/States';
import { Meter, StatusDot } from '@/components/ui/StatusBadge';

interface HostTableProps {
  hosts: HostWithRisk[];
  loading: boolean;
  now: number;
  /** Filters the event feed to this host. */
  onSelectHost: (hostId: string) => void;
  activeHostId: string | null;
}

const COLUMNS = ['Host', 'IP Address', 'OS', 'Status', 'CPU', 'Memory', 'Network', 'Last Seen', 'Risk'];

export function HostTable({ hosts, loading, now, onSelectHost, activeHostId }: HostTableProps) {
  return (
    <Panel title="Active Hosts" meta={`${hosts.length} monitored`} flush className="min-h-[180px]">
      {loading ? (
        <div className="space-y-2 p-3">
          {Array.from({ length: 3 }, (_, i) => (
            <Skeleton key={i} className="h-8" />
          ))}
        </div>
      ) : hosts.length === 0 ? (
        <EmptyState
          icon={<Server className="h-5 w-5" />}
          title="No hosts reporting"
          description="No agent or collector has checked in with the detection engine."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] border-collapse">
            <thead>
              <tr className="border-b border-line">
                {COLUMNS.map((column) => (
                  <th
                    key={column}
                    scope="col"
                    className="label-caps px-3 py-1.5 text-left font-semibold whitespace-nowrap"
                  >
                    {column}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => {
                const status = HOST_STATUS_META[host.status];
                const network = NETWORK_STATE_META[host.network];
                const riskStyles = SEVERITY_STYLES[host.riskLevel];
                const isActive = host.id === activeHostId;

                return (
                  <tr
                    key={host.id}
                    onClick={() => onSelectHost(host.id)}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectHost(host.id);
                      }
                    }}
                    title={`Filter events for ${host.hostname}`}
                    className={cn(
                      'cursor-pointer border-b border-line/50 text-[11.5px] last:border-b-0',
                      'transition-colors duration-100',
                      isActive ? 'bg-accent/10' : 'hover:bg-surface-hover',
                    )}
                  >
                    <td className="px-3 py-2 font-medium whitespace-nowrap text-fg">
                      <span className="flex items-center gap-1.5">
                        {host.hostname}
                        <span className="rounded border border-line px-1 text-[9px] text-fg-dim uppercase">
                          {host.role}
                        </span>
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono whitespace-nowrap text-fg-muted">{host.ip}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-fg-muted">{host.os}</td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span className={cn('flex items-center gap-1.5', status.text)}>
                        <StatusDot tone={status.dot} pulse={host.status === 'online'} />
                        {status.label}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <Utilization value={host.cpu} />
                    </td>
                    <td className="px-3 py-2">
                      <Utilization value={host.memory} />
                    </td>
                    <td className={cn('px-3 py-2 whitespace-nowrap', network.text)}>{network.label}</td>
                    <td className="px-3 py-2 whitespace-nowrap text-fg-dim tabular">
                      {relativeTime(host.lastSeen, now)}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase',
                          riskStyles.badge,
                        )}
                        title={`Risk score ${host.riskScore} of 100 from ${host.eventCount} events`}
                      >
                        {SEVERITY_META[host.riskLevel].abbr}
                        <span className="tabular opacity-75">{host.riskScore}</span>
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/** Percentage with an inline meter — the number stays readable in grayscale. */
function Utilization({ value }: { value: number }) {
  return (
    <div className="flex min-w-16 items-center gap-1.5">
      <span className="w-7 shrink-0 text-fg-muted tabular">{value}%</span>
      <Meter value={value} tone={utilizationTone(value)} className="h-1 w-10" />
    </div>
  );
}
