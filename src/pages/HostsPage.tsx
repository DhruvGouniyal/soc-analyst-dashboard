import { useMemo, useState } from 'react';
import { useClock } from '@/hooks/useClock';
import { computeHostRisk } from '@/services/metrics';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { HostTable } from '@/components/dashboard/HostTable';

/** Endpoint inventory view — the dashboard's host table given full width. */
export function HostsPage() {
  const { hosts, events, loading } = useSecurityFeed();
  const now = useClock(2000);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);

  const hostsWithRisk = useMemo(
    () => computeHostRisk(hosts, events, now),
    [hosts, events, now],
  );

  return (
    <div className="h-full overflow-y-auto p-3">
      <HostTable
        hosts={hostsWithRisk}
        loading={loading}
        now={now}
        onSelectHost={(id) => setSelectedHost((current) => (current === id ? null : id))}
        activeHostId={selectedHost}
      />
    </div>
  );
}
