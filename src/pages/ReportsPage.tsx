import { Download, FileText } from 'lucide-react';
import { useMemo } from 'react';
import { useClock } from '@/hooks/useClock';
import { cn } from '@/lib/cn';
import { deriveIncidents } from '@/services/derived';
import { computeKpis } from '@/services/metrics';
import { computeSecurityScore } from '@/services/riskEngine';
import { formatCount, fullTimestamp, relativeTime } from '@/services/time';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Panel } from '@/components/ui/Panel';
import { Button } from '@/components/ui/Button';
import { Skeleton } from '@/components/ui/States';

type Cadence = 'Daily' | 'Weekly' | 'On demand';
type ReportStatus = 'ready' | 'scheduled';

interface ReportEntry {
  id: string;
  title: string;
  description: string;
  cadence: Cadence;
  format: string;
  status: ReportStatus;
  /** Minutes since generation; undefined for scheduled-but-not-yet-run. */
  generatedAgoMin?: number;
  sizeKb?: number;
}

const REPORTS: ReportEntry[] = [
  {
    id: 'daily-summary',
    title: 'Daily SOC Summary',
    description: 'Detections, triage progress, and posture over the last 24 hours.',
    cadence: 'Daily',
    format: 'PDF',
    status: 'ready',
    generatedAgoMin: 47,
    sizeKb: 312,
  },
  {
    id: 'exec-brief',
    title: 'Executive Threat Brief',
    description: 'Leadership-level summary of active campaigns and risk trend.',
    cadence: 'Weekly',
    format: 'PDF',
    status: 'ready',
    generatedAgoMin: 60 * 20,
    sizeKb: 188,
  },
  {
    id: 'incident-report',
    title: 'Incident Report',
    description: 'Full evidence-backed write-up for the highest-severity incident.',
    cadence: 'On demand',
    format: 'PDF',
    status: 'ready',
    generatedAgoMin: 60 * 3,
    sizeKb: 574,
  },
  {
    id: 'event-export',
    title: 'Raw Event Export',
    description: 'Every retained security event as a flat file for external tooling.',
    cadence: 'On demand',
    format: 'CSV',
    status: 'ready',
    generatedAgoMin: 60 * 6,
    sizeKb: 2480,
  },
  {
    id: 'mitre-coverage',
    title: 'MITRE Coverage Report',
    description: 'Observed ATT&CK techniques mapped to tactics with evidence counts.',
    cadence: 'Weekly',
    format: 'PDF',
    status: 'scheduled',
  },
];

const CADENCE_CLASS: Record<Cadence, string> = {
  Daily: 'text-ok border-ok/40 bg-ok/10',
  Weekly: 'text-low border-low/40 bg-low/10',
  'On demand': 'text-fg-muted border-line-strong bg-surface-raised',
};

export function ReportsPage() {
  const { events, loading } = useSecurityFeed();
  const now = useClock(5000);

  const summary = useMemo(() => {
    const kpis = computeKpis(events, now);
    const score = computeSecurityScore(events, now);
    const incidents = deriveIncidents(events, now);
    return { kpis, score, activeIncidents: incidents.filter((i) => i.status === 'active').length };
  }, [events, now]);

  return (
    <div className="h-full overflow-y-auto p-3">
      <Panel title="Current Posture" meta="Snapshot for the next report" className="mb-2">
        {loading ? (
          <Skeleton className="h-16 w-full" />
        ) : (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label="Security Score" value={`${summary.score.score}/100`} sub={summary.score.label} />
            <Metric label="Critical / High" value={`${summary.kpis.criticalCount} / ${summary.kpis.highCount}`} sub="open in queue" />
            <Metric label="Events (24h)" value={formatCount(summary.kpis.totalEvents)} sub="observed" />
            <Metric label="Active Incidents" value={String(summary.activeIncidents)} sub="need attention" />
          </div>
        )}
      </Panel>

      <Panel title="Reports" meta="Scheduled & on-demand" flush>
        <ul className="divide-y divide-line/60">
          {REPORTS.map((report) => (
            <ReportRow key={report.id} report={report} now={now} />
          ))}
        </ul>
      </Panel>

      <p className="px-1 pt-2 text-[10px] text-fg-dim">
        Report generation and export are illustrative — the underlying data is live, but delivery wiring is
        backend work for a later phase.
      </p>
    </div>
  );
}

function Metric({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div>
      <div className="label-caps mb-1">{label}</div>
      <div className="text-xl leading-none font-semibold text-fg tabular">{value}</div>
      <div className="mt-1 text-[10px] text-fg-dim">{sub}</div>
    </div>
  );
}

function ReportRow({ report, now: _now }: { report: ReportEntry; now: number }) {
  const ready = report.status === 'ready';
  return (
    <li className="flex items-center gap-3 px-3 py-3 hover:bg-surface-hover">
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded border border-line bg-surface-raised">
        <FileText className="h-4 w-4 text-fg-muted" />
      </span>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-[12.5px] font-medium text-fg">{report.title}</span>
          <span className={cn('shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium', CADENCE_CLASS[report.cadence])}>
            {report.cadence}
          </span>
          <span className="shrink-0 rounded border border-line px-1 text-[9px] text-fg-dim uppercase">
            {report.format}
          </span>
        </div>
        <div className="mt-0.5 truncate text-[10.5px] text-fg-dim">{report.description}</div>
      </div>

      <div className="hidden shrink-0 text-right text-[10.5px] text-fg-dim sm:block">
        {ready && report.generatedAgoMin !== undefined ? (
          <>
            <div title={fullTimestamp(Date.now() - report.generatedAgoMin * 60_000)}>
              generated {relativeTime(Date.now() - report.generatedAgoMin * 60_000, Date.now())}
            </div>
            {report.sizeKb ? <div className="tabular">{formatReportSize(report.sizeKb)}</div> : null}
          </>
        ) : (
          <div className="text-med">scheduled</div>
        )}
      </div>

      <Button
        variant={ready ? 'default' : 'ghost'}
        disabled={!ready}
        title={ready ? 'Illustrative download' : 'Not yet generated'}
      >
        {ready ? <Download className="h-3 w-3" /> : null}
        {ready ? 'Download' : 'Pending'}
      </Button>
    </li>
  );
}

function formatReportSize(kb: number): string {
  return kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb} KB`;
}
