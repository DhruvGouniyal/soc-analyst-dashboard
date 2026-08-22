import { ExternalLink, X } from 'lucide-react';
import { useEffect, useMemo, type ReactNode } from 'react';
import { ALERT_ACTIONS, EVENT_TYPES, type AlertAction } from '@/config/eventTypes';
import { getTechnique } from '@/config/mitre';
import { SEVERITY_STYLES } from '@/config/theme';
import { cn } from '@/lib/cn';
import { clockTime, fullTimestamp, relativeTime } from '@/services/time';
import type { SecurityEvent } from '@/types/security';
import { Button } from '@/components/ui/Button';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { StatusBadge } from '@/components/ui/StatusBadge';

/** Events from the same source and type within this window are one campaign. */
const CORRELATION_WINDOW_MS = 60 * 60 * 1000;

interface AlertDetailPanelProps {
  event: SecurityEvent | null;
  /** Full event set, used to correlate the selected alert. */
  events: SecurityEvent[];
  onClose: () => void;
  onAction: (event: SecurityEvent, action: AlertAction) => void;
  now: number;
}

export function AlertDetailPanel({ event, events, onClose, onAction, now }: AlertDetailPanelProps) {
  // Escape closes the panel, matching the popover behavior elsewhere.
  useEffect(() => {
    if (!event) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [event, onClose]);

  /**
   * Correlates the selected alert with related activity so the panel can show
   * first/last seen and an occurrence count — a single detection rarely tells
   * the whole story.
   */
  const correlation = useMemo(() => {
    if (!event) return null;
    const related = events.filter(
      (candidate) =>
        candidate.sourceIp === event.sourceIp &&
        candidate.eventType === event.eventType &&
        Math.abs(candidate.timestamp - event.timestamp) <= CORRELATION_WINDOW_MS,
    );
    const timestamps = related.map((e) => e.timestamp);
    return {
      occurrences: related.length,
      firstSeen: Math.min(...timestamps, event.timestamp),
      lastSeen: Math.max(...timestamps, event.timestamp),
    };
  }, [event, events]);

  if (!event) return null;

  const meta = EVENT_TYPES[event.eventType];
  const technique = getTechnique(event.mitreTechnique);
  const styles = SEVERITY_STYLES[event.severity];

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/50 lg:hidden"
        onClick={onClose}
        aria-hidden="true"
      />

      <aside
        role="dialog"
        aria-modal="false"
        aria-label="Alert details"
        className={cn(
          'fixed inset-y-0 right-0 z-50 flex w-full max-w-96 flex-col border-l border-line bg-surface shadow-2xl',
          'lg:static lg:z-auto lg:w-88 lg:max-w-none lg:shadow-none',
        )}
      >
        <header className="flex h-10 shrink-0 items-center justify-between gap-2 border-b border-line px-3">
          <h2 className="label-caps">Alert Details</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close alert details"
            className="rounded p-1 text-fg-dim hover:bg-surface-hover hover:text-fg"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto">
          <div className={cn('border-b border-line px-3 py-3', styles.tint)}>
            <h3 className="mb-2 text-sm leading-tight font-semibold text-fg">{meta.label}</h3>
            <div className="flex flex-wrap items-center gap-1.5">
              <SeverityBadge severity={event.severity} />
              <StatusBadge status={event.status} />
              <span className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10px] text-fg-dim">
                {event.confidence}% confidence
              </span>
            </div>
          </div>

          <Section title="Connection">
            <Field label="Source" value={event.sourceIp} mono />
            <Field
              label="Destination"
              value={`${event.destinationIp}${event.destinationPort ? `:${event.destinationPort}` : ''}`}
              mono
            />
            <Field label="Protocol" value={event.protocol} />
            <Field label="Host" value={event.host} mono />
          </Section>

          <Section title="Timing">
            <Field label="Detected" value={fullTimestamp(event.timestamp)} mono />
            <Field label="Age" value={relativeTime(event.timestamp, now)} />
            {correlation && correlation.occurrences > 1 ? (
              <>
                <Field label="First Seen" value={clockTime(correlation.firstSeen)} mono />
                <Field label="Last Seen" value={clockTime(correlation.lastSeen)} mono />
                <Field
                  label="Occurrences"
                  value={`${correlation.occurrences} from this source`}
                />
              </>
            ) : null}
          </Section>

          {technique ? (
            <Section title="MITRE ATT&CK">
              <a
                href={technique.url}
                target="_blank"
                rel="noreferrer noopener"
                className="mb-1.5 flex items-center gap-1.5 text-[12px] font-medium text-accent hover:underline"
              >
                {technique.id} — {technique.name}
                <ExternalLink className="h-3 w-3" />
              </a>
              <p className="mb-1 text-[10.5px] text-fg-dim">Tactic: {technique.tactic}</p>
              <p className="text-[11px] leading-relaxed text-fg-muted">{technique.summary}</p>
            </Section>
          ) : null}

          <Section title="Description">
            <p className="mb-2 text-[11.5px] leading-relaxed text-fg">{event.description}</p>
            {event.detail ? (
              <p className="text-[11px] leading-relaxed text-fg-muted">{event.detail}</p>
            ) : null}
          </Section>

          <Section title="Analyst Guidance">
            <p className="text-[11px] leading-relaxed text-fg-muted">{meta.guidance}</p>
          </Section>

          {event.rawLog ? (
            <Section title={`Raw Log · ${event.logSource}`}>
              <pre className="overflow-x-auto rounded border border-line bg-canvas p-2 font-mono text-[10px] leading-relaxed break-all whitespace-pre-wrap text-fg-muted">
                {event.rawLog}
              </pre>
            </Section>
          ) : null}
        </div>

        <footer className="shrink-0 border-t border-line p-3">
          <div className="label-caps mb-2">Recommended Actions</div>
          <div className="flex flex-wrap gap-1.5">
            {meta.actions.map((action) => {
              const actionMeta = ALERT_ACTIONS[action];
              const alreadyApplied = event.status === actionMeta.transitionsTo;
              return (
                <Button
                  key={action}
                  size="md"
                  variant={actionMeta.emphasis ? 'danger' : 'default'}
                  disabled={alreadyApplied}
                  onClick={() => onAction(event, action)}
                  title={
                    alreadyApplied
                      ? `Already ${actionMeta.transitionsTo}`
                      : `Move alert to "${actionMeta.transitionsTo}"`
                  }
                >
                  {actionMeta.label}
                </Button>
              );
            })}
          </div>
          <p className="mt-2 text-[10px] leading-relaxed text-fg-dim">
            Actions update dashboard state only. Enforcement is wired once the detection engine
            backend is connected.
          </p>
        </footer>
      </aside>
    </>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-b border-line px-3 py-2.5 last:border-b-0">
      <div className="label-caps mb-1.5">{title}</div>
      {children}
    </section>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-0.5">
      <span className="shrink-0 text-[10.5px] text-fg-dim">{label}</span>
      <span className={cn('truncate text-[11px] text-fg', mono && 'font-mono')} title={value}>
        {value}
      </span>
    </div>
  );
}
