import { Check, ListFilter, Search, X } from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { EVENT_TYPES, EVENT_TYPE_KEYS } from '@/config/eventTypes';
import { SEVERITY_META, SEVERITY_ORDER } from '@/config/severity';
import { SEVERITY_STYLES, EVENT_STATUS_META } from '@/config/theme';
import { cn } from '@/lib/cn';
import type { UseEventFiltersResult } from '@/hooks/useEventFilters';
import type { EventStatus, Host, Severity } from '@/types/security';

const STATUS_KEYS = Object.keys(EVENT_STATUS_META) as EventStatus[];

interface EventFilterBarProps {
  filters: UseEventFiltersResult;
  /** Per-severity counts of the unfiltered set, shown on the chips. */
  counts: Record<Severity, number>;
  hosts: Host[];
}

export function EventFilterBar({ filters, counts, hosts }: EventFilterBarProps) {
  const {
    filters: state,
    setQuery,
    toggleSeverity,
    setSeverities,
    toggleEventType,
    toggleHost,
    toggleStatus,
    clear,
    active,
  } = filters;

  const advancedCount =
    state.eventTypes.length + state.hosts.length + state.statuses.length;

  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b border-[var(--separator)] px-3 py-2">
      <label className="relative min-w-40 flex-1">
        <Search className="pointer-events-none absolute top-1/2 left-2 h-3 w-3 -translate-y-1/2 text-fg-dim" />
        <input
          type="search"
          value={state.query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search IP, event type, MITRE ID…"
          aria-label="Search security events"
          className={cn(
            'h-6 w-full rounded-[var(--radius-control)] border border-[var(--separator)] bg-[var(--fill-1)] pr-2 pl-7 text-[11px] text-fg',
            'placeholder:text-fg-dim focus:border-accent/60 focus:outline-none',
          )}
        />
      </label>

      <div className="flex items-center gap-1">
        <FilterChip
          label="All"
          count={SEVERITY_ORDER.reduce((sum, s) => sum + counts[s], 0)}
          active={state.severities.length === 0}
          onClick={() => setSeverities([])}
        />
        {SEVERITY_ORDER.map((severity) => (
          <FilterChip
            key={severity}
            label={SEVERITY_META[severity].label}
            count={counts[severity]}
            active={state.severities.includes(severity)}
            tone={SEVERITY_STYLES[severity].badge}
            onClick={() => toggleSeverity(severity)}
          />
        ))}
      </div>

      <AdvancedFilters
        activeCount={advancedCount}
        state={state}
        hosts={hosts}
        onToggleEventType={toggleEventType}
        onToggleHost={toggleHost}
        onToggleStatus={toggleStatus}
      />

      {active ? (
        <button
          type="button"
          onClick={clear}
          className="flex items-center gap-1 rounded-[var(--radius-control)] px-1.5 py-1 text-[10.5px] text-fg-dim hover:bg-[var(--fill-1)] hover:text-fg"
        >
          <X className="h-3 w-3" />
          Clear
        </button>
      ) : null}
    </div>
  );
}

function FilterChip({
  label,
  count,
  active,
  tone,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  tone?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] font-medium whitespace-nowrap',
        'transition-colors duration-100',
        active
          ? (tone ?? 'border-accent/50 bg-accent/15 text-accent')
          : 'border-[var(--separator)] bg-[var(--fill-1)] text-fg-dim hover:border-[var(--separator)] hover:text-fg-muted',
      )}
    >
      {label}
      <span className="tabular opacity-70">{count}</span>
    </button>
  );
}

interface AdvancedFiltersProps {
  activeCount: number;
  state: UseEventFiltersResult['filters'];
  hosts: Host[];
  onToggleEventType: (value: (typeof EVENT_TYPE_KEYS)[number]) => void;
  onToggleHost: (value: string) => void;
  onToggleStatus: (value: EventStatus) => void;
}

/** Popover holding the lower-frequency filters, to keep the bar compact. */
function AdvancedFilters({
  activeCount,
  state,
  hosts,
  onToggleEventType,
  onToggleHost,
  onToggleStatus,
}: AdvancedFiltersProps) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: MouseEvent) {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className={cn(
          'flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10.5px] font-medium',
          activeCount > 0
            ? 'border-accent/50 bg-accent/15 text-accent'
            : 'border-[var(--separator)] bg-[var(--fill-1)] text-fg-dim hover:border-[var(--separator)] hover:text-fg-muted',
        )}
      >
        <ListFilter className="h-3 w-3" />
        Filters
        {activeCount > 0 ? <span className="tabular">{activeCount}</span> : null}
      </button>

      {open ? (
        <div className="absolute right-0 z-20 mt-1 max-h-80 w-56 overflow-y-auto rounded-[var(--radius-control)] border border-[var(--separator)] bg-[#2c2c2e] p-2 shadow-xl">
          <FilterSection title="Status">
            {STATUS_KEYS.map((status) => (
              <CheckRow
                key={status}
                label={EVENT_STATUS_META[status].label}
                checked={state.statuses.includes(status)}
                onClick={() => onToggleStatus(status)}
              />
            ))}
          </FilterSection>

          <FilterSection title="Host">
            {hosts.map((host) => (
              <CheckRow
                key={host.id}
                label={host.hostname}
                checked={state.hosts.includes(host.id)}
                onClick={() => onToggleHost(host.id)}
              />
            ))}
          </FilterSection>

          <FilterSection title="Event Type">
            {EVENT_TYPE_KEYS.map((type) => (
              <CheckRow
                key={type}
                label={EVENT_TYPES[type].shortLabel}
                checked={state.eventTypes.includes(type)}
                onClick={() => onToggleEventType(type)}
              />
            ))}
          </FilterSection>
        </div>
      ) : null}
    </div>
  );
}

function FilterSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mb-2 last:mb-0">
      <div className="label-caps mb-1 px-1">{title}</div>
      <div className="space-y-px">{children}</div>
    </div>
  );
}

function CheckRow({
  label,
  checked,
  onClick,
}: {
  label: string;
  checked: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      role="checkbox"
      aria-checked={checked}
      className="flex w-full items-center gap-2 rounded-[var(--radius-control)] px-1 py-1 text-left text-[11px] text-fg-muted hover:bg-[var(--fill-1)] hover:text-fg"
    >
      <span
        className={cn(
          'flex h-3 w-3 shrink-0 items-center justify-center rounded-[3px] border',
          checked ? 'border-accent bg-accent/25 text-accent' : 'border-[var(--separator)]',
        )}
      >
        {checked ? <Check className="h-2.5 w-2.5" /> : null}
      </span>
      <span className="truncate">{label}</span>
    </button>
  );
}
