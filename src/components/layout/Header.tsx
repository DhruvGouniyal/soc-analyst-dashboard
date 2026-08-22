import { Bell, Menu, Pause, Play, User } from 'lucide-react';
import { getNavItem, type ViewKey } from '@/config/navigation';
import { HOST_IDS } from '@/data/topology';
import { useClock } from '@/hooks/useClock';
import { cn } from '@/lib/cn';
import { fullTimestamp } from '@/services/time';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Button, ToggleGroup } from '@/components/ui/Button';
import { StatusDot } from '@/components/ui/StatusBadge';
import type { DataSourceMode } from '@/types/security';

interface HeaderProps {
  view: ViewKey;
  onOpenNav: () => void;
  /** Count of unacknowledged high/critical alerts. */
  notificationCount: number;
}

export function Header({ view, onOpenNav, notificationCount }: HeaderProps) {
  const nav = getNavItem(view);
  const { status, hosts, mode, setMode, paused, setPaused, bufferedCount } = useSecurityFeed();
  const now = useClock(1000);

  const victim = hosts.find((host) => host.id === HOST_IDS.victim);
  const engineLive = status === 'live';

  return (
    <header className="flex h-12 shrink-0 items-center justify-between gap-3 border-b border-line bg-surface px-3">
      <div className="flex min-w-0 items-center gap-2">
        <button
          type="button"
          onClick={onOpenNav}
          aria-label="Open navigation"
          className="rounded p-1.5 text-fg-muted hover:bg-surface-hover hover:text-fg lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>
        <div className="min-w-0">
          <h1 className="truncate text-[13px] leading-tight font-semibold text-fg">{nav.title}</h1>
          <p className="truncate text-[10.5px] leading-tight text-fg-dim">{nav.subtitle}</p>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {/* Pipeline health, mirrored from the sidebar for at-a-glance reading. */}
        <div className="hidden items-center gap-3 rounded border border-line bg-canvas px-2.5 py-1 xl:flex">
          <StatusPill
            label={engineLive ? 'LIVE' : status === 'connecting' ? 'CONNECTING' : 'OFFLINE'}
            ok={engineLive}
            pulse={engineLive}
            emphasis
          />
          <Divider />
          <StatusPill
            label="Ubuntu Victim"
            value={victim?.status === 'online' ? 'ONLINE' : 'OFFLINE'}
            ok={victim?.status === 'online'}
          />
          <Divider />
          <StatusPill label="Detection Engine" value={engineLive ? 'ACTIVE' : 'IDLE'} ok={engineLive} />
        </div>

        <ToggleGroup<DataSourceMode>
          label="Data source"
          value={mode}
          onChange={setMode}
          options={[
            { value: 'live', label: 'LIVE DATA' },
            { value: 'demo', label: 'DEMO MODE' },
          ]}
        />

        <Button
          variant={paused ? 'primary' : 'ghost'}
          onClick={() => setPaused(!paused)}
          aria-label={paused ? 'Resume live feed' : 'Pause live feed'}
          title={paused ? `Resume feed${bufferedCount > 0 ? ` (${bufferedCount} buffered)` : ''}` : 'Pause feed'}
        >
          {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
          <span className="hidden sm:inline">{paused ? 'Resume' : 'Pause'}</span>
          {paused && bufferedCount > 0 ? (
            <span className="rounded bg-accent/25 px-1 text-[10px] tabular">{bufferedCount}</span>
          ) : null}
        </Button>

        <time
          dateTime={new Date(now).toISOString()}
          className="hidden text-[11px] text-fg-muted tabular md:block"
        >
          {fullTimestamp(now)}
        </time>

        <button
          type="button"
          aria-label={`Notifications: ${notificationCount} unacknowledged`}
          title={`${notificationCount} unacknowledged high or critical alerts`}
          className="relative rounded p-1.5 text-fg-muted hover:bg-surface-hover hover:text-fg"
        >
          <Bell className="h-4 w-4" />
          {notificationCount > 0 ? (
            <span className="absolute -top-0.5 -right-0.5 flex h-3.5 min-w-3.5 items-center justify-center rounded-full bg-crit px-1 text-[9px] font-semibold text-white tabular">
              {notificationCount > 99 ? '99+' : notificationCount}
            </span>
          ) : null}
        </button>

        <div className="flex items-center gap-1.5 border-l border-line pl-2">
          <div className="flex h-6 w-6 items-center justify-center rounded-full border border-line-strong bg-surface-raised">
            <User className="h-3 w-3 text-fg-muted" />
          </div>
          <div className="hidden leading-tight sm:block">
            <div className="text-[11px] font-medium text-fg">analyst</div>
            <div className="text-[9.5px] text-fg-dim">Tier 1</div>
          </div>
        </div>
      </div>
    </header>
  );
}

function Divider() {
  return <span className="h-3 w-px bg-line" aria-hidden="true" />;
}

function StatusPill({
  label,
  value,
  ok,
  pulse,
  emphasis,
}: {
  label: string;
  value?: string;
  ok: boolean;
  pulse?: boolean;
  emphasis?: boolean;
}) {
  return (
    <span className="flex items-center gap-1.5 whitespace-nowrap">
      <StatusDot tone={ok ? 'bg-ok' : 'bg-crit'} pulse={pulse} />
      <span className={cn('text-[10px]', emphasis ? 'font-semibold tracking-wide' : 'text-fg-dim')}>
        {emphasis ? (
          <span className={ok ? 'text-ok' : 'text-crit'}>{label}</span>
        ) : (
          <>
            {label}:{' '}
            <span className={cn('font-semibold', ok ? 'text-fg-muted' : 'text-crit')}>{value}</span>
          </>
        )}
      </span>
    </span>
  );
}
