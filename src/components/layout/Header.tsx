import { Bell, ChevronDown, Menu, Pause, Play, User } from 'lucide-react';
import { getNavItem, type ViewKey } from '@/config/navigation';
import { HOST_IDS } from '@/data/topology';
import { useClock } from '@/hooks/useClock';
import { cn } from '@/lib/cn';
import { fullTimestamp } from '@/services/time';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Button, ToggleGroup } from '@/components/ui/Button';
import BlurText from '@/components/reactbits/BlurText';
import ShinyText from '@/components/reactbits/ShinyText';
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
    <header className="liquid-flat liquid-flat-b flex h-16 shrink-0 items-center justify-between gap-4 px-5">
      <div className="flex min-w-0 items-center gap-2.5">
        <button
          type="button"
          onClick={onOpenNav}
          aria-label="Open navigation"
          className="rounded-[var(--radius-control)] p-2 text-fg-muted hover:bg-[var(--fill-1)] hover:text-fg lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>
        <div className="min-w-0">
          {/* Re-keyed on view so the title re-reveals on every navigation. */}
          <BlurText
            key={nav.title}
            text={nav.title}
            animateBy="words"
            direction="top"
            delay={38}
            stepDuration={0.3}
            className="truncate text-[16px] leading-tight font-semibold tracking-tight text-fg"
          />
          <p className="truncate text-[11.5px] leading-tight text-fg-dim">{nav.subtitle}</p>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2.5">
        {/* Pipeline health, mirrored from the sidebar for at-a-glance reading. */}
        <div className="liquid-control hidden items-center gap-3 px-3 py-1.5 xl:flex">
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
          variant={paused ? 'primary' : 'default'}
          onClick={() => setPaused(!paused)}
          aria-label={paused ? 'Resume live feed' : 'Pause live feed'}
          title={paused ? `Resume feed${bufferedCount > 0 ? ` (${bufferedCount} buffered)` : ''}` : 'Pause feed'}
        >
          {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          <span className="hidden sm:inline">{paused ? 'Resume' : 'Pause'}</span>
          {paused && bufferedCount > 0 ? (
            <span className="rounded-full bg-accent/25 px-1.5 text-[10px] tabular">{bufferedCount}</span>
          ) : null}
        </Button>

        <time
          dateTime={new Date(now).toISOString()}
          className="hidden text-[11.5px] text-fg-muted tabular md:block"
        >
          {fullTimestamp(now)}
        </time>

        <button
          type="button"
          aria-label={`Notifications: ${notificationCount} unacknowledged`}
          title={`${notificationCount} unacknowledged high or critical alerts`}
          className="liquid-control relative flex h-9 w-9 items-center justify-center text-fg-muted ios-transition-fast ios-press hover:brightness-125 hover:text-fg"
        >
          <Bell className="h-4 w-4" />
          {notificationCount > 0 ? (
            <span className="absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-crit px-1 text-[9.5px] font-semibold text-white tabular">
              {notificationCount > 99 ? '99+' : notificationCount}
            </span>
          ) : null}
        </button>

        <div className="liquid-control flex items-center gap-2 py-1 pr-2.5 pl-1">
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-accent/15 ring-1 ring-accent/30">
            <User className="h-3.5 w-3.5 text-accent" />
          </span>
          <div className="hidden leading-tight sm:block">
            <div className="text-[11.5px] font-medium text-fg">analyst</div>
            <div className="text-[9.5px] text-fg-dim">Tier 1</div>
          </div>
          <ChevronDown className="hidden h-3.5 w-3.5 text-fg-dim sm:block" aria-hidden="true" />
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
      <span className={cn('text-[10.5px]', emphasis ? 'font-semibold tracking-wide' : 'text-fg-muted')}>
        {emphasis ? (
          ok ? (
            // Only the live indicator shimmers: motion here means "streaming".
            <ShinyText
              text={label}
              speed={3.4}
              className="font-semibold tracking-wide"
              color="#ffffff"
              shineColor="rgba(255,255,255,0.35)"
            />
          ) : (
            <span className="text-crit">{label}</span>
          )
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
