import {
  Bell,
  BrainCircuit,
  Crosshair,
  ExternalLink,
  FileText,
  Flame,
  LayoutGrid,
  Network,
  ScrollText,
  Server,
  Settings,
  X,
} from 'lucide-react';
import type { ComponentType } from 'react';
import {
  EXTERNAL_LINKS,
  NAV_PRIMARY,
  NAV_SECONDARY,
  type ExternalNavLink,
  type NavItem,
  type ViewKey,
} from '@/config/navigation';
import { HOST_IDS } from '@/data/topology';
import { cn } from '@/lib/cn';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { StatusDot } from '@/components/ui/StatusBadge';
import { SentinelMark } from '@/components/layout/LiquidGlassDefs';

const ICONS: Record<string, ComponentType<{ className?: string }>> = {
  LayoutGrid,
  Bell,
  Flame,
  Network,
  Server,
  Crosshair,
  ScrollText,
  FileText,
  Settings,
  BrainCircuit,
};

interface SidebarProps {
  active: ViewKey;
  onNavigate: (view: ViewKey) => void;
  /** Controls the mobile overlay; ignored at desktop widths. */
  open: boolean;
  onClose: () => void;
  /** Open critical alerts, rendered as the Alerts nav badge. */
  criticalCount: number;
}

export function Sidebar({ active, onNavigate, open, onClose, criticalCount }: SidebarProps) {
  return (
    <>
      {/* Scrim only exists on narrow screens, where the sidebar is an overlay. */}
      {open ? (
        <div
          className="fixed inset-0 z-30 bg-black/70 lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      ) : null}

      <nav
        aria-label="Primary"
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex w-60 shrink-0 flex-col',
          'liquid-flat liquid-flat-r',
          'transition-transform duration-[var(--dur)] ease-[cubic-bezier(0.32,0.72,0,1)] lg:static lg:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-16 shrink-0 items-center gap-2.5 px-4">
          <span className="liquid-control flex h-9 w-9 shrink-0 items-center justify-center !rounded-[11px]">
            <SentinelMark className="h-5 w-5 text-white" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px] leading-tight font-semibold text-fg">
              Sentinel SOC
            </div>
            <div className="truncate text-[10.5px] leading-tight text-fg-dim">
              Threat Detection Console
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close navigation"
            className="rounded-[var(--radius-control)] p-1.5 text-fg-dim hover:bg-[var(--fill-1)] hover:text-fg lg:hidden"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col justify-between overflow-y-auto pb-3">
          <div className="px-3">
            <div className="label-caps px-2 pt-1 pb-2">Menu</div>
            <ul className="space-y-1">
              {NAV_PRIMARY.map((item) => (
                <NavRow
                  key={item.key}
                  item={item}
                  active={item.key === active}
                  onNavigate={onNavigate}
                  badgeCount={item.badge === 'critical' ? criticalCount : 0}
                />
              ))}
            </ul>
          </div>

          <div className="px-3 pt-4">
            <div className="mb-3 border-t border-[var(--separator)] pt-3">
              <ul className="space-y-1">
                {NAV_SECONDARY.map((item) => (
                  <NavRow
                    key={item.key}
                    item={item}
                    active={item.key === active}
                    onNavigate={onNavigate}
                    badgeCount={0}
                  />
                ))}
                {EXTERNAL_LINKS.map((link) => (
                  <ExternalRow key={link.href} link={link} />
                ))}
              </ul>
            </div>
            <SystemStatus />
          </div>
        </div>
      </nav>
    </>
  );
}

function NavRow({
  item,
  active,
  onNavigate,
  badgeCount,
}: {
  item: NavItem;
  active: boolean;
  onNavigate: (view: ViewKey) => void;
  badgeCount: number;
}) {
  const Icon = ICONS[item.icon] ?? LayoutGrid;

  return (
    <li>
      <button
        type="button"
        onClick={() => onNavigate(item.key)}
        aria-current={active ? 'page' : undefined}
        className={cn(
          'group flex w-full items-center gap-3 rounded-[var(--radius-control)] px-2.5 py-2 text-left text-[12.5px]',
          'ios-transition-fast ios-press',
          active
            ? 'bg-[var(--fill-2)] font-semibold text-fg ring-1 ring-[var(--separator)]'
            : 'font-medium text-fg-muted hover:bg-[var(--fill-1)] hover:text-fg',
        )}
      >
        <Icon className={cn('h-4 w-4 shrink-0', active ? 'text-accent' : 'text-fg-dim')} />
        <span className="min-w-0 flex-1 truncate">{item.label}</span>
        {badgeCount > 0 ? (
          <span className="shrink-0 rounded-full bg-crit/15 px-1.5 py-0.5 text-[10px] font-semibold text-crit tabular">
            {badgeCount}
          </span>
        ) : null}
        {!item.implemented ? (
          <span
            className="shrink-0 text-[9.5px] text-fg-dim opacity-0 transition-opacity group-hover:opacity-100"
            title="Not implemented in this phase"
          >
            soon
          </span>
        ) : null}
      </button>
    </li>
  );
}

/**
 * A link to a companion app. Rendered as an anchor (not a view button) so it
 * gets real open-in-new-tab semantics, with a trailing glyph marking it as
 * leaving the dashboard.
 */
function ExternalRow({ link }: { link: ExternalNavLink }) {
  const Icon = ICONS[link.icon] ?? ExternalLink;

  return (
    <li>
      <a
        href={link.href}
        target="_blank"
        rel="noreferrer noopener"
        title={`${link.label} - opens in a new tab`}
        className={cn(
          'group flex w-full items-center gap-3 rounded-[var(--radius-control)] px-2.5 py-2 text-left text-[12.5px]',
          'ios-transition-fast ios-press font-medium text-fg-muted hover:bg-[var(--fill-1)] hover:text-fg',
        )}
      >
        <Icon className="h-4 w-4 shrink-0 text-fg-dim" />
        <span className="min-w-0 flex-1 truncate">{link.label}</span>
        <ExternalLink className="h-3.5 w-3.5 shrink-0 text-fg-dim opacity-60" />
      </a>
    </li>
  );
}

/**
 * Pipeline health. Every line reflects real state — the victim indicator reads
 * the actual host record, so it degrades if telemetry stops.
 */
function SystemStatus() {
  const { status, hosts, backendConfigured, providerLabel } = useSecurityFeed();

  const victim = hosts.find((host) => host.id === HOST_IDS.victim);
  const online = status === 'live';

  const rows = [
    {
      label: backendConfigured ? 'Backend Connected' : 'Mock Data Source',
      ok: online,
      hint: backendConfigured ? providerLabel : 'No VITE_SOC_API_URL configured',
    },
    {
      label: 'Ubuntu Victim Online',
      ok: victim?.status === 'online',
      hint: victim ? `${victim.ip} · ${victim.os}` : 'Host not reporting',
    },
    { label: 'Detection Engine Active', ok: online, hint: providerLabel },
  ];

  return (
    <div className="liquid rounded-[var(--radius-control)] p-3">
      <div className="label-caps mb-2">System Status</div>
      <ul className="space-y-1.5">
        {rows.map((row) => (
          <li key={row.label} className="flex items-center gap-2" title={row.hint}>
            <StatusDot tone={row.ok ? 'bg-ok' : 'bg-crit'} pulse={row.ok} />
            <span className={cn('truncate text-[11px]', row.ok ? 'text-fg-muted' : 'text-crit')}>
              {row.label}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
