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
  Shield,
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
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      ) : null}

      <nav
        aria-label="Primary"
        className={cn(
          'fixed inset-y-0 left-0 z-40 flex w-52 shrink-0 flex-col border-r border-line bg-surface',
          'transition-transform duration-150 lg:static lg:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-12 shrink-0 items-center gap-2 border-b border-line px-3">
          <Shield className="h-4 w-4 shrink-0 text-accent" />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[11px] leading-tight font-semibold tracking-wide text-fg">
              SOC COMMAND CENTER
            </div>
            <div className="truncate text-[9.5px] leading-tight text-fg-dim">Threat Detection Console</div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close navigation"
            className="rounded p-1 text-fg-dim hover:bg-surface-hover hover:text-fg lg:hidden"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col justify-between overflow-y-auto py-2">
          <ul className="space-y-0.5 px-2">
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

          <div className="px-2 pt-2">
            <div className="mb-1 border-t border-line pt-2">
              <ul className="space-y-0.5">
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
          'group relative flex w-full items-center gap-2.5 rounded px-2 py-1.5 text-left text-xs',
          'transition-colors duration-100',
          active
            ? 'bg-accent/12 font-medium text-fg'
            : 'text-fg-muted hover:bg-surface-hover hover:text-fg',
        )}
      >
        {/* Active rail: a second, non-color cue alongside the tint. */}
        <span
          className={cn(
            'absolute top-1 bottom-1 -left-2 w-0.5 rounded-r',
            active ? 'bg-accent' : 'bg-transparent',
          )}
          aria-hidden="true"
        />
        <Icon className={cn('h-3.5 w-3.5 shrink-0', active ? 'text-accent' : 'text-fg-dim')} />
        <span className="min-w-0 flex-1 truncate">{item.label}</span>
        {badgeCount > 0 ? (
          <span className="shrink-0 rounded bg-crit/15 px-1.5 py-0.5 text-[10px] font-semibold text-crit tabular">
            {badgeCount}
          </span>
        ) : null}
        {!item.implemented ? (
          <span
            className="shrink-0 text-[9px] text-fg-dim opacity-0 transition-opacity group-hover:opacity-100"
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
        title={`${link.label} — opens in a new tab`}
        className={cn(
          'group relative flex w-full items-center gap-2.5 rounded px-2 py-1.5 text-left text-xs',
          'text-fg-muted transition-colors duration-100 hover:bg-surface-hover hover:text-fg',
        )}
      >
        <Icon className="h-3.5 w-3.5 shrink-0 text-fg-dim" />
        <span className="min-w-0 flex-1 truncate">{link.label}</span>
        <ExternalLink className="h-3 w-3 shrink-0 text-fg-dim opacity-60" />
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
    <div className="rounded border border-line bg-canvas p-2">
      <div className="label-caps mb-1.5">System Status</div>
      <ul className="space-y-1">
        {rows.map((row) => (
          <li key={row.label} className="flex items-center gap-1.5" title={row.hint}>
            <StatusDot tone={row.ok ? 'bg-ok' : 'bg-crit'} pulse={row.ok} />
            <span className={cn('truncate text-[10.5px]', row.ok ? 'text-fg-muted' : 'text-crit')}>
              {row.label}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
