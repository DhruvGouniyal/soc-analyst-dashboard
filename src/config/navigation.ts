/**
 * Sidebar structure. `implemented: false` sections render a consistent
 * "not built yet" placeholder rather than a broken page — honest about scope
 * for this phase without dead links.
 */
export type ViewKey =
  | 'dashboard'
  | 'alerts'
  | 'incidents'
  | 'network'
  | 'hosts'
  | 'threat-intel'
  | 'logs'
  | 'reports'
  | 'settings';

export interface NavItem {
  key: ViewKey;
  label: string;
  /** lucide-react icon name, resolved in the Sidebar component. */
  icon: string;
  title: string;
  subtitle: string;
  implemented: boolean;
  /**
   * Shows a live count badge sourced from current events. Only the triage
   * queue gets one — badging a section with a number that does not describe it
   * (open alerts on "Incidents", say) reads as precision the app does not have.
   */
  badge?: 'critical';
}

export const NAV_PRIMARY: NavItem[] = [
  {
    key: 'dashboard',
    label: 'Dashboard',
    icon: 'LayoutGrid',
    title: 'SOC Command Center',
    subtitle: 'Security monitoring & threat detection',
    implemented: true,
  },
  {
    key: 'alerts',
    label: 'Alerts',
    icon: 'Bell',
    title: 'Alerts',
    subtitle: 'Triage queue across all detections',
    implemented: true,
    badge: 'critical',
  },
  {
    key: 'incidents',
    label: 'Incidents',
    icon: 'Flame',
    title: 'Incidents',
    subtitle: 'Correlated multi-stage attack chains',
    implemented: false,
  },
  {
    key: 'network',
    label: 'Network',
    icon: 'Network',
    title: 'Network',
    subtitle: 'Flow analysis & connection monitoring',
    implemented: false,
  },
  {
    key: 'hosts',
    label: 'Hosts',
    icon: 'Server',
    title: 'Hosts',
    subtitle: 'Managed endpoint inventory & telemetry',
    implemented: true,
  },
  {
    key: 'threat-intel',
    label: 'Threat Intelligence',
    icon: 'Crosshair',
    title: 'Threat Intelligence',
    subtitle: 'Indicators, reputation & MITRE coverage',
    implemented: false,
  },
  {
    key: 'logs',
    label: 'Logs',
    icon: 'ScrollText',
    title: 'Logs',
    subtitle: 'Raw collector output & search',
    implemented: false,
  },
  {
    key: 'reports',
    label: 'Reports',
    icon: 'FileText',
    title: 'Reports',
    subtitle: 'Scheduled exports & executive summaries',
    implemented: false,
  },
];

export const NAV_SECONDARY: NavItem[] = [
  {
    key: 'settings',
    label: 'Settings',
    icon: 'Settings',
    title: 'Settings',
    subtitle: 'Data sources, detection tuning & preferences',
    implemented: false,
  },
];

export const ALL_NAV_ITEMS = [...NAV_PRIMARY, ...NAV_SECONDARY];

export function getNavItem(key: ViewKey): NavItem {
  const item = ALL_NAV_ITEMS.find((n) => n.key === key);
  if (!item) throw new Error(`Unknown view: ${key}`);
  return item;
}

/**
 * Links to companion tools that live outside this app.
 *
 * Kept separate from `NavItem` on purpose: those map to internal `ViewKey`
 * routes and `getNavItem` throws on anything it can't route, so an external URL
 * has no place in that union. These render as their own sidebar group and open
 * in a new tab.
 */
export interface ExternalNavLink {
  label: string;
  /** lucide-react icon name, resolved in the Sidebar component. */
  icon: string;
  href: string;
}

/**
 * ThreatPulse-AI, the companion evidence-investigation app. Build-time
 * configurable via `VITE_THREATPULSE_URL` (mirrors how the backend URL is set),
 * defaulting to its Railway deployment. The `?.` guard keeps the
 * expression safe under plain Node/tsx, where `import.meta.env` is undefined.
 */
export const THREATPULSE_URL =
  import.meta.env?.VITE_THREATPULSE_URL?.trim() || 'https://threatpulse.up.railway.app/';

export const EXTERNAL_LINKS: ExternalNavLink[] = [
  { label: 'ThreatPulse AI', icon: 'BrainCircuit', href: THREATPULSE_URL },
];
