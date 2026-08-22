import { useMemo, useState } from 'react';
import { getNavItem, type ViewKey } from '@/config/navigation';
import { SecurityFeedProvider } from '@/state/SecurityFeedProvider';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { AlertsPage } from '@/pages/AlertsPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { HostsPage } from '@/pages/HostsPage';
import { PlaceholderPage } from '@/pages/PlaceholderPage';

export default function App() {
  return (
    <SecurityFeedProvider>
      <AppShell />
    </SecurityFeedProvider>
  );
}

function AppShell() {
  const [view, setView] = useState<ViewKey>('dashboard');
  const [navOpen, setNavOpen] = useState(false);
  const { events } = useSecurityFeed();

  /**
   * Nav and header badges. Derived here so the counts are computed once and
   * shared, rather than each chrome component scanning the event set.
   */
  const badges = useMemo(() => {
    let critical = 0;
    let unacknowledged = 0;
    for (const event of events) {
      const open = event.status === 'new' || event.status === 'investigating';
      if (!open) continue;
      if (event.severity === 'critical') critical += 1;
      if (event.status === 'new' && (event.severity === 'critical' || event.severity === 'high')) {
        unacknowledged += 1;
      }
    }
    return { critical, unacknowledged };
  }, [events]);

  function navigate(next: ViewKey) {
    setView(next);
    setNavOpen(false);
  }

  return (
    <div className="flex h-screen overflow-hidden bg-canvas text-fg">
      <Sidebar
        active={view}
        onNavigate={navigate}
        open={navOpen}
        onClose={() => setNavOpen(false)}
        criticalCount={badges.critical}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <Header
          view={view}
          onOpenNav={() => setNavOpen(true)}
          notificationCount={badges.unacknowledged}
        />
        <main className="min-h-0 flex-1 overflow-hidden">
          <ViewRouter view={view} />
        </main>
      </div>
    </div>
  );
}

function ViewRouter({ view }: { view: ViewKey }) {
  if (!getNavItem(view).implemented) return <PlaceholderPage view={view} />;

  switch (view) {
    case 'dashboard':
      return <DashboardPage />;
    case 'alerts':
      return <AlertsPage />;
    case 'hosts':
      return <HostsPage />;
    default:
      return <PlaceholderPage view={view} />;
  }
}
