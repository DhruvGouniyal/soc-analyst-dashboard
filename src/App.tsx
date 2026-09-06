import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { getNavItem, type ViewKey } from '@/config/navigation';
import { SecurityFeedProvider } from '@/state/SecurityFeedProvider';
import { useSecurityFeed } from '@/state/useSecurityFeed';
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { AlertsPage } from '@/pages/AlertsPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { HostsPage } from '@/pages/HostsPage';
import { PlaceholderPage } from '@/pages/PlaceholderPage';
import ClickSpark from '@/components/reactbits/ClickSpark';
// Also ogl-backed: only high-tier devices ever fetch it.
const SwarmCursor = lazy(() => import('@/components/reactbits/SwarmCursor'));
import { LiquidGlassDefs } from '@/components/layout/LiquidGlassDefs';
import { useDeviceTier } from '@/hooks/useDeviceTier';

export default function App() {
  const tier = useDeviceTier();

  // Published on <html> so CSS can strip blur wholesale without every component
  // needing to know the tier.
  useEffect(() => {
    document.documentElement.dataset.tier = tier;
  }, [tier]);

  return (
    <>
      {/*
        Everything here sits outside SecurityFeedProvider on purpose. These are
        WebGL/SVG layers with no interest in security events, and mounting them
        inside the provider is what made the shader rebuild on every metric tick.
      */}
      <LiquidGlassDefs />
      {tier === 'high' ? (
      <Suspense fallback={null}>
      <SwarmCursor
        color="#ffffff"
        accentColor="#ff453a"
        count={26}
        size={13}
        merge={0.55}
        glow={0.5}
        opacity={0.5}
        speed={0.9}
        trail={0.86}
        scatterOnClick
      />
      </Suspense>
      ) : null}

      <SecurityFeedProvider>
        <AppShell />
      </SecurityFeedProvider>
    </>
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
    <ClickSpark sparkColor="#ffffff" sparkSize={7} sparkRadius={16} sparkCount={8} duration={420}>
      <div className="relative z-10 flex h-screen overflow-hidden text-fg">
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
            <ViewTransition view={view} />
          </main>
        </div>
      </div>
    </ClickSpark>
  );
}

/**
 * View change, iOS-style.
 *
 * `mode="wait"` would blank the pane between views; iOS never shows an empty
 * frame, so the outgoing and incoming views overlap. The movement is 8px, not
 * a full slide — at dashboard scale a large translate reads as a gimmick, while
 * a short offset on the presentation curve reads as the surface settling.
 */
function ViewTransition({ view }: { view: ViewKey }) {
  const reduce = useReducedMotion();

  return (
    <AnimatePresence initial={false}>
      <motion.div
        key={view}
        className="h-full"
        initial={reduce ? false : { opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        exit={reduce ? undefined : { opacity: 0 }}
        transition={{ duration: 0.42, ease: [0.32, 0.72, 0, 1] }}
      >
        <ViewRouter view={view} />
      </motion.div>
    </AnimatePresence>
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
