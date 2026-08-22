import { Construction } from 'lucide-react';
import { getNavItem, type ViewKey } from '@/config/navigation';
import { Panel } from '@/components/ui/Panel';
import { EmptyState } from '@/components/ui/States';

/**
 * Honest placeholder for sections outside this phase's scope.
 *
 * Preferable to either hiding the nav entry or shipping a hollow page that
 * looks functional: the analyst can see the section exists and what it will do.
 */
export function PlaceholderPage({ view }: { view: ViewKey }) {
  const nav = getNavItem(view);

  return (
    <div className="h-full overflow-y-auto p-3">
      <Panel title={nav.title} meta="Planned">
        <EmptyState
          icon={<Construction className="h-5 w-5" />}
          title={`${nav.title} is not part of this build`}
          description={`${nav.subtitle}. The data layer already carries the fields this view needs — it is scoped out of the current phase so the main console stays polished.`}
        />
      </Panel>
    </div>
  );
}
