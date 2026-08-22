import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

interface PanelProps {
  title: string;
  /** Secondary text shown next to the title, e.g. a count or window. */
  meta?: ReactNode;
  /** Controls rendered on the right of the header. */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Removes body padding for tables and feeds that manage their own. */
  flush?: boolean;
}

/**
 * The standard container for every dashboard section.
 *
 * One consistent frame keeps the layout dense and predictable; panels differ
 * by content, never by chrome.
 */
export function Panel({ title, meta, actions, children, className, flush }: PanelProps) {
  return (
    <section
      className={cn(
        'flex min-h-0 flex-col overflow-hidden rounded border border-line bg-surface',
        className,
      )}
    >
      <header className="flex h-10 shrink-0 items-center justify-between gap-3 border-b border-line px-3">
        <div className="flex min-w-0 items-baseline gap-2">
          <h2 className="label-caps truncate text-fg-muted">{title}</h2>
          {meta ? <span className="truncate text-[11px] text-fg-dim tabular">{meta}</span> : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-1">{actions}</div> : null}
      </header>
      <div className={cn('min-h-0 flex-1', flush ? '' : 'p-3')}>{children}</div>
    </section>
  );
}
