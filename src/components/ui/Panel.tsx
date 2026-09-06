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
 * One consistent frame keeps the layout predictable; panels differ by content,
 * never by chrome.
 */
export function Panel({ title, meta, actions, children, className, flush }: PanelProps) {
  return (
    <section className={cn('liquid flex min-h-0 flex-col overflow-hidden', className)}>
      <header className="flex min-h-[54px] shrink-0 items-center justify-between gap-3 px-5 pt-4 pb-2">
        <div className="flex min-w-0 flex-col gap-0.5">
          <h2 className="truncate text-[13.5px] leading-tight font-semibold tracking-tight text-fg">
            {title}
          </h2>
          {meta ? (
            <span className="truncate text-[11px] leading-tight text-fg-dim tabular">{meta}</span>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
      </header>
      <div className={cn('min-h-0 flex-1', flush ? '' : 'px-5 pt-1 pb-5')}>{children}</div>
    </section>
  );
}
