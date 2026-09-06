import { Inbox, TriangleAlert } from 'lucide-react';
import type { CSSProperties, ReactNode } from 'react';
import { cn } from '@/lib/cn';
import { Button } from './Button';

/** Neutral shimmer placeholder used while the initial snapshot loads. */
export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-[var(--radius-control)] bg-[var(--fill-1)]', className)} />;
}

/** Skeleton shaped like a feed row, so loading doesn't shift the layout. */
export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-px" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="flex items-center gap-3 px-3 py-2.5 opacity-[var(--row-fade)]"
          style={{ '--row-fade': `${1 - i * 0.13}` } as CSSProperties}
        >
          <Skeleton className="h-4 w-14" />
          <Skeleton className="h-3 flex-1" />
          <Skeleton className="h-3 w-20" />
        </div>
      ))}
    </div>
  );
}

interface EmptyStateProps {
  title: string;
  description?: string;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
}

export function EmptyState({ title, description, action, icon, className }: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex h-full min-h-32 flex-col items-center justify-center gap-2 px-6 py-10 text-center',
        className,
      )}
    >
      <div className="text-fg-dim">{icon ?? <Inbox className="h-5 w-5" />}</div>
      <p className="text-xs font-medium text-fg-muted">{title}</p>
      {description ? <p className="max-w-sm text-[11px] text-fg-dim">{description}</p> : null}
      {action ? <div className="mt-1">{action}</div> : null}
    </div>
  );
}

interface ErrorStateProps {
  title: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({ title, message, onRetry, className }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        'flex h-full min-h-32 flex-col items-center justify-center gap-2 px-6 py-10 text-center',
        className,
      )}
    >
      <TriangleAlert className="h-5 w-5 text-crit" />
      <p className="text-xs font-medium text-fg">{title}</p>
      <p className="max-w-md text-[11px] leading-relaxed text-fg-muted">{message}</p>
      {onRetry ? (
        <Button variant="default" onClick={onRetry} className="mt-1">
          Retry connection
        </Button>
      ) : null}
    </div>
  );
}
