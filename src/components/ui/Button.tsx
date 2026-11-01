import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { cn } from '@/lib/cn';

type Variant = 'default' | 'primary' | 'danger' | 'ghost';
type Size = 'sm' | 'md';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
}

const VARIANTS: Record<Variant, string> = {
  default: 'border-line-strong bg-surface-raised text-fg hover:bg-surface-hover hover:border-fg-dim',
  primary: 'border-accent/50 bg-accent/12 text-accent hover:bg-accent/20',
  danger: 'border-crit/50 bg-crit/12 text-crit hover:bg-crit/20',
  ghost: 'border-transparent text-fg-muted hover:bg-surface-hover hover:text-fg',
};

const SIZES: Record<Size, string> = {
  sm: 'h-6 px-2 text-[11px]',
  md: 'h-7 px-3 text-xs',
};

export function Button({
  variant = 'default',
  size = 'sm',
  className,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      type="button"
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded border font-medium whitespace-nowrap',
        'transition-colors duration-100',
        'disabled:pointer-events-none disabled:opacity-40',
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}

interface ToggleGroupProps<T extends string> {
  options: { value: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
  /** Accessible name for the group. */
  label: string;
  className?: string;
}

/**
 * Segmented control used for the chart's time range and the data-source
 * switch. Rendered as a radiogroup so arrow keys and screen readers work.
 */
export function ToggleGroup<T extends string>({
  options,
  value,
  onChange,
  label,
  className,
}: ToggleGroupProps<T>) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn('flex items-center gap-0.5 rounded border border-line bg-canvas p-0.5', className)}
    >
      {options.map((option) => {
        const selected = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={() => onChange(option.value)}
            className={cn(
              'rounded px-2 py-1 text-[11px] font-medium transition-colors duration-100',
              selected
                ? 'bg-surface-raised text-fg shadow-[inset_0_0_0_1px_var(--color-line-strong)]'
                : 'text-fg-dim hover:text-fg-muted',
            )}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
