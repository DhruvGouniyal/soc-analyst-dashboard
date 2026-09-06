import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { cn } from '@/lib/cn';

type Variant = 'default' | 'primary' | 'danger' | 'ghost';
type Size = 'sm' | 'md';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
}

/**
 * Apple's button hierarchy.
 *
 * `primary` is a filled white pill with black text — the single loudest control
 * on any screen, used sparingly. `default` is a translucent white fill on grey,
 * the macOS "gray button". `ghost` carries no fill until hover. `danger` is the
 * only control allowed to spend the product's one hue.
 *
 * Every variant clears WCAG AA against its own fill: black on white for
 * primary, white on 9%-white-over-#1C1C1E for the rest.
 */
const VARIANTS: Record<Variant, string> = {
  primary: 'bg-white text-black border-transparent hover:bg-white/90 font-semibold',
  default: 'liquid-control text-fg border-transparent hover:brightness-125',
  ghost: 'bg-transparent text-fg-muted border-transparent hover:bg-[var(--fill-1)] hover:text-fg',
  danger: 'bg-crit/15 text-crit border-crit/40 hover:bg-crit/25',
};

const SIZES: Record<Size, string> = {
  sm: 'h-8 px-3 text-[12px]',
  md: 'h-9 px-4 text-[13px]',
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
        'inline-flex items-center justify-center gap-1.5 rounded-full border font-medium whitespace-nowrap',
        'ios-transition-fast ios-press',
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
 * The iOS segmented control: a recessed track with a raised selected pill that
 * slides between positions. Rendered as a radiogroup so arrow keys and screen
 * readers work.
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
      className={cn(
        'liquid-control flex items-center gap-0.5 p-0.5',
        className,
      )}
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
              'rounded-full px-3 py-1 text-[11.5px] font-medium ios-transition-fast',
              selected
                ? 'bg-[var(--color-surface-hover)] text-fg shadow-[0_1px_3px_rgb(0_0_0/0.5)]'
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
