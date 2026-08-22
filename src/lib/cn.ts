import clsx, { type ClassValue } from 'clsx';

/** Conditional className joiner used across all components. */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
