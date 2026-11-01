import { Check, Circle, Radio } from 'lucide-react';
import { DEMO_SCRIPT } from '@/data/scenarios';
import { cn } from '@/lib/cn';
import type { DemoProgress } from '@/data/providers';

interface DemoTimelineProps {
  progress: DemoProgress | null;
}

/**
 * Presentation aid shown only in demo mode.
 *
 * Makes the scripted sequence legible to an audience: the beat currently
 * firing is marked, completed beats are checked, so a narrator can point at
 * where the attack chain has reached without guessing.
 */
export function DemoTimeline({ progress }: DemoTimelineProps) {
  const currentIndex = progress?.beatIndex ?? -1;

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded border border-accent/30 bg-accent/8 px-3 py-2">
      <span className="flex shrink-0 items-center gap-1.5 text-[10px] font-semibold tracking-wide text-accent uppercase">
        <Radio className="h-3 w-3" />
        Demo Sequence
        {progress && progress.cycle > 0 ? (
          <span className="font-normal text-fg-dim normal-case">· run {progress.cycle + 1}</span>
        ) : null}
      </span>

      <ol className="flex flex-1 flex-wrap items-center gap-x-1 gap-y-1">
        {DEMO_SCRIPT.map((beat, index) => {
          const isActive = index === currentIndex;
          const isDone = currentIndex > index;

          return (
            <li key={beat.label} className="flex items-center gap-1">
              <span
                className={cn(
                  'flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[10.5px] whitespace-nowrap',
                  'transition-colors duration-200',
                  isActive
                    ? 'border-accent/60 bg-accent/20 font-medium text-accent'
                    : isDone
                      ? 'border-line bg-canvas text-fg-muted'
                      : 'border-line/60 bg-canvas text-fg-dim',
                )}
              >
                {isDone ? (
                  <Check className="h-2.5 w-2.5 shrink-0" />
                ) : (
                  <Circle
                    className={cn('h-2 w-2 shrink-0', isActive && 'fill-current')}
                  />
                )}
                <span className="tabular opacity-70">
                  {String(Math.floor(beat.at / 60)).padStart(2, '0')}:
                  {String(beat.at % 60).padStart(2, '0')}
                </span>
                {beat.label}
              </span>
              {index < DEMO_SCRIPT.length - 1 ? (
                <span className="text-fg-dim" aria-hidden="true">
                  ·
                </span>
              ) : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
