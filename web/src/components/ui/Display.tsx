import { useEffect, useRef, useState, type ReactNode } from 'react';
import { cn } from '@/lib/cn';

/** Tab bar used inside panels and on the analyzer result view. */
export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  className,
  variant = 'underline',
}: {
  tabs: readonly { value: T; label: string; icon?: ReactNode; count?: number }[];
  value: T;
  onChange: (value: T) => void;
  className?: string;
  variant?: 'underline' | 'pill';
}) {
  return (
    <div
      role="tablist"
      className={cn(
        'no-scrollbar flex items-center gap-1 overflow-x-auto',
        variant === 'underline' && 'border-b border-edge',
        className,
      )}
    >
      {tabs.map((tab) => {
        const active = tab.value === value;
        return (
          <button
            key={tab.value}
            role="tab"
            aria-selected={active}
            type="button"
            onClick={() => onChange(tab.value)}
            className={cn(
              'inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap text-xs font-semibold transition-colors duration-150',
              variant === 'underline' &&
                cn(
                  '-mb-px border-b-2 px-3 py-2.5',
                  active
                    ? 'border-intel text-intel'
                    : 'border-transparent text-ink-faint hover:border-edge-bright hover:text-ink-dim',
                ),
              variant === 'pill' &&
                cn(
                  'rounded-md border px-2.5 py-1.5',
                  active
                    ? 'border-intel/45 bg-intel/12 text-intel'
                    : 'border-edge bg-surface-raised text-ink-faint hover:text-ink-dim',
                ),
            )}
          >
            {tab.icon}
            {tab.label}
            {typeof tab.count === 'number' ? (
              <span
                className={cn(
                  'tabular rounded px-1 py-px text-2xs font-bold',
                  active ? 'bg-intel/20 text-intel' : 'bg-surface-overlay text-ink-faint',
                )}
              >
                {tab.count}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

/** Lightweight hover tooltip. Positioned above the trigger. */
export function Tooltip({
  content,
  children,
  className,
}: {
  content: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <span
      className={cn('relative inline-flex', className)}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open ? (
        <span
          role="tooltip"
          className="pointer-events-none absolute bottom-full left-1/2 z-40 mb-1.5 w-max max-w-[16rem] -translate-x-1/2 animate-fade-in rounded-md border border-edge-strong bg-surface-overlay px-2 py-1.5 text-2xs leading-relaxed text-ink-dim shadow-lift"
        >
          {content}
        </span>
      ) : null}
    </span>
  );
}

/** Collapsible section for dense forensic detail. */
export function Disclosure({
  summary,
  children,
  defaultOpen = false,
  className,
  badge,
}: {
  summary: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
  className?: string;
  badge?: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={cn('rounded-md border border-edge bg-surface-inset', className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left transition-colors hover:bg-surface-raised/60"
      >
        <span className="flex min-w-0 items-center gap-2 text-xs font-semibold text-ink-dim">
          {summary}
        </span>
        <span className="flex shrink-0 items-center gap-2">
          {badge}
          <svg
            viewBox="0 0 12 12"
            className={cn(
              'h-3 w-3 text-ink-ghost transition-transform duration-200',
              open && 'rotate-180',
            )}
            aria-hidden="true"
          >
            <path
              d="M3 4.5 6 8l3-3.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
          </svg>
        </span>
      </button>
      {open ? <div className="border-t border-edge/70 p-3">{children}</div> : null}
    </div>
  );
}

/**
 * Count-up animation for headline metrics. Uses requestAnimationFrame and
 * respects prefers-reduced-motion by jumping straight to the final value.
 */
export function AnimatedNumber({
  value,
  durationMs = 900,
  format = (n: number) => String(Math.round(n)),
  className,
}: {
  value: number;
  durationMs?: number;
  format?: (value: number) => string;
  className?: string;
}) {
  const [display, setDisplay] = useState(value);
  const fromRef = useRef(value);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    const reduced =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const from = fromRef.current;
    const delta = value - from;

    if (reduced || delta === 0) {
      setDisplay(value);
      fromRef.current = value;
      return undefined;
    }

    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / durationMs);
      // easeOutExpo keeps the motion authoritative rather than bouncy.
      const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
      setDisplay(from + delta * eased);
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(tick);
      } else {
        fromRef.current = value;
      }
    };
    frameRef.current = requestAnimationFrame(tick);

    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
      fromRef.current = value;
    };
  }, [value, durationMs]);

  return <span className={cn('tabular', className)}>{format(display)}</span>;
}

/** Horizontal meter used for score components and distribution bars. */
export function Meter({
  value,
  max = 100,
  color,
  className,
  height = 'h-1.5',
  trackClassName,
}: {
  value: number;
  max?: number;
  color: string;
  className?: string;
  height?: string;
  trackClassName?: string;
}) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div
      className={cn('w-full overflow-hidden rounded-full bg-surface-inset', height, trackClassName, className)}
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={max}
    >
      <div
        className="h-full rounded-full transition-[width] duration-700 ease-out"
        style={{ width: `${pct}%`, backgroundColor: color }}
      />
    </div>
  );
}
