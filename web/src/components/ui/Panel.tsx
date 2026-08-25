import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

interface PanelProps {
  children: ReactNode;
  className?: string;
  /** Adds a subtle translucent gradient. Use sparingly — hero surfaces only. */
  glass?: boolean;
  /** Emphasis border for the highest-priority surface on a screen. */
  accent?: 'none' | 'intel' | 'critical';
}

/** The base surface of the platform. Everything sits inside one of these. */
export function Panel({ children, className, glass = false, accent = 'none' }: PanelProps) {
  return (
    <div
      className={cn(
        'rounded-panel border shadow-panel',
        glass ? 'glass' : 'bg-surface',
        accent === 'none' && 'border-edge',
        accent === 'intel' && 'border-intel/30 shadow-glow-intel',
        accent === 'critical' && 'border-critical/35 shadow-glow-critical',
        'print-surface',
        className,
      )}
    >
      {children}
    </div>
  );
}

interface PanelHeaderProps {
  title: string;
  /** Small uppercase kicker above the title. */
  eyebrow?: string;
  description?: string;
  icon?: ReactNode;
  actions?: ReactNode;
  className?: string;
}

export function PanelHeader({
  title,
  eyebrow,
  description,
  icon,
  actions,
  className,
}: PanelHeaderProps) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-start justify-between gap-3 border-b border-edge/70 px-4 py-3',
        className,
      )}
    >
      <div className="flex min-w-0 items-start gap-3">
        {icon ? (
          <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-md border border-edge bg-surface-raised text-intel">
            {icon}
          </span>
        ) : null}
        <div className="min-w-0">
          {eyebrow ? <div className="label-caps mb-1">{eyebrow}</div> : null}
          <h2 className="truncate text-sm font-semibold tracking-tight text-ink">{title}</h2>
          {description ? (
            <p className="mt-1 text-xs leading-relaxed text-ink-faint">{description}</p>
          ) : null}
        </div>
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function PanelBody({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cn('p-4', className)}>{children}</div>;
}

export function PanelFooter({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-between gap-2 border-t border-edge/70 px-4 py-2.5 text-xs text-ink-faint',
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Page-level heading used at the top of every route. */
export function PageHeader({
  title,
  eyebrow,
  description,
  actions,
}: {
  title: string;
  eyebrow?: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow ? <div className="label-caps mb-1.5 text-intel/80">{eyebrow}</div> : null}
        <h1 className="text-xl font-semibold tracking-tight text-ink sm:text-2xl">{title}</h1>
        {description ? (
          <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-ink-dim">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}
