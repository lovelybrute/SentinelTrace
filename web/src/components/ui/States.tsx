import type { ReactNode } from 'react';
import { AlertTriangle, Inbox, RefreshCw, ServerCrash } from 'lucide-react';
import { cn } from '@/lib/cn';
import { Button } from './Button';

/** Shimmering placeholder block. */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'relative overflow-hidden rounded bg-surface-raised',
        'after:absolute after:inset-0 after:animate-sweep after:bg-gradient-to-r after:from-transparent after:via-white/[0.04] after:to-transparent',
        className,
      )}
    />
  );
}

/** Multi-line text skeleton for loading panels. */
export function SkeletonLines({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={cn('h-3', i === lines - 1 ? 'w-2/3' : 'w-full')} />
      ))}
    </div>
  );
}

export function SkeletonTable({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-1.5">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-2">
          {Array.from({ length: cols }).map((__, c) => (
            <Skeleton key={c} className={cn('h-8 flex-1', c === 0 && 'max-w-[9rem]')} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action,
  className,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center px-6 py-12 text-center',
        className,
      )}
    >
      <span className="mb-3 grid h-11 w-11 place-items-center rounded-lg border border-edge bg-surface-raised text-ink-ghost">
        {icon ?? <Inbox className="h-5 w-5" />}
      </span>
      <h3 className="text-sm font-semibold text-ink-dim">{title}</h3>
      {description ? (
        <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-ink-faint">{description}</p>
      ) : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  title = 'Unable to load data',
  message,
  onRetry,
  className,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center px-6 py-10 text-center',
        className,
      )}
    >
      <span className="mb-3 grid h-11 w-11 place-items-center rounded-lg border border-critical/35 bg-critical/10 text-critical">
        <ServerCrash className="h-5 w-5" />
      </span>
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      <p className="mt-1.5 max-w-md text-xs leading-relaxed text-ink-faint">{message}</p>
      {onRetry ? (
        <Button
          className="mt-4"
          variant="outline"
          onClick={onRetry}
          icon={<RefreshCw className="h-3.5 w-3.5" />}
        >
          Retry
        </Button>
      ) : null}
    </div>
  );
}

/**
 * Shown when the platform is serving simulated data because the FastAPI
 * backend could not be reached. Always visible — never silently faked.
 */
export function SimulationNotice({
  className,
  detail,
}: {
  className?: string;
  detail?: string;
}) {
  return (
    <div
      className={cn(
        'flex items-start gap-2.5 rounded-md border border-intel/25 bg-intel/[0.06] px-3 py-2',
        className,
      )}
    >
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-intel" />
      <p className="text-2xs leading-relaxed text-ink-dim">
        <span className="font-semibold text-intel">Simulated dataset.</span>{' '}
        {detail ??
          'The analysis backend is unreachable, so this view is populated from the built-in demonstration corpus. Figures are representative, not live measurements.'}
      </p>
    </div>
  );
}
