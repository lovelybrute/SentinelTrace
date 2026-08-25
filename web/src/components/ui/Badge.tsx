import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';
import {
  AUTH_STYLES,
  REPUTATION_STYLES,
  SEVERITY_STYLES,
} from '@/lib/constants';
import { spacedEnum } from '@/lib/format';
import type { AuthVerdict, Reputation, ServiceState, Severity } from '@/types';

type BadgeTone = 'neutral' | 'intel' | 'safe' | 'medium' | 'high' | 'critical';

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: 'border-edge-strong bg-ink/5 text-ink-dim',
  intel: 'border-intel/40 bg-intel/10 text-intel',
  safe: 'border-safe/40 bg-safe/10 text-safe',
  medium: 'border-medium/40 bg-medium/10 text-medium',
  high: 'border-high/40 bg-high/10 text-high',
  critical: 'border-critical/40 bg-critical/10 text-critical',
};

export function Badge({
  children,
  tone = 'neutral',
  className,
  mono = false,
}: {
  children: ReactNode;
  tone?: BadgeTone;
  className?: string;
  mono?: boolean;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wider',
        mono && 'font-mono tracking-normal',
        TONE_CLASSES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'intel',
  INFO: 'neutral',
};

export function SeverityBadge({
  severity,
  className,
  withDot = true,
}: {
  severity: Severity;
  className?: string;
  withDot?: boolean;
}) {
  return (
    <Badge tone={SEVERITY_TONE[severity]} className={className}>
      {withDot ? (
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ backgroundColor: SEVERITY_STYLES[severity].hex }}
        />
      ) : null}
      {severity}
    </Badge>
  );
}

export function AuthBadge({
  verdict,
  className,
}: {
  verdict: AuthVerdict;
  className?: string;
}) {
  const style = AUTH_STYLES[verdict];
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-2 py-0.5 font-mono text-2xs font-bold tracking-wider',
        style.text,
        style.bg,
        style.border,
        className,
      )}
    >
      {verdict}
    </span>
  );
}

export function ReputationBadge({
  reputation,
  className,
}: {
  reputation: Reputation;
  className?: string;
}) {
  const style = REPUTATION_STYLES[reputation];
  return (
    <span
      className={cn(
        'inline-flex items-center rounded px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-wider',
        style.text,
        style.bg,
        className,
      )}
    >
      {style.label}
    </span>
  );
}

/** Classification chip — the verdict taxonomy, e.g. Business Email Compromise. */
export function ClassificationBadge({
  classification,
  className,
}: {
  classification: string;
  className?: string;
}) {
  const tone: BadgeTone =
    classification === 'LEGITIMATE'
      ? 'safe'
      : classification === 'SUSPICIOUS'
        ? 'medium'
        : 'critical';
  return (
    <Badge tone={tone} className={className}>
      {spacedEnum(classification)}
    </Badge>
  );
}

const STATE_DOT: Record<ServiceState, string> = {
  ONLINE: 'bg-safe',
  DEGRADED: 'bg-medium',
  OFFLINE: 'bg-critical',
  CHECKING: 'bg-ink-ghost',
};

const STATE_TEXT: Record<ServiceState, string> = {
  ONLINE: 'text-safe',
  DEGRADED: 'text-medium',
  OFFLINE: 'text-critical',
  CHECKING: 'text-ink-faint',
};

/** Pulsing status dot used across the service strip and headers. */
export function StatusDot({
  state,
  className,
}: {
  state: ServiceState;
  className?: string;
}) {
  return (
    <span className={cn('relative inline-flex h-2 w-2 shrink-0', className)}>
      {state === 'ONLINE' ? (
        <span className="absolute inset-0 animate-pulse-dot rounded-full bg-safe/50" />
      ) : null}
      <span className={cn('relative m-auto h-1.5 w-1.5 rounded-full', STATE_DOT[state])} />
    </span>
  );
}

export function ServiceStateLabel({
  state,
  label,
  className,
}: {
  state: ServiceState;
  label: string;
  className?: string;
}) {
  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <StatusDot state={state} />
      <span className="text-2xs font-semibold uppercase tracking-[0.12em] text-ink-dim">
        {label}
      </span>
      <span className={cn('text-2xs font-bold uppercase tracking-wider', STATE_TEXT[state])}>
        {state}
      </span>
    </span>
  );
}

/** Marks whether a figure came from the live backend or the simulation. */
export function OriginBadge({
  origin,
  className,
}: {
  origin: 'LIVE_BACKEND' | 'SIMULATED';
  className?: string;
}) {
  return origin === 'LIVE_BACKEND' ? (
    <Badge tone="safe" className={className}>
      Live backend
    </Badge>
  ) : (
    <Badge tone="intel" className={className}>
      Simulated
    </Badge>
  );
}
