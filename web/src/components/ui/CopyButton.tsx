import { useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { cn } from '@/lib/cn';

/**
 * Copy-to-clipboard control used on every IOC and hash in the platform.
 * Falls back to a hidden textarea when the async Clipboard API is unavailable
 * (e.g. a non-secure origin), so it never silently does nothing.
 */
export function CopyButton({
  value,
  label = 'Copy',
  className,
  size = 'sm',
}: {
  value: string;
  label?: string;
  className?: string;
  size?: 'xs' | 'sm';
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );

  async function copy() {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        ok = true;
      } else {
        ok = legacyCopy(value);
      }
    } catch {
      ok = legacyCopy(value);
    }
    if (ok) {
      setCopied(true);
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1400);
    }
  }

  const dim = size === 'xs' ? 'h-3 w-3' : 'h-3.5 w-3.5';

  return (
    <button
      type="button"
      onClick={copy}
      title={copied ? 'Copied' : `${label}: ${value}`}
      aria-label={copied ? 'Copied to clipboard' : `${label} ${value}`}
      className={cn(
        'inline-flex shrink-0 items-center gap-1 rounded border border-transparent px-1 py-0.5 text-2xs font-medium transition-colors duration-150',
        copied
          ? 'text-safe'
          : 'text-ink-ghost hover:border-edge-strong hover:bg-surface-raised hover:text-intel',
        className,
      )}
    >
      {copied ? <Check className={dim} /> : <Copy className={dim} />}
      {copied ? 'Copied' : null}
    </button>
  );
}

function legacyCopy(value: string): boolean {
  try {
    const area = document.createElement('textarea');
    area.value = value;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(area);
    return ok;
  } catch {
    return false;
  }
}

/** Monospace value with an attached copy affordance. */
export function CopyableValue({
  value,
  display,
  className,
  tone = 'default',
}: {
  value: string;
  display?: string;
  className?: string;
  tone?: 'default' | 'critical' | 'intel';
}) {
  return (
    <span className={cn('group inline-flex min-w-0 items-center gap-1', className)}>
      <span
        className={cn(
          'truncate font-mono text-xs',
          tone === 'default' && 'text-ink',
          tone === 'critical' && 'text-critical',
          tone === 'intel' && 'text-intel',
        )}
        title={value}
      >
        {display ?? value}
      </span>
      <CopyButton value={value} className="opacity-0 group-hover:opacity-100 focus:opacity-100" />
    </span>
  );
}
