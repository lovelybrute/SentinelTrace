import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { cn } from '@/lib/cn';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'outline';
type Size = 'xs' | 'sm' | 'md' | 'lg';

const VARIANTS: Record<Variant, string> = {
  primary:
    'bg-intel/15 text-intel border-intel/45 hover:bg-intel/25 hover:border-intel/70 active:bg-intel/30',
  secondary:
    'bg-surface-raised text-ink border-edge-strong hover:bg-surface-overlay hover:border-edge-bright',
  ghost: 'bg-transparent text-ink-dim border-transparent hover:bg-surface-raised hover:text-ink',
  danger:
    'bg-critical/15 text-critical border-critical/45 hover:bg-critical/25 hover:border-critical/70',
  outline: 'bg-transparent text-ink-dim border-edge-strong hover:border-intel/50 hover:text-intel',
};

const SIZES: Record<Size, string> = {
  xs: 'h-6 px-2 text-2xs gap-1',
  sm: 'h-8 px-2.5 text-xs gap-1.5',
  md: 'h-9 px-3.5 text-sm gap-2',
  lg: 'h-11 px-5 text-sm gap-2',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  icon?: ReactNode;
  iconRight?: ReactNode;
  loading?: boolean;
  fullWidth?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'secondary',
    size = 'sm',
    icon,
    iconRight,
    loading = false,
    fullWidth = false,
    className,
    children,
    disabled,
    type = 'button',
    ...rest
  },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      className={cn(
        'inline-flex items-center justify-center whitespace-nowrap rounded-md border font-semibold transition-colors duration-150',
        'disabled:cursor-not-allowed disabled:opacity-45',
        VARIANTS[variant],
        SIZES[size],
        fullWidth && 'w-full',
        className,
      )}
      {...rest}
    >
      {loading ? <Spinner /> : icon}
      {children}
      {iconRight}
    </button>
  );
});

function Spinner() {
  return (
    <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Square icon-only button for toolbars. */
export function IconButton({
  label,
  icon,
  onClick,
  variant = 'ghost',
  className,
  disabled,
}: {
  label: string;
  icon: ReactNode;
  onClick?: () => void;
  variant?: Variant;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'grid h-8 w-8 place-items-center rounded-md border transition-colors duration-150',
        'disabled:cursor-not-allowed disabled:opacity-40',
        VARIANTS[variant],
        className,
      )}
    >
      {icon}
    </button>
  );
}

/** Segmented control — used for time ranges and view switches. */
export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  className,
  size = 'sm',
}: {
  options: readonly { value: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
  className?: string;
  size?: 'xs' | 'sm';
}) {
  return (
    <div
      role="tablist"
      className={cn(
        'inline-flex items-center gap-0.5 rounded-md border border-edge bg-surface-inset p-0.5',
        className,
      )}
    >
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            role="tab"
            aria-selected={active}
            type="button"
            onClick={() => onChange(option.value)}
            className={cn(
              'rounded font-semibold transition-colors duration-150',
              size === 'xs' ? 'px-2 py-1 text-2xs' : 'px-2.5 py-1 text-xs',
              active
                ? 'bg-intel/15 text-intel'
                : 'text-ink-faint hover:bg-surface-raised hover:text-ink-dim',
            )}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
