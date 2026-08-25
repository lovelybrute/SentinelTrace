import {
  forwardRef,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';
import { cn } from '@/lib/cn';

const CONTROL_BASE =
  'w-full rounded-md border border-edge bg-surface-inset px-3 text-sm text-ink placeholder:text-ink-ghost transition-colors duration-150 hover:border-edge-strong focus:border-intel/60 disabled:cursor-not-allowed disabled:opacity-50';

export function Label({
  children,
  htmlFor,
  hint,
  required,
}: {
  children: ReactNode;
  htmlFor?: string;
  hint?: string;
  required?: boolean;
}) {
  return (
    <label htmlFor={htmlFor} className="mb-1.5 flex items-baseline justify-between gap-2">
      <span className="text-xs font-semibold text-ink-dim">
        {children}
        {required ? <span className="ml-0.5 text-critical">*</span> : null}
      </span>
      {hint ? <span className="text-2xs text-ink-ghost">{hint}</span> : null}
    </label>
  );
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return <input ref={ref} className={cn(CONTROL_BASE, 'h-9', className)} {...rest} />;
  },
);

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(function Textarea({ className, ...rest }, ref) {
  return (
    <textarea
      ref={ref}
      className={cn(CONTROL_BASE, 'resize-y py-2 font-mono text-xs leading-relaxed', className)}
      {...rest}
    />
  );
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  function Select({ className, children, ...rest }, ref) {
    return (
      <select
        ref={ref}
        className={cn(CONTROL_BASE, 'h-9 cursor-pointer appearance-none pr-8', className)}
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.5 6 8l3-3.5' fill='none' stroke='%2366718A' stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E\")",
          backgroundRepeat: 'no-repeat',
          backgroundPosition: 'right 0.6rem center',
          backgroundSize: '12px',
        }}
        {...rest}
      >
        {children}
      </select>
    );
  },
);

/** Search field with a leading icon slot. */
export function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
  icon,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('relative', className)}>
      {icon ? (
        <span className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-ghost">
          {icon}
        </span>
      ) : null}
      <input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={cn(CONTROL_BASE, 'h-9', icon && 'pl-8')}
      />
    </div>
  );
}

/** Accessible switch used throughout Settings & Privacy. */
export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5">
      <div className="min-w-0">
        <div className="text-sm font-medium text-ink">{label}</div>
        {description ? (
          <p className="mt-0.5 text-xs leading-relaxed text-ink-faint">{description}</p>
        ) : null}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative mt-0.5 h-5 w-9 shrink-0 rounded-full border transition-colors duration-200',
          checked ? 'border-intel/60 bg-intel/30' : 'border-edge-strong bg-surface-inset',
          disabled && 'cursor-not-allowed opacity-50',
        )}
      >
        <span
          className={cn(
            'absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all duration-200',
            checked ? 'left-[1.15rem] bg-intel' : 'left-0.5 bg-ink-ghost',
          )}
        />
      </button>
    </div>
  );
}

/** Labelled field wrapper with optional validation message. */
export function Field({
  label,
  htmlFor,
  hint,
  required,
  error,
  children,
  className,
}: {
  label: string;
  htmlFor?: string;
  hint?: string;
  required?: boolean;
  error?: string | null;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      <Label htmlFor={htmlFor} hint={hint} required={required}>
        {label}
      </Label>
      {children}
      {error ? <p className="mt-1 text-2xs text-critical">{error}</p> : null}
    </div>
  );
}
