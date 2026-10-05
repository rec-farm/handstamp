import { useId, type ButtonHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react';
import { ChevronDown, CircleAlert, LoaderCircle, TriangleAlert } from 'lucide-react';

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  // lg: full-width card actions (44px touch target) · md: inline page actions (36px)
  size?: 'lg' | 'md';
  busy?: boolean;
  icon?: ReactNode;
};

const VARIANTS = {
  // The one offset shadow on the page (DESIGN §6.3).
  primary:
    'border-[1.5px] border-border-strong bg-primary text-primary-fg shadow-hard press hover:bg-primary-hover',
  secondary: 'border border-border-input bg-surface-1 text-fg hover:bg-surface-2',
  ghost: 'text-fg-muted hover:text-fg hover:bg-surface-2',
  danger: 'border-[1.5px] border-border-strong bg-danger-solid text-white hover:opacity-90',
};
const SIZES = {
  lg: 'h-11 w-full px-[18px] text-[15px]',
  md: 'h-9 px-3.5 text-body',
};

export function Button({
  variant = 'secondary',
  size = 'lg',
  busy,
  icon,
  children,
  className = '',
  disabled,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={`inline-flex shrink-0 items-center justify-center gap-2 rounded-sm font-semibold transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none ${SIZES[size]} ${VARIANTS[variant]} ${className}`}
    >
      {busy ? <LoaderCircle className="size-4 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
}

// Page titles end with the purple period (DESIGN §2.1).
export function Title({ children }: { children: ReactNode }) {
  return (
    <h1 className="text-title-2 text-fg">
      {children}
      <span className="text-primary">.</span>
    </h1>
  );
}

export function Callout({ tone, children }: { tone: 'warning' | 'danger'; children: ReactNode }) {
  const Icon = tone === 'danger' ? CircleAlert : TriangleAlert;
  // The edge is the status -400 in both themes (DESIGN §6.2, §10.8).
  const edge = tone === 'danger' ? 'border-l-rose-400' : 'border-l-sun-400';
  const icon = tone === 'danger' ? 'text-danger-icon' : 'text-warning-icon';
  return (
    <div
      role={tone === 'danger' ? 'alert' : 'note'}
      className={`flex gap-3 rounded-sm border border-border border-l-4 ${edge} bg-surface-2 px-4 py-3 text-body-sm text-fg`}
    >
      <Icon className={`mt-0.5 size-4 shrink-0 ${icon}`} aria-hidden />
      <div>{children}</div>
    </div>
  );
}

// One calm card in the middle of the page: the product's face (DESIGN §11, plan §7).
export function CardPage({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col items-center px-4 py-10 sm:py-16">
      <header className="mb-8 flex items-center gap-3 text-fg">
        {/* TODO(brand): the Handstamp mark comes from rec-brand/build.py (§2.10). */}
        <span aria-hidden className="size-6 rounded-xs border border-dashed border-border-strong" />
        <span className="wordmark">Handstamp</span>
      </header>
      <main className="w-full max-w-[420px] rounded-sm border border-border bg-surface-1 p-6 sm:p-8">
        {children}
      </main>
      {footer && (
        <div className="mt-4 w-full max-w-[420px] text-center font-mono text-mono-sm text-fg-subtle">
          {footer}
        </div>
      )}
      <footer className="mt-auto pt-10 text-caption text-fg-subtle">
        <span className="font-mono">Handstamp v{__HANDSTAMP_VERSION__}</span> · by R.E.C.
      </footer>
    </div>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <div role="status" className="flex items-center gap-3 text-body text-fg-muted">
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      {label}
    </div>
  );
}

// Label stamp above the field, optional accent dot for required, helper text (DESIGN §10.2).
export function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: (id: string) => ReactNode;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="label-stamp block text-fg">
        {label}
        {required && (
          <>
            {' '}
            <span aria-hidden className="text-accent">
              ●
            </span>
            <span className="sr-only">(required)</span>
          </>
        )}
      </label>
      {hint && <p className="mt-1 text-body-sm text-fg-muted">{hint}</p>}
      <div className="mt-2">{children(id)}</div>
    </div>
  );
}

// Small mono tag for states like "Synced" or "This browser" (DESIGN §10.10).
export function Tag({
  tone = 'neutral',
  children,
}: {
  tone?: 'neutral' | 'info' | 'success';
  children: ReactNode;
}) {
  const tones = {
    neutral: 'bg-surface-3 text-fg-muted',
    info: 'bg-info-tile text-info-text',
    success: 'bg-success-tile text-success-text',
  };
  return (
    <span
      className={`inline-flex h-[22px] items-center gap-1.5 rounded-xs px-1.5 font-mono text-mono-sm ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

// Native select in the input shell, with the trailing chevron-down (DESIGN §10.2).
export function Select({
  className = '',
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <div className="relative">
      <select {...rest} className={`input appearance-none pr-10 ${className}`}>
        {children}
      </select>
      <ChevronDown
        className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-fg-subtle"
        aria-hidden
      />
    </div>
  );
}

export type Choice<T extends string> = {
  value: T;
  label: string;
  hint: string;
  icon: ReactNode;
};

// A picker of cards for a few options worth explaining. The selected card is the one place a
// card gets the offset shadow (DESIGN §6.3, §10.7).
export function Choices<T extends string>({
  label,
  hint,
  value,
  options,
  disabled,
  onChange,
}: {
  label: string;
  hint: string;
  value: T;
  options: Choice<T>[];
  disabled?: boolean;
  onChange: (value: T) => void;
}) {
  const name = useId();
  return (
    <fieldset disabled={disabled}>
      <legend className="label-stamp text-fg">{label}</legend>
      <p className="mt-1 text-body-sm text-fg-muted">{hint}</p>
      <div className="mt-2 grid gap-3 sm:grid-cols-3">
        {options.map((o) => (
          <label
            key={o.value}
            className="flex cursor-pointer gap-3 rounded-sm border border-border-input bg-surface-2 p-3 transition-colors duration-150 hover:border-border-strong has-checked:border-primary has-checked:shadow-hard-sm has-focus-visible:ring-3 has-focus-visible:ring-primary/25 has-disabled:cursor-not-allowed has-disabled:not-has-checked:opacity-40 has-disabled:hover:border-border-input light:bg-surface-1"
          >
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={value === o.value}
              onChange={() => onChange(o.value)}
              className="sr-only"
            />
            <span className="mt-0.5 shrink-0 text-fg-muted [label:has(:checked)_&]:text-fg">
              {o.icon}
            </span>
            <span className="min-w-0">
              <span className="block text-body font-semibold text-fg">{o.label}</span>
              <span className="mt-0.5 block text-body-sm text-fg-muted">{o.hint}</span>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

// One block of a form: a stamp and a line of context on the left, the fields on the right
// (DESIGN §10.7 card header, §11.3 sections with a divider).
export function Section({
  label,
  subtitle,
  children,
}: {
  label: string;
  subtitle: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <div
      role="group"
      aria-labelledby={id}
      className="grid gap-x-10 gap-y-5 border-b border-border px-6 py-6 lg:grid-cols-[14rem_minmax(0,1fr)]"
    >
      <div>
        <h3 id={id} className="label-stamp text-fg">
          {label}
        </h3>
        <p className="mt-1 text-body-sm text-fg-muted">{subtitle}</p>
      </div>
      <div className="space-y-6">{children}</div>
    </div>
  );
}

// The button row under a sectioned form, lined up with the fields column.
export function FormActions({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap gap-3 px-6 py-5 lg:pl-[calc(14rem+4rem)]">{children}</div>;
}

export function Check({
  checked,
  onChange,
  label,
  hint,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  hint: string;
  disabled?: boolean;
}) {
  return (
    <label className="flex items-start gap-3 text-body text-fg has-disabled:cursor-not-allowed">
      <input
        type="checkbox"
        className="mt-0.5 size-4 accent-primary"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        {label}
        <span className="mt-0.5 block text-body-sm text-fg-muted">{hint}</span>
      </span>
    </label>
  );
}
