import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { Check, ChevronRight, Copy, ShieldCheck } from 'lucide-react';
import { relative } from '../lib/time.ts';
import type { Notice } from '../lib/console.tsx';
import { Button, Callout } from './ui.tsx';

// Eyebrow · title (with the purple period unless it's an identifier) · subtitle (DESIGN §10.5).
export function PageHeader({
  eyebrow,
  title,
  subtitle,
  identifier,
  name,
  action,
}: {
  eyebrow: string;
  title: ReactNode;
  subtitle?: ReactNode;
  // Machine identifiers (client IDs, slugs) are mono and get no period (DESIGN §11.2).
  identifier?: boolean;
  // A person's name: human text, so sans, but no period either.
  name?: boolean;
  action?: ReactNode;
}) {
  return (
    <>
      <header className="flex flex-wrap items-end justify-between gap-6 pt-10 pb-8 md:pt-16">
        <div className="min-w-0">
          <p className="eyebrow">{eyebrow}</p>
          <h1
            className={`mt-2 text-[2.5rem] leading-none font-extrabold tracking-[-0.035em] break-words text-fg md:text-title-1 ${identifier ? 'font-mono font-semibold tracking-normal md:text-[2.75rem]' : ''}`}
          >
            {title}
            {!identifier && !name && <span className="text-primary">.</span>}
          </h1>
          {subtitle && <p className="mt-3 max-w-[60ch] text-body-lg text-fg-muted">{subtitle}</p>}
        </div>
        {action}
      </header>
      <hr className="border-t-2 border-border-strong" />
    </>
  );
}

export function NoticeLine({ notice }: { notice?: Notice }) {
  return (
    <div aria-live="polite">
      {notice && (
        <div className="mt-8">
          {notice.tone === 'error' ? (
            <Callout tone="danger">{notice.text}</Callout>
          ) : (
            <p className="flex items-center gap-2 text-body text-success-text">
              <ShieldCheck className="size-4" aria-hidden /> {notice.text}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export function Panel({
  label,
  action,
  children,
}: {
  label: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="mt-10 border border-border bg-surface-1">
      <div className="flex min-h-14 flex-wrap items-center justify-between gap-4 border-b border-border px-6 py-3">
        <h2 className="label-stamp text-fg">{label}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

// Tables per DESIGN §10.11: label-stamp header, 52px rows, mono for machine data.
export function Table({
  head,
  children,
  empty,
}: {
  head: string[];
  children: ReactNode;
  empty?: ReactNode;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] border-collapse text-left text-body">
        <thead>
          <tr className="h-10 bg-surface-2 light:bg-surface-1">
            {head.map((h) => (
              <th key={h} scope="col" className="label-stamp px-6 font-bold text-fg-subtle">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">{children}</tbody>
      </table>
      {empty}
    </div>
  );
}

export function Row({ to, children }: { to?: string; children: ReactNode }) {
  return <tr className={`h-[52px] ${to ? 'hover:bg-surface-2' : ''}`}>{children}</tr>;
}

export function Cell({
  children,
  mono,
  muted,
}: {
  children: ReactNode;
  mono?: boolean;
  muted?: boolean;
}) {
  return (
    <td
      className={`px-6 py-2 align-middle ${mono ? 'font-mono text-mono' : ''} ${muted ? 'text-fg-muted' : 'text-fg'}`}
    >
      {children}
    </td>
  );
}

export function RowLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      className="group inline-flex items-center gap-1 font-semibold text-fg hover:underline"
    >
      {children}
      <ChevronRight
        className="size-4 text-fg-subtle transition-transform group-hover:translate-x-0.5"
        aria-hidden
      />
    </Link>
  );
}

export function When({ iso }: { iso: string | null | undefined }) {
  return (
    <time dateTime={iso ?? undefined} title={iso ?? undefined} className="font-mono text-mono-sm">
      {relative(iso)}
    </time>
  );
}

// Status is a word plus a dot, never colour alone (DESIGN §3.5).
export function Status({ ok, yes, no }: { ok: boolean; yes: string; no: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-body">
      <span aria-hidden className={`size-1.5 rounded-full ${ok ? 'bg-mint-400' : 'bg-rose-400'}`} />
      {ok ? yes : no}
    </span>
  );
}

export function KeyValues({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid gap-x-8 gap-y-5 px-6 py-6 sm:grid-cols-2 lg:grid-cols-3">
      {items.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="label-stamp text-fg-subtle">{label}</dt>
          <dd className="mt-1.5 break-words text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="md"
      variant="secondary"
      icon={
        copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />
      }
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
    >
      {copied ? 'Copied' : label}
    </Button>
  );
}

// A secret or one-time link we can show exactly once.
export function ShownOnce({
  title,
  value,
  children,
}: {
  title: string;
  value: string;
  children?: ReactNode;
}) {
  return (
    <div className="mt-8 rounded-sm border border-border border-l-4 border-l-sun-400 bg-surface-2 px-5 py-4">
      <p className="text-body font-semibold text-fg">{title}</p>
      <p className="mt-1 text-body-sm text-fg-muted">
        {children ??
          'Copy it now. Handstamp keeps only an encrypted copy and will not show it again.'}
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <code className="min-w-0 flex-1 rounded-xs border border-border-input bg-surface-1 px-3 py-2 font-mono text-mono break-all text-fg">
          {value}
        </code>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="px-6 py-6 text-body-sm text-fg-muted">{children}</p>;
}
