"use client";

/**
 * The shared layout vocabulary.
 *
 * The product had one container — a large bordered card — and reached for it
 * whether it was framing a workflow or a single number. Fifteen of those on a
 * page flattens every hierarchy: the verdict and the collector duration get the
 * same box, so the analyst has to read everything to find anything.
 *
 * These are the alternatives. Headings, rows, aligned metadata, tables and
 * dividers carry structure without drawing a border around it; `Card` stays for
 * things that genuinely are separate objects. Everything is styled from
 * `globals.css` tokens so density is one decision, not a hundred inline values.
 */

import React from "react";

export type Status = "success" | "info" | "warning" | "danger" | "critical" | "neutral";

const STATUS_COLOR: Record<Status, string> = {
  success: "var(--status-success)",
  info: "var(--status-info)",
  warning: "var(--status-warning)",
  danger: "var(--status-danger)",
  critical: "var(--status-critical)",
  neutral: "var(--status-neutral)",
};

export function statusColor(status: Status): string {
  return STATUS_COLOR[status] || STATUS_COLOR.neutral;
}

/* ── Page shell ─────────────────────────────────────────────────────────── */

export function Page({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div className="ds-page" style={style}>
      {children}
    </div>
  );
}

/**
 * Title, one line of context, and the page's actions.
 *
 * `subtitle` is for what the page is *for*, when the title alone leaves it in
 * doubt — not for restating the title in a sentence. `meta` carries small
 * orienting facts (counts, window, last refresh) that used to each get a card.
 */
export function PageHeader({
  title,
  subtitle,
  meta,
  status,
  actions,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  meta?: React.ReactNode;
  status?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <header className="ds-page-header">
      <div style={{ minWidth: 0, flex: "1 1 420px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)", flexWrap: "wrap" }}>
          <h1 className="ds-page-header__title">{title}</h1>
          {status}
        </div>
        {subtitle ? <p className="ds-page-header__subtitle">{subtitle}</p> : null}
        {meta ? <div className="ds-page-header__meta">{meta}</div> : null}
      </div>
      {actions ? <div className="ds-page-header__actions">{actions}</div> : null}
    </header>
  );
}

/** A dot separator for header meta, so facts read as one line rather than a row of chips. */
export function MetaDot() {
  return <span aria-hidden="true">·</span>;
}

/* ── Sections ───────────────────────────────────────────────────────────── */

export function Section({
  title,
  hint,
  actions,
  children,
  as = "h2",
  style,
}: {
  title?: React.ReactNode;
  hint?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  as?: "h2" | "h3";
  style?: React.CSSProperties;
}) {
  const Heading = as;
  return (
    <section className="ds-section" style={style}>
      {title || actions ? (
        <div className="ds-section__header">
          <div style={{ minWidth: 0 }}>
            {title ? <Heading className="ds-section__title">{title}</Heading> : null}
            {hint ? <div className="ds-section__hint">{hint}</div> : null}
          </div>
          {actions ? <div className="ds-toolbar">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

/** Only for a genuinely distinct object, action or workflow — never per value. */
export function Card({
  children,
  flush = false,
  className,
  style,
}: {
  children: React.ReactNode;
  flush?: boolean;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <div className={`ds-card${flush ? " ds-card--flush" : ""}${className ? ` ${className}` : ""}`} style={style}>
      {children}
    </div>
  );
}

/* ── Status ─────────────────────────────────────────────────────────────── */

/**
 * Status as colour *and* words. Never colour alone — a red dot means nothing to
 * a screen reader or to anyone who cannot separate it from the green one.
 */
export function StatusBadge({
  status,
  children,
  dot = true,
  title,
}: {
  status: Status;
  children: React.ReactNode;
  dot?: boolean;
  title?: string;
}) {
  return (
    <span className="ds-badge" style={{ color: statusColor(status) }} title={title}>
      {dot ? <span className="ds-badge__dot" aria-hidden="true" /> : null}
      <span style={{ color: "var(--text-secondary)" }}>{children}</span>
    </span>
  );
}

/* ── Metrics ────────────────────────────────────────────────────────────── */

export type Metric = {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  status?: Status;
  href?: string;
};

/**
 * A few high-value numbers on one line.
 *
 * Replaces the grid of bordered stat cards. A metric earns its place only if it
 * changes what the analyst does next; anything else belongs in the content it
 * summarises.
 */
export function MetricStrip({ metrics, style }: { metrics: Metric[]; style?: React.CSSProperties }) {
  const shown = metrics.filter(Boolean);
  if (!shown.length) return null;
  return (
    <div className="ds-metrics" style={style}>
      {shown.map((metric) => {
        const body = (
          <>
            <div className="ds-metric__label">{metric.label}</div>
            <div
              className="ds-metric__value"
              style={metric.status ? { color: statusColor(metric.status) } : undefined}
            >
              {metric.value}
            </div>
            {metric.hint ? <div className="ds-metric__hint">{metric.hint}</div> : null}
          </>
        );
        return metric.href ? (
          <a key={metric.label} href={metric.href} style={{ textDecoration: "none", minWidth: 0 }}>
            {body}
          </a>
        ) : (
          <div key={metric.label} style={{ minWidth: 0 }}>
            {body}
          </div>
        );
      })}
    </div>
  );
}

/* ── Metadata ───────────────────────────────────────────────────────────── */

export type MetaItem = { label: string; value: React.ReactNode; mono?: boolean };

/** Aligned label/value pairs. A real definition list, so it reads as one. */
export function MetaList({ items, style }: { items: MetaItem[]; style?: React.CSSProperties }) {
  const shown = items.filter((item) => item && item.value !== null && item.value !== undefined && item.value !== "");
  if (!shown.length) return null;
  return (
    <dl className="ds-meta" style={style}>
      {shown.map((item) => (
        <div key={item.label} style={{ minWidth: 0 }}>
          <dt className="ds-meta__label">{item.label}</dt>
          <dd className="ds-meta__value" style={item.mono ? { fontFamily: "var(--font-mono)" } : undefined}>
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/* ── Progressive disclosure ─────────────────────────────────────────────── */

/**
 * Secondary detail, collapsed by default.
 *
 * Internal ids, exact timestamps, durations, model names and raw payloads go
 * here. Errors, missing evidence and anything that blocks a decision do not —
 * those stay visible whatever they do to the layout.
 */
export function Details({
  summary,
  children,
  open = false,
  style,
}: {
  summary: React.ReactNode;
  children: React.ReactNode;
  open?: boolean;
  style?: React.CSSProperties;
}) {
  return (
    <details className="ds-details" open={open} style={style}>
      <summary>{summary}</summary>
      <div className="ds-details__body">{children}</div>
    </details>
  );
}

/* ── States ─────────────────────────────────────────────────────────────── */

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: React.ReactNode;
  hint?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="ds-state">
      <div className="ds-state__title">{title}</div>
      {hint ? <div>{hint}</div> : null}
      {action}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="ds-state" role="status" aria-live="polite">
      <div className="ds-state__title">{label}</div>
    </div>
  );
}

/**
 * A failure the analyst has to know about.
 *
 * Loud enough not to be missed, quiet enough not to become the page. `partial`
 * is for "some of this worked" — the case a plain error banner tells you
 * nothing useful about.
 */
export function ErrorState({
  title,
  detail,
  action,
  partial = false,
}: {
  title: React.ReactNode;
  detail?: React.ReactNode;
  action?: React.ReactNode;
  partial?: boolean;
}) {
  const color = partial ? "var(--status-warning)" : "var(--status-danger)";
  return (
    <div
      role="alert"
      style={{
        display: "grid",
        gap: "var(--space-2)",
        justifyItems: "start",
        padding: "var(--space-3) var(--space-4)",
        borderLeft: `3px solid ${color}`,
        background: partial ? "rgba(251, 191, 36, 0.07)" : "rgba(251, 113, 133, 0.07)",
        borderRadius: "0 var(--shell-radius-sm) var(--shell-radius-sm) 0",
      }}
    >
      <div style={{ fontSize: "var(--font-body)", fontWeight: 700, color }}>{title}</div>
      {detail ? <div style={{ fontSize: "var(--font-meta)", color: "var(--text-secondary)" }}>{detail}</div> : null}
      {action}
    </div>
  );
}

/* ── Actions ────────────────────────────────────────────────────────────── */

export function Button({
  variant = "secondary",
  children,
  ...rest
}: {
  variant?: "primary" | "secondary" | "quiet" | "danger";
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const suffix =
    variant === "primary" ? " ds-btn--primary" : variant === "danger" ? " ds-btn--danger" : variant === "quiet" ? " ds-btn--quiet" : "";
  return (
    <button {...rest} className={`ds-btn${suffix}${rest.className ? ` ${rest.className}` : ""}`}>
      {children}
    </button>
  );
}

/**
 * Infrequent actions, behind one control.
 *
 * The alternative — every operation as its own button — makes the rare
 * destructive one exactly as prominent as the one used daily.
 */
export function OverflowMenu({
  label = "More actions",
  children,
}: {
  label?: string;
  children: React.ReactNode | ((close: () => void) => React.ReactNode);
}) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDown = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        type="button"
        className="ds-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        onClick={() => setOpen((value) => !value)}
      >
        ⋯
      </button>
      {open ? (
        <div
          role="menu"
          style={{
            position: "absolute",
            right: 0,
            top: "calc(100% + 4px)",
            zIndex: 30,
            minWidth: 200,
            padding: "var(--space-1)",
            display: "grid",
            gap: 2,
            border: "1px solid var(--panel-divider-strong)",
            borderRadius: "var(--shell-radius-md)",
            background: "var(--shell-surface-strong)",
            boxShadow: "var(--shadow-md)",
          }}
        >
          {typeof children === "function" ? children(() => setOpen(false)) : children}
        </div>
      ) : null}
    </div>
  );
}

export function MenuItem({
  children,
  danger = false,
  ...rest
}: { danger?: boolean } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      role="menuitem"
      className="ds-btn ds-btn--quiet"
      style={{
        justifyContent: "flex-start",
        width: "100%",
        color: danger ? "var(--red)" : "var(--text-secondary)",
        ...(danger ? { borderTop: "1px solid var(--panel-divider-soft)", borderRadius: 0, marginTop: 2 } : null),
        ...rest.style,
      }}
    >
      {children}
    </button>
  );
}

/** Destructive actions ask first, and say what will be lost. */
export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel = "Confirm",
  onConfirm,
  onCancel,
  busy = false,
}: {
  open: boolean;
  title: React.ReactNode;
  body?: React.ReactNode;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
}) {
  React.useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={typeof title === "string" ? title : "Confirm"}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        display: "grid",
        placeItems: "center",
        padding: "var(--space-4)",
        background: "rgba(4, 10, 18, 0.6)",
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <div
        style={{
          width: "min(440px, 100%)",
          display: "grid",
          gap: "var(--space-3)",
          padding: "var(--space-5)",
          border: "1px solid var(--panel-divider-strong)",
          borderRadius: "var(--shell-radius-xl)",
          background: "var(--shell-surface-strong)",
          boxShadow: "var(--shadow-lg)",
        }}
      >
        <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-strong)" }}>{title}</div>
        {body ? <div style={{ fontSize: "var(--font-meta)", color: "var(--text-secondary)" }}>{body}</div> : null}
        <div className="ds-toolbar" style={{ justifyContent: "flex-end" }}>
          <Button variant="quiet" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

/* ── Tables and lists ───────────────────────────────────────────────────── */

export type Column<T> = {
  key: string;
  header: React.ReactNode;
  render: (row: T) => React.ReactNode;
  width?: number | string;
  align?: "left" | "right";
};

/**
 * Comparable records, scanned down a column.
 *
 * Carries its own empty, loading and error states because a table that renders
 * nothing on failure is indistinguishable from one with no rows.
 */
export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  loading = false,
  error,
  empty = "Nothing to show.",
  onRowClick,
}: {
  caption?: string;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  loading?: boolean;
  error?: React.ReactNode;
  empty?: React.ReactNode;
  onRowClick?: (row: T) => void;
}) {
  if (loading) return <LoadingState />;
  if (error) return <ErrorState title="Could not load this list" detail={error} />;
  if (!rows.length) return <EmptyState title={empty} />;

  return (
    <div className="ds-table-wrap">
      <table className="ds-table">
        {caption ? <caption className="ds-sr-only">{caption}</caption> : null}
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} style={{ width: column.width, textAlign: column.align || "left" }} scope="col">
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={rowKey(row, index)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              style={onRowClick ? { cursor: "pointer" } : undefined}
            >
              {columns.map((column) => (
                <td key={column.key} style={{ textAlign: column.align || "left" }}>
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
