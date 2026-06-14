import type { ReactNode } from "react";

type Variant =
  | "neutral"
  | "accent"
  | "success"
  | "warning"
  | "danger"
  | "pouch";

type StatusBadgeProps = {
  variant?: Variant;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
};

const variantClass: Record<Variant, string> = {
  neutral:
    "bg-background-sunken text-foreground-muted border-border/60",
  accent: "bg-accent-soft text-accent border-accent/20",
  success: "bg-success-soft text-success border-success/20",
  warning: "bg-warning-soft text-warning border-warning/20",
  danger: "bg-danger-soft text-danger border-danger/20",
  pouch: "bg-pouch-soft text-pouch-strong border-pouch/30",
};

export function StatusBadge({
  variant = "neutral",
  icon,
  children,
  className = "",
}: StatusBadgeProps) {
  return (
    <span
      className={
        `inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ` +
        `${variantClass[variant]} ${className}`
      }
    >
      {icon ? <span aria-hidden>{icon}</span> : null}
      {children}
    </span>
  );
}
