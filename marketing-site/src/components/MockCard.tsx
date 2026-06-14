import type { ReactNode } from "react";

type Variant = "default" | "warning" | "success" | "accent";

type MockCardProps = {
  variant?: Variant;
  children: ReactNode;
  className?: string;
};

const variantClass: Record<Variant, string> = {
  default: "border-border bg-background-elevated",
  warning: "border-warning/30 bg-warning-soft",
  success: "border-success/30 bg-success-soft",
  accent: "border-accent/30 bg-accent-soft",
};

export function MockCard({
  variant = "default",
  children,
  className = "",
}: MockCardProps) {
  return (
    <div
      className={
        `rounded-2xl border p-4 shadow-sm ` +
        `${variantClass[variant]} ${className}`
      }
    >
      {children}
    </div>
  );
}
