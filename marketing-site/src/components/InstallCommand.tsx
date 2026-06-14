"use client";

import { useState } from "react";

type CopyState = "idle" | "copied" | "error";

type InstallCommandProps = {
  command: string;
  ariaLabel?: string;
  className?: string;
};

export function InstallCommand({
  command,
  ariaLabel = "Install command",
  className = "",
}: InstallCommandProps) {
  const [state, setState] = useState<CopyState>("idle");

  const handleCopy = async () => {
    if (!navigator.clipboard) {
      setState("error");
      window.setTimeout(() => setState("idle"), 2400);
      return;
    }
    try {
      await navigator.clipboard.writeText(command);
      setState("copied");
      window.setTimeout(() => setState("idle"), 1600);
    } catch {
      setState("error");
      window.setTimeout(() => setState("idle"), 2400);
    }
  };

  const buttonLabel =
    state === "copied" ? "Copied" : state === "error" ? "Copy failed" : "Copy";

  return (
    <div
      className={
        `flex w-full flex-col gap-2 rounded-xl border border-border bg-background-elevated p-1.5 shadow-sm sm:flex-row sm:items-center sm:gap-2 sm:pl-4 ` +
        className
      }
      aria-label={ariaLabel}
    >
      <div className="flex min-w-0 flex-1 items-center gap-2 overflow-x-auto px-3 py-1.5 sm:px-0">
        <span
          aria-hidden
          className="select-none font-mono text-sm text-foreground-subtle"
        >
          $
        </span>
        <code className="whitespace-nowrap font-mono text-sm text-foreground sm:text-[0.95rem]">
          {command}
        </code>
      </div>
      <button
        type="button"
        onClick={handleCopy}
        aria-label={
          state === "copied"
            ? "Install command copied"
            : state === "error"
              ? "Copy failed — select the command manually"
              : "Copy install command"
        }
        className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border border-transparent bg-pouch px-3 py-2 text-xs font-medium text-white transition-colors hover:bg-pouch-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-pouch focus-visible:ring-offset-2 focus-visible:ring-offset-background-elevated"
      >
        {buttonLabel}
      </button>
      <span role="status" aria-live="polite" className="sr-only">
        {state === "copied"
          ? "Install command copied to clipboard"
          : state === "error"
            ? "Copy failed — select the command manually"
            : ""}
      </span>
    </div>
  );
}
