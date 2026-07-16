"use client";

import {
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { InstallCommand } from "./InstallCommand";

type TabDef = {
  id: string;
  label: string;
  command: string;
  note?: ReactNode;
};

const TABS: readonly TabDef[] = [
  {
    id: "unix",
    label: "macOS / Linux",
    command: "curl -fsSL https://lemurpouch.com/install.sh | sh",
    note: (
      <>
        Verifies the SHA-256 of the release before running. Installs to{" "}
        <code className="font-mono text-foreground">~/.local/bin</code>, then
        opens the picker (Start a relay / Connect to a relay). Re-runs are
        idempotent. Skip the picker with{" "}
        <code className="font-mono text-foreground">… | sh -s -- --serve</code>{" "}
        or{" "}
        <code className="font-mono text-foreground">
          … | sh -s -- --connect http://HOST:8080/
        </code>
        .
      </>
    ),
  },
  {
    id: "windows",
    label: "Windows",
    command: "irm https://lemurpouch.com/install.ps1 | iex",
    note: (
      <>
        PowerShell. Verifies the SHA-256 before running. Installs to{" "}
        <code className="font-mono text-foreground">~/.local/bin</code>, then
        opens the picker. Re-runs are idempotent.{" "}
        <code className="font-mono text-foreground">irm | iex</code> cannot
        forward args — save the script and run with{" "}
        <code className="font-mono text-foreground">--serve</code> or{" "}
        <code className="font-mono text-foreground">
          --connect http://HOST:8080/
        </code>{" "}
        to skip the picker.
      </>
    ),
  },
  {
    id: "docker",
    label: "Docker",
    command:
      "docker run --rm -p 8080:8080 ghcr.io/steelbrain/lemurpouch:latest",
    note: (
      <>
        Multi-platform image: linux/amd64, linux/arm64, windows/amd64.
        <span className="mt-2 block text-foreground-subtle">
          On macOS with OrbStack, container ports bind only to 127.0.0.1 — LAN
          devices won&rsquo;t reach the relay. Use the binary install above, or
          Docker Desktop / colima.
        </span>
      </>
    ),
  },
];

export function InstallTabs() {
  const baseId = useId();
  const [activeIdx, setActiveIdx] = useState(0);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const focusTab = (idx: number) => {
    setActiveIdx(idx);
    tabRefs.current[idx]?.focus();
  };

  const handleKey = (event: KeyboardEvent<HTMLButtonElement>, idx: number) => {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      focusTab((idx + 1) % TABS.length);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      focusTab((idx - 1 + TABS.length) % TABS.length);
    } else if (event.key === "Home") {
      event.preventDefault();
      focusTab(0);
    } else if (event.key === "End") {
      event.preventDefault();
      focusTab(TABS.length - 1);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <div
        role="tablist"
        aria-label="Install methods"
        className="inline-flex w-fit max-w-full overflow-x-auto rounded-xl border border-border bg-background-elevated p-1"
      >
        {TABS.map((tab, idx) => {
          const selected = idx === activeIdx;
          return (
            <button
              key={tab.id}
              ref={(el) => {
                tabRefs.current[idx] = el;
              }}
              role="tab"
              type="button"
              id={`${baseId}-tab-${tab.id}`}
              aria-controls={`${baseId}-panel-${tab.id}`}
              aria-selected={selected}
              tabIndex={selected ? 0 : -1}
              onClick={() => setActiveIdx(idx)}
              onKeyDown={(event) => handleKey(event, idx)}
              className={
                `whitespace-nowrap rounded-lg px-4 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-pouch focus-visible:ring-offset-2 focus-visible:ring-offset-background-elevated ` +
                (selected
                  ? "bg-pouch-soft text-pouch-strong"
                  : "text-foreground-muted hover:text-foreground")
              }
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {TABS.map((tab, idx) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={`${baseId}-panel-${tab.id}`}
          aria-labelledby={`${baseId}-tab-${tab.id}`}
          hidden={idx !== activeIdx}
          className="flex flex-col gap-3"
        >
          <InstallCommand
            command={tab.command}
            ariaLabel={`${tab.label} install command`}
          />
          {tab.note ? (
            <p className="text-sm leading-relaxed text-foreground-muted">
              {tab.note}
            </p>
          ) : null}
        </div>
      ))}
    </div>
  );
}
