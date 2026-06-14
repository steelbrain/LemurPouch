import { MockCard } from "./MockCard";

type Line =
  | { kind: "prompt"; text: string }
  | { kind: "output"; text: string }
  | { kind: "ok"; text: string };

const LINES: readonly Line[] = [
  { kind: "prompt", text: "curl -fsSL https://lemurpouch.com/install.sh | sh" },
  { kind: "output", text: "Downloading lemur-pouch-darwin-arm64.tar.gz" },
  { kind: "output", text: "Verifying checksum" },
  {
    kind: "output",
    text: "Extracting to /Users/you/Library/Application Support/lemur-pouch",
  },
  { kind: "output", text: "Starting LemurPouch…" },
  { kind: "ok", text: "✓ Listening on :8080" },
  { kind: "output", text: "  http://192.168.1.42:8080/" },
  { kind: "output", text: "  http://[fe80::1c5:c1d2]:8080/" },
];

export function TerminalMockup() {
  return (
    <MockCard className="overflow-hidden p-0">
      <div className="flex items-center gap-1.5 border-b border-border bg-background-sunken px-4 py-2.5">
        <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-danger/70" />
        <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-warning/70" />
        <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-success/70" />
        <span className="ml-2 text-xs text-foreground-subtle">
          ~/lemur-pouch
        </span>
      </div>
      <pre className="w-full max-w-full overflow-x-auto px-4 py-4 font-mono text-xs leading-relaxed sm:text-sm">
        {LINES.map((line, idx) => (
          <div key={idx} className="flex gap-2">
            {line.kind === "prompt" ? (
              <>
                <span aria-hidden className="select-none text-foreground-subtle">
                  $
                </span>
                <span className="text-foreground">{line.text}</span>
              </>
            ) : line.kind === "ok" ? (
              <span className="text-success">{line.text}</span>
            ) : (
              <span className="text-foreground-muted">{line.text}</span>
            )}
          </div>
        ))}
      </pre>
    </MockCard>
  );
}
