import { Fingerprint } from "./Fingerprint";
import { MockCard } from "./MockCard";
import { StatusBadge } from "./StatusBadge";

const PEER_FINGERPRINT = [
  "abandon",
  "ladder",
  "marble",
  "finger",
  "zebra",
  "rocket",
] as const;

export function TransferProgressMockup() {
  return (
    <MockCard className="flex flex-col gap-4 p-5">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-foreground-subtle">
          Sending to
        </span>
        <StatusBadge variant="accent">Encrypted</StatusBadge>
      </div>

      <div className="flex flex-col gap-2">
        <Fingerprint words={PEER_FINGERPRINT} size="sm" />

        <div className="flex items-baseline justify-between gap-3">
          <span className="font-mono text-sm text-foreground">
            roadmap-q3.pdf
          </span>
          <span className="font-mono text-xs text-foreground-subtle">
            12.4 MB
          </span>
        </div>

        <div
          className="h-2 w-full overflow-hidden rounded-full bg-background-sunken"
          role="progressbar"
          aria-valuenow={62}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Sending roadmap-q3.pdf, 62 percent complete"
        >
          <div
            className="h-full rounded-full bg-accent"
            style={{ width: "62%" }}
          />
        </div>

        <div className="flex items-center justify-between text-xs">
          <span className="text-foreground-muted">62% · 7.7 MB of 12.4 MB</span>
          <span className="font-mono text-foreground-subtle">
            chunk 124/200
          </span>
        </div>
      </div>
    </MockCard>
  );
}
