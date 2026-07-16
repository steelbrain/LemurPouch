import { Fingerprint } from "./Fingerprint";
import { MockCard } from "./MockCard";

const WORDS = [
  "abandon",
  "ladder",
  "marble",
  "finger",
  "zebra",
  "rocket",
] as const;

export function FingerprintMatch() {
  return (
    <MockCard className="flex flex-col gap-4 p-5">
      <div className="flex flex-col gap-1.5">
        <span className="text-xs font-medium uppercase tracking-wide text-foreground-subtle">
          Your laptop sees
        </span>
        <Fingerprint words={WORDS} size="md" />
      </div>

      <div className="flex items-center gap-3 text-xs font-medium text-success">
        <span
          aria-hidden
          className="flex h-6 w-6 items-center justify-center rounded-full bg-success-soft"
        >
          <svg
            viewBox="0 0 16 16"
            className="h-3 w-3"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M3 8.5l3.5 3.5L13 5" />
          </svg>
        </span>
        <span>Same six words → friend confirmed</span>
      </div>

      <div className="flex flex-col gap-1.5">
        <span className="text-xs font-medium uppercase tracking-wide text-foreground-subtle">
          Your phone sees
        </span>
        <Fingerprint words={WORDS} size="md" />
      </div>
    </MockCard>
  );
}
