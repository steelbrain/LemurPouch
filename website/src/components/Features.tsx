import type { ReactNode } from "react";

type Feature = {
  title: string;
  body: string;
  icon: ReactNode;
};

const iconClass = "h-5 w-5";
const iconStroke = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

const FEATURES: readonly Feature[] = [
  {
    title: "End-to-end encrypted",
    body:
      "XChaCha20-Poly1305 with X25519 ECDH session keys, bound to Ed25519 identities. The relay forwards opaque ciphertext it cannot read.",
    icon: (
      <svg viewBox="0 0 24 24" className={iconClass} {...iconStroke}>
        <rect x="5" y="11" width="14" height="9" rx="2" />
        <path d="M8 11V8a4 4 0 0 1 8 0v3" />
      </svg>
    ),
  },
  {
    title: "Works on locked-down networks",
    body:
      "Plain outbound WebSocket over TCP. No WebRTC, no UDP, no STUN, no inbound ports — runs through corporate firewalls that break everything else.",
    icon: (
      <svg viewBox="0 0 24 24" className={iconClass} {...iconStroke}>
        <path d="M3 8h18M3 16h18M3 8v8M21 8v8M3 12h18M9 8v4M15 12v4" />
      </svg>
    ),
  },
  {
    title: "Nothing to install on clients",
    body:
      "The relay is one curl on any LAN machine. From there, every sender and receiver just opens a URL — no app, no extension, no account.",
    icon: (
      <svg viewBox="0 0 24 24" className={iconClass} {...iconStroke}>
        <rect x="3" y="5" width="18" height="14" rx="2" />
        <path d="M3 9h18" />
        <circle cx="6.5" cy="7" r="0.5" fill="currentColor" stroke="none" />
        <circle cx="8.5" cy="7" r="0.5" fill="currentColor" stroke="none" />
        <circle cx="10.5" cy="7" r="0.5" fill="currentColor" stroke="none" />
      </svg>
    ),
  },
  {
    title: "Two-tier consent",
    body:
      "Friendship is mutually established once per session; every individual file transfer still needs an explicit accept. Either side can refuse at any point.",
    icon: (
      <svg viewBox="0 0 24 24" className={iconClass} {...iconStroke}>
        <circle cx="9" cy="12" r="5" />
        <circle cx="15" cy="12" r="5" />
      </svg>
    ),
  },
  {
    title: "Session-only state",
    body:
      "Identities, friendships, transfers — all in relay memory, all session-scoped. Restart the relay and it's a clean slate. No database, no logs of content.",
    icon: (
      <svg viewBox="0 0 24 24" className={iconClass} {...iconStroke}>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </svg>
    ),
  },
  {
    title: "Single binary, cross-platform",
    body:
      "macOS, Linux, and Windows on amd64 and arm64 — plus a multi-platform Docker image. The frontend is embedded in the binary; one file is the whole product.",
    icon: (
      <svg viewBox="0 0 24 24" className={iconClass} {...iconStroke}>
        <rect x="3" y="6" width="18" height="11" rx="1.5" />
        <path d="M9 21h6M12 17v4" />
      </svg>
    ),
  },
];

export function Features() {
  return (
    <section className="border-t border-border">
      <div className="mx-auto w-full max-w-7xl px-6 py-20 lg:py-28">
        <div className="max-w-2xl">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-pouch-strong">
            What you get
          </span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Built for the network you&rsquo;ve got, not the one you wish you had.
          </h2>
        </div>

        <ul className="mt-12 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3 lg:gap-6">
          {FEATURES.map((feature) => (
            <li
              key={feature.title}
              className="flex flex-col gap-3 rounded-2xl border border-border bg-background-elevated p-6"
            >
              <span
                aria-hidden
                className="flex h-10 w-10 items-center justify-center rounded-xl bg-pouch-soft text-pouch-strong"
              >
                {feature.icon}
              </span>
              <h3 className="text-base font-semibold text-foreground">
                {feature.title}
              </h3>
              <p className="text-sm leading-relaxed text-foreground-muted">
                {feature.body}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
