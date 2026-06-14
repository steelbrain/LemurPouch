type Item = {
  text: string;
  detail?: string;
};

const SEES: readonly Item[] = [
  {
    text: "Routing identities",
    detail:
      "Source and destination Ed25519 public keys, so envelopes reach the right peer.",
  },
  {
    text: "Approximate volume and timing",
    detail: "Bytes through the relay are bytes the relay can count.",
  },
  {
    text: "Friendship-control bits",
    detail: "invite / accept / reject — needed to enforce two-tier consent.",
  },
  {
    text: "Source IP and ephemeral port",
    detail: "Used for per-IP rate limiting and the discovery row.",
  },
];

const NEVER_SEES: readonly Item[] = [
  {
    text: "Filenames and file sizes",
    detail: "Encrypted inside the transfer offer.",
  },
  { text: "File contents", detail: "Streamed as opaque ciphertext chunks." },
  {
    text: "Per-transfer accept or reject",
    detail: "Carried inside encrypted envelopes after friendship.",
  },
  {
    text: "Accounts, cookies, or display names",
    detail: "No registration, no analytics — just session-scoped keys.",
  },
];

function TrustList({
  items,
  variant,
}: {
  items: readonly Item[];
  variant: "sees" | "never";
}) {
  const isSees = variant === "sees";
  return (
    <ul className="flex flex-col gap-4">
      {items.map((item) => (
        <li key={item.text} className="flex items-start gap-3">
          <span
            aria-hidden
            className={
              `mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ` +
              (isSees
                ? "bg-background-sunken text-foreground-muted"
                : "bg-success-soft text-success")
            }
          >
            <svg
              viewBox="0 0 16 16"
              className="h-3 w-3"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden
            >
              {isSees ? (
                <path d="M4 8h8" />
              ) : (
                <path d="M4 8.5l3 3 5-6" />
              )}
            </svg>
          </span>
          <div className="flex flex-col gap-0.5">
            <span className="text-sm font-medium text-foreground">
              {item.text}
            </span>
            {item.detail ? (
              <span className="text-sm leading-relaxed text-foreground-muted">
                {item.detail}
              </span>
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function TrustModel() {
  return (
    <section className="relative border-t border-border bg-background-sunken/40">
      <div className="mx-auto w-full max-w-7xl px-6 py-20 lg:py-28">
        <div className="max-w-2xl">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-pouch-strong">
            Trust model
          </span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            What the relay sees, and what it never sees.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-foreground-muted sm:text-lg">
            The relay routes envelopes; it does not read them. Trust is rooted
            in the six-word fingerprint humans verify out-of-band — not in the
            relay.
          </p>
        </div>

        <div className="mt-14 grid grid-cols-1 gap-6 lg:grid-cols-2 lg:gap-10">
          <article className="rounded-2xl border border-border bg-background-elevated p-7">
            <header className="mb-5 flex items-center gap-3">
              <span
                aria-hidden
                className="inline-block h-2 w-2 rounded-full bg-foreground-muted"
              />
              <h3 className="text-sm font-semibold uppercase tracking-wide text-foreground-muted">
                The relay sees
              </h3>
            </header>
            <TrustList items={SEES} variant="sees" />
          </article>

          <article className="rounded-2xl border border-success/30 bg-success-soft p-7">
            <header className="mb-5 flex items-center gap-3">
              <span
                aria-hidden
                className="inline-block h-2 w-2 rounded-full bg-success"
              />
              <h3 className="text-sm font-semibold uppercase tracking-wide text-success">
                The relay never sees
              </h3>
            </header>
            <TrustList items={NEVER_SEES} variant="never" />
          </article>
        </div>
      </div>
    </section>
  );
}
