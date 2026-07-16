import type { ReactNode } from "react";
import { FingerprintMatch } from "./FingerprintMatch";
import { TerminalMockup } from "./TerminalMockup";
import { TransferProgressMockup } from "./TransferProgressMockup";

type Step = {
  number: string;
  title: string;
  body: string;
  visual: ReactNode;
};

const STEPS: readonly Step[] = [
  {
    number: "01",
    title: "Install the relay, once",
    body:
      "One curl on any Mac, Linux, or Windows machine on your network. The binary verifies its own checksum, picks a sensible install path, and starts listening on :8080. That's the only setup.",
    visual: <TerminalMockup />,
  },
  {
    number: "02",
    title: "Verify six words",
    body:
      "Each device generates its identity locally in the browser and renders it as a six-word BIP-39 fingerprint. Read it aloud across the room or across the call to confirm — humans verify identity, not the relay.",
    visual: <FingerprintMatch />,
  },
  {
    number: "03",
    title: "Send the file",
    body:
      "Drag a file in, the receiver accepts the offer, and bytes flow through the relay as opaque ciphertext it can't read. Filenames, sizes, and content stay on your network.",
    visual: <TransferProgressMockup />,
  },
];

export function HowItWorks() {
  return (
    <section className="relative border-t border-border bg-background-sunken/40">
      <div className="mx-auto w-full max-w-7xl px-6 py-20 lg:py-28">
        <div className="max-w-2xl">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-pouch-strong">
            How it works
          </span>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Three steps, no accounts.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-foreground-muted sm:text-lg">
            Set up once on the LAN, then any browser on the network can send
            files end-to-end encrypted. No app, no extension, nothing to
            install on the senders or receivers.
          </p>
        </div>

        <ol className="mt-14 flex flex-col gap-16 lg:gap-20">
          {STEPS.map((step, idx) => (
            <li
              key={step.number}
              className="grid min-w-0 items-center gap-8 lg:grid-cols-2 lg:gap-14"
            >
              <div
                className={
                  "min-w-0 " +
                  (idx % 2 === 0 ? "lg:order-1" : "lg:order-2")
                }
              >
                <span
                  aria-hidden
                  className="font-mono text-sm font-medium text-pouch-strong"
                >
                  {step.number}
                </span>
                <h3 className="mt-2 text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
                  {step.title}
                </h3>
                <p className="mt-3 text-base leading-relaxed text-foreground-muted">
                  {step.body}
                </p>
              </div>
              <div
                className={
                  "min-w-0 " +
                  (idx % 2 === 0 ? "lg:order-2" : "lg:order-1")
                }
              >
                {step.visual}
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
