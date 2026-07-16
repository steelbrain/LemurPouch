import Image from "next/image";
import { Features } from "@/components/Features";
import { HowItWorks } from "@/components/HowItWorks";
import { InstallCommand } from "@/components/InstallCommand";
import { InstallSection } from "@/components/InstallSection";
import { PeerListMockup } from "@/components/PeerListMockup";
import { ThemeToggle } from "@/components/ThemeToggle";
import { TrustModel } from "@/components/TrustModel";

const TRUST_SIGNALS = [
  "MIT licensed",
  "Relay for macOS, Linux, Windows",
  "No accounts",
  "No telemetry",
  "Session-only",
];

export default function Home() {
  return (
    <div className="flex flex-1 flex-col bg-background text-foreground">
      <main className="flex-1">
        <section className="relative overflow-hidden">
          <div aria-hidden className="hero-glow" />
          <div className="relative mx-auto w-full max-w-7xl px-6">
            <div className="flex items-center justify-between pt-6">
              <div className="flex items-center gap-3">
                <Image
                  src="/logo.png"
                  alt=""
                  width={56}
                  height={56}
                  priority
                  className="h-12 w-12 rounded-2xl shadow-sm sm:h-14 sm:w-14"
                />
                <span className="text-base font-semibold tracking-tight text-foreground">
                  LemurPouch
                </span>
              </div>
              <ThemeToggle />
            </div>
          </div>
          <div className="relative mx-auto grid w-full max-w-7xl items-center gap-12 px-6 pt-6 pb-24 lg:grid-cols-[1.4fr_1fr] lg:gap-16 lg:pt-10">
            <div className="flex min-w-0 flex-col items-start">
              <h1 className="text-4xl font-semibold leading-tight tracking-tight text-foreground sm:text-5xl">
                End-to-end encrypted file sharing that{" "}
                <span className="text-pouch-strong">never leaves your network</span>.
              </h1>

              <p className="mt-6 max-w-2xl text-lg leading-relaxed text-foreground-muted">
                Run the relay on any LAN machine. Anyone on your network opens
                it in a browser, verifies a six-word fingerprint, and sends.
                Files never touch the cloud — and the relay routes opaque
                ciphertext it can&rsquo;t read.
              </p>

              <div className="mt-10 w-full max-w-2xl">
                <InstallCommand command="curl -fsSL https://lemurpouch.com/install.sh | sh" />
                <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-foreground-muted">
                  <span>Installs the relay. Clients just open a URL.</span>
                  <a
                    href="https://github.com/steelbrain/LemurPouch"
                    className="font-medium text-accent hover:text-accent-strong hover:underline"
                  >
                    View on GitHub →
                  </a>
                </div>
              </div>

              <ul className="mt-8 flex flex-wrap items-center gap-y-1 text-xs text-foreground-subtle">
                {TRUST_SIGNALS.map((signal, idx) => (
                  <li key={signal} className="flex items-center">
                    <span>{signal}</span>
                    {idx < TRUST_SIGNALS.length - 1 ? (
                      <span
                        aria-hidden
                        className="mx-2 text-foreground-subtle/60"
                      >
                        ·
                      </span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>

            <div className="relative min-w-0 w-full lg:justify-self-end">
              <div
                aria-hidden
                className="absolute -inset-4 rounded-3xl bg-pouch-soft blur-2xl"
              />
              <div className="relative">
                <PeerListMockup />
              </div>
            </div>
          </div>
        </section>

        <HowItWorks />
        <Features />
        <TrustModel />
        <InstallSection />
      </main>

      <footer className="border-t border-border bg-background-sunken/40">
        <div className="mx-auto w-full max-w-7xl px-6 py-12">
          <div className="flex flex-col gap-8 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2.5">
                <Image
                  src="/logo.png"
                  alt=""
                  width={32}
                  height={32}
                  className="h-7 w-7 rounded-lg"
                />
                <span className="text-sm font-semibold text-foreground">
                  LemurPouch
                </span>
              </div>
              <p className="max-w-sm text-sm leading-relaxed text-foreground-muted">
                End-to-end encrypted LAN file sharing that runs on the network
                you&rsquo;ve got.
              </p>
            </div>

            <nav
              aria-label="Project links"
              className="grid grid-cols-2 gap-x-10 gap-y-2 text-sm sm:gap-x-12"
            >
              <a
                href="https://github.com/steelbrain/LemurPouch"
                className="text-foreground-muted hover:text-foreground"
              >
                Source
              </a>
              <a
                href="https://github.com/steelbrain/LemurPouch/releases"
                className="text-foreground-muted hover:text-foreground"
              >
                Releases
              </a>
              <a
                href="https://github.com/steelbrain/LemurPouch/issues"
                className="text-foreground-muted hover:text-foreground"
              >
                Issues
              </a>
              <a
                href="https://github.com/steelbrain/LemurPouch/blob/main/LICENSE.md"
                className="text-foreground-muted hover:text-foreground"
              >
                MIT license
              </a>
            </nav>
          </div>

          <div className="mt-10 flex flex-col gap-2 border-t border-border pt-6 text-xs text-foreground-subtle sm:flex-row sm:items-center sm:justify-between">
            <p>
              © {new Date().getFullYear()} LemurPouch · Open source under the
              MIT license.
            </p>
            <p>
              Made with{" "}
              <span aria-hidden className="text-pouch-strong">
                ♥
              </span>
              <span className="sr-only">love</span> by{" "}
              <a
                href="https://aneesiqbal.ai"
                className="text-foreground-muted hover:text-foreground hover:underline"
              >
                Anees Iqbal @steelbrain
              </a>
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
