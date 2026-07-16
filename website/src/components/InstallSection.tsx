import { InstallTabs } from "./InstallTabs";

export function InstallSection() {
  return (
    <section
      id="install"
      className="border-t border-border"
    >
      <div className="mx-auto w-full max-w-7xl px-6 py-20 lg:py-28">
        <div className="grid gap-12 lg:grid-cols-2 lg:gap-16">
          <div className="flex min-w-0 flex-col gap-4">
            <span className="text-xs font-semibold uppercase tracking-[0.18em] text-pouch-strong">
              Install
            </span>
            <h2 className="text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
              One command. Then anyone on your network can use it.
            </h2>
            <p className="text-base leading-relaxed text-foreground-muted sm:text-lg">
              Install on a laptop, a Pi, a NAS — anything reachable on the LAN
              that runs macOS, Linux, or Windows. The relay binds on{" "}
              <code className="font-mono text-foreground">:8080</code>, prints
              every URL it&rsquo;s reachable at, and waits for clients.
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
              <a
                href="https://github.com/steelbrain/LemurPouch/releases"
                className="font-medium text-accent hover:text-accent-strong hover:underline"
              >
                Download a binary directly →
              </a>
              <a
                href="https://github.com/steelbrain/LemurPouch#from-source"
                className="font-medium text-accent hover:text-accent-strong hover:underline"
              >
                Build from source →
              </a>
            </div>
          </div>

          <div className="min-w-0">
            <InstallTabs />
          </div>
        </div>
      </div>
    </section>
  );
}
