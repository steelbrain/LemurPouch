import { Fingerprint } from "./Fingerprint";
import { MockCard } from "./MockCard";
import { StatusBadge } from "./StatusBadge";

const SELF_FINGERPRINT = [
  "tide",
  "quantum",
  "velvet",
  "tribe",
  "yellow",
  "orchard",
] as const;

type PeerRow = {
  fingerprint: readonly string[];
  ip: string;
  port: number;
  status: "friend" | "stranger";
};

const PEERS: readonly PeerRow[] = [
  {
    fingerprint: ["abandon", "ladder", "marble", "finger", "zebra", "rocket"],
    ip: "192.168.1.21",
    port: 51422,
    status: "friend",
  },
  {
    fingerprint: ["forest", "narrow", "coast", "meadow", "piano", "walnut"],
    ip: "192.168.1.34",
    port: 49810,
    status: "stranger",
  },
];

export function PeerListMockup() {
  return (
    <MockCard className="flex flex-col gap-0 p-0">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2">
          <span
            aria-hidden
            className="inline-block h-2 w-2 rounded-full bg-success"
          />
          <span className="text-xs font-medium text-foreground-muted">
            LemurPouch · running on the LAN
          </span>
        </div>
        <span className="font-mono text-xs text-foreground-subtle">:8080</span>
      </div>

      <section className="flex flex-col gap-2 px-5 py-4">
        <span className="text-xs font-medium uppercase tracking-wide text-foreground-subtle">
          This device
        </span>
        <Fingerprint words={SELF_FINGERPRINT} size="sm" />
        <span className="font-mono text-xs text-foreground-subtle">
          192.168.1.42 :54088
        </span>
      </section>

      <section className="flex flex-col gap-3 border-t border-border px-5 py-4">
        <header className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wide text-foreground-subtle">
            Peers nearby
          </span>
          <StatusBadge variant="neutral">{PEERS.length}</StatusBadge>
        </header>

        <ul className="flex flex-col gap-3">
          {PEERS.map((peer) => (
            <li
              key={peer.ip}
              className="flex items-start justify-between gap-3"
            >
              <div className="flex min-w-0 flex-col gap-1">
                <Fingerprint words={peer.fingerprint} size="sm" />
                <span className="font-mono text-xs text-foreground-subtle">
                  {peer.ip} :{peer.port}
                </span>
              </div>
              {peer.status === "friend" ? (
                <StatusBadge
                  variant="success"
                  icon={
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-success" />
                  }
                >
                  Friend
                </StatusBadge>
              ) : (
                <StatusBadge variant="pouch">Send invite</StatusBadge>
              )}
            </li>
          ))}
        </ul>
      </section>
    </MockCard>
  );
}
