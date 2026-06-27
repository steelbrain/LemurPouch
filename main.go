package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/steelbrain/lemur-pouch/internal/client"
	"github.com/steelbrain/lemur-pouch/internal/cryptoid"
	"github.com/steelbrain/lemur-pouch/internal/relay"
	"github.com/steelbrain/lemur-pouch/internal/tui"
)

//go:embed all:web/dist
var distFS embed.FS

// connectTimeout bounds the relay handshake when launching the TUI client.
const connectTimeout = 15 * time.Second

// serveFn / connectFn are indirected so dispatch's routing can be unit-tested
// without starting a server or a terminal program.
var (
	serveFn   = runServe
	connectFn = runConnect
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

// dispatch parses args and routes to one of the three modes:
//
//	lemur-pouch              → print help
//	lemur-pouch --serve      → run the relay server (with --listen)
//	lemur-pouch --connect URL → launch the full-screen TUI client (with --out)
func dispatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lemur-pouch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printHelp(stderr) }

	serve := fs.Bool("serve", false, "run the relay server")
	connect := fs.String("connect", "", "connect to a relay as a TUI client (relay URL)")
	listen := fs.String("listen", ":8080", "relay bind address (host:port); only with --serve")
	out := fs.String("out", "", "directory to save received files in (default: current directory); only with --connect")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	switch {
	case *serve && *connect != "":
		fmt.Fprintln(stderr, "error: --serve and --connect are mutually exclusive")
		return 2
	case *serve:
		return serveFn(*listen, stderr)
	case *connect != "":
		return connectFn(*connect, *out, stdout, stderr)
	default:
		printHelp(stdout)
		return 0
	}
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `LemurPouch — a LAN file-sharing relay (lemurpouch.com)

Usage:
  lemur-pouch                  Show this help.
  lemur-pouch --serve          Run the relay server on this machine.
  lemur-pouch --connect URL    Connect to a relay as a full-screen TUI client.

Serve options:
  --serve                Run the relay (serves the web client and the /ws endpoint).
  --listen host:port     Bind address (default ":8080").
                           :8080            all interfaces, port 8080
                           127.0.0.1:8080   localhost only
                           192.168.1.5:80   one specific interface IP

Connect options (native client — no browser, low memory/CPU):
  --connect URL          Relay URL to connect to, e.g. http://192.168.1.5:8080/
                         (http/https or ws/wss accepted; /ws is added automatically).
  --out DIR              Directory to save received files in (default: current directory).

In the TUI: ↑/↓ move, [c] connect to a peer, [s] send a file (you'll enter a
path), [a]/[r] accept or reject an incoming file, [q] quit. Verify a peer by
their six-word fingerprint before connecting.

Examples:
  lemur-pouch --serve --listen 0.0.0.0:8080
  lemur-pouch --connect http://192.168.1.5:8080/ --out ~/Downloads
`)
}

// runConnect generates a session identity, connects to the relay, and runs the
// full-screen TUI. Returns a process exit code.
func runConnect(rawURL, outDir string, stdout, stderr io.Writer) int {
	if outDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "error: could not determine working directory: %v\n", err)
			return 1
		}
		outDir = wd
	}
	info, err := os.Stat(outDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: download directory %q: %v\n", outDir, err)
		return 1
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "error: download directory %q is not a directory\n", outDir)
		return 1
	}

	id, err := cryptoid.GenerateIdentity()
	if err != nil {
		fmt.Fprintf(stderr, "error: generate identity: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Your fingerprint: %s\n", cryptoid.Fingerprint(id.Ed25519Pub))
	fmt.Fprintf(stdout, "Connecting to %s …\n", rawURL)

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	c, err := client.Connect(ctx, rawURL, id, outDir)
	cancel()
	if err != nil {
		fmt.Fprintf(stderr, "error: connect to relay: %v\n", err)
		return 1
	}
	if err := tui.Run(c, rawURL); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// runServe starts the relay HTTP+WebSocket server and blocks. Returns a
// process exit code.
func runServe(listenAddr string, stderr io.Writer) int {
	hub := relay.NewHub()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", relay.HandleWebSocket(hub))

	staticFS, err := fs.Sub(distFS, "web/dist")
	if err != nil {
		fmt.Fprintf(stderr, "error: derive web/dist sub-FS: %v\n", err)
		return 1
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logReachableURLs(listenAddr)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "error: server error: %v\n", err)
		return 1
	}
	return 0
}

// logReachableURLs prints the URLs the relay is reachable at, given
// the configured listen address.
//
// For wildcard binds (the default ":8080", or explicit "0.0.0.0:..."
// or "[::]:..."), it enumerates every non-loopback, non-link-local
// interface IP and prints a URL per address — so a user starting the
// relay on a laptop sees the LAN IPs they should give to other
// participants without having to dig through `ifconfig` / `ip addr`.
//
// For specific binds (e.g. "127.0.0.1:8080" or "192.168.1.5:8080"),
// it prints only that one URL, since other addresses won't reach the
// listener anyway.
func logReachableURLs(listen string) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		log.Printf("could not parse --listen %q: %v", listen, err)
		return
	}

	log.Printf("relay listening on %s — reachable at:", listen)

	if !isWildcard(host) {
		// Specific bind — only that address is reachable.
		log.Printf("  http://%s/", net.JoinHostPort(host, port))
		return
	}

	// Wildcard bind. Always print localhost (the local user's URL),
	// then enumerate every interface IP for LAN/peer access.
	log.Printf("  http://localhost:%s/   (this machine)", port)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("could not enumerate interface addresses: %v", err)
		return
	}

	var v4, v6 []net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		// Skip loopback (already covered by the localhost line above)
		// and link-local addresses. Link-local IPv6 (fe80::/10)
		// requires a zone-id suffix in URLs ("[fe80::1%eth0]"), which
		// is awkward and rarely useful for cross-machine LAN sharing.
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	// Stable order: IPv4 first (more familiar to LAN users), then
	// IPv6. Sort within each family so the output is deterministic
	// across runs even if the OS reorders interfaces.
	sort.Slice(v4, func(i, j int) bool { return v4[i].String() < v4[j].String() })
	sort.Slice(v6, func(i, j int) bool { return v6[i].String() < v6[j].String() })

	for _, ip := range v4 {
		log.Printf("  http://%s/", net.JoinHostPort(ip.String(), port))
	}
	for _, ip := range v6 {
		// JoinHostPort brackets IPv6 literals automatically, producing
		// the URL-safe "http://[2001:db8::1]:8080/" form.
		log.Printf("  http://%s/", net.JoinHostPort(ip.String(), port))
	}

	if len(v4)+len(v6) == 0 {
		log.Printf("  (no non-loopback interfaces detected — only the localhost URL works)")
	}

	// Inside a container the IPs above are container-internal (bridge
	// addresses like 172.x.x.x) and aren't reachable from the host's
	// LAN. Print a hint so users running `docker run -p 8080:8080 …`
	// know to navigate to their HOST's LAN IP instead.
	//
	// Detection is via the LEMURPOUCH_IN_CONTAINER env var, which the
	// project's Dockerfile sets explicitly. We deliberately don't
	// probe /.dockerenv: that would also fire for users who built a
	// custom container around the binary (or `docker cp`-ed it out
	// and re-ran it elsewhere). A binary that doesn't see this var
	// stays quiet and lets the URLs speak for themselves.
	if os.Getenv("LEMURPOUCH_IN_CONTAINER") != "" {
		log.Printf("  (running in a container — those interface IPs are container-internal;")
		log.Printf("   reach the relay from other LAN hosts via your host's LAN IP)")
	}
}

// isWildcard reports whether host designates "all interfaces" — either
// the empty string (Go's :PORT shorthand) or the unspecified IP
// literal in either family (0.0.0.0 / ::).
func isWildcard(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsUnspecified()
}
