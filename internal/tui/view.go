package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/steelbrain/lemur-pouch/internal/client"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("13"))
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("13"))
	friendStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	pendingStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	statusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

func (m model) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("LemurPouch") + dimStyle.Render("  — connected as ") +
		friendStyle.Render(m.self.Fingerprint) + "\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("relay %s   downloads %s", m.relayURL, m.downloadDir)) + "\n\n")

	b.WriteString(headerStyle.Render("PEERS") + "\n")
	if len(m.peers) == 0 {
		b.WriteString(dimStyle.Render("  (no other peers connected yet)") + "\n")
	}
	for i, p := range m.peers {
		b.WriteString(m.renderPeerRow(i, p) + "\n")
	}

	b.WriteString("\n" + headerStyle.Render("TRANSFERS") + "\n")
	if len(m.xfers) == 0 {
		b.WriteString(dimStyle.Render("  (none yet)") + "\n")
	}
	for _, x := range m.xfers {
		b.WriteString("  " + renderXfer(x) + "\n")
	}

	b.WriteString("\n")
	if m.mode == modePath {
		b.WriteString(m.input.View() + "\n")
	} else {
		b.WriteString(statusStyle.Render(m.status) + "\n")
	}
	b.WriteString(helpStyle.Render(m.helpLine()))
	return b.String()
}

func (m model) renderPeerRow(i int, p client.PeerInfo) string {
	marker := "  "
	if i == m.cursor {
		marker = "> "
	}
	label := ""
	switch m.states[hexOf(p.Ed25519Pub)] {
	case peerFriend:
		label = friendStyle.Render(" [connected]")
	case peerInvited:
		label = pendingStyle.Render(" [invite sent]")
	case peerIncoming:
		label = pendingStyle.Render(" [wants to connect]")
	}
	row := fmt.Sprintf("%s%s  %s%s", marker, p.Fingerprint, dimStyle.Render(addr(p)), label)
	if i == m.cursor {
		// Re-render without inner styles so the highlight is uniform.
		plain := fmt.Sprintf("%s%s  %s%s", marker, p.Fingerprint, addr(p), stateLabel(m.states[hexOf(p.Ed25519Pub)]))
		return selectedStyle.Render(plain)
	}
	return row
}

func stateLabel(s peerState) string {
	switch s {
	case peerFriend:
		return " [connected]"
	case peerInvited:
		return " [invite sent]"
	case peerIncoming:
		return " [wants to connect]"
	default:
		return ""
	}
}

func renderXfer(x *xfer) string {
	arrow := "↑"
	if x.dir == client.Inbound {
		arrow = "↓"
	}
	switch x.status {
	case xferOffered:
		if x.dir == client.Inbound {
			return fmt.Sprintf("%s %s  offered (%s)", arrow, x.filename, humanBytes(x.total))
		}
		return fmt.Sprintf("%s %s  awaiting accept", arrow, x.filename)
	case xferActive:
		return fmt.Sprintf("%s %s  %s  %s", arrow, x.filename, pct(x.done, x.total), progress(x.done, x.total))
	case xferDone:
		if x.dir == client.Inbound {
			return friendStyle.Render(fmt.Sprintf("%s %s  done → %s", arrow, x.filename, x.detail))
		}
		return friendStyle.Render(fmt.Sprintf("%s %s  sent", arrow, x.filename))
	case xferFailed:
		return pendingStyle.Render(fmt.Sprintf("%s %s  failed: %s", arrow, x.filename, x.detail))
	}
	return x.filename
}

func (m model) helpLine() string {
	if m.disconnected {
		return "[q] quit"
	}
	if m.mode == modePath {
		return "[Enter] send   [Esc] cancel"
	}
	keys := "[↑/↓] move   [c] connect   [x] reject   [s] send file   [q] quit"
	if len(m.offers) > 0 {
		keys = "[a] accept offer   [r] reject offer   " + keys
	}
	return keys
}

func addr(p client.PeerInfo) string {
	if p.IP == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", p.IP, p.Port)
}

// shortFP keeps fingerprints readable in one-line status messages.
func shortFP(fp string) string {
	parts := strings.Split(fp, "-")
	if len(parts) <= 3 {
		return fp
	}
	return strings.Join(parts[:3], "-") + "-…"
}

func baseName(path string) string { return filepath.Base(path) }

// cleanPath makes a typed/pasted/drag-dropped file path forgiving:
//   - trims surrounding whitespace,
//   - strips one layer of matching single/double quotes,
//   - otherwise un-escapes shell-style backslash escapes (e.g. "\ " → " ")
//     on non-Windows (where backslash is not a path separator),
//   - expands a leading ~ to the user's home directory.
//
// Terminals insert backslash-escaped spaces when a file is dragged in, and
// users often paste quoted paths; without this, `stat` fails on the literal
// backslashes/quotes.
func cleanPath(raw string) string {
	s := strings.TrimSpace(raw)
	if l := len(s); l >= 2 && ((s[0] == '"' && s[l-1] == '"') || (s[0] == '\'' && s[l-1] == '\'')) {
		s = s[1 : l-1]
	} else if runtime.GOOS != "windows" {
		s = unescapeBackslashes(s)
	}
	return expandHome(s)
}

func unescapeBackslashes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func expandHome(s string) string {
	if s != "~" && !strings.HasPrefix(s, "~/") {
		return s
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return s
	}
	if s == "~" {
		return home
	}
	return filepath.Join(home, s[2:])
}

func pct(done, total int64) string {
	if total <= 0 {
		return "100%"
	}
	return fmt.Sprintf("%d%%", done*100/total)
}

func progress(done, total int64) string {
	return fmt.Sprintf("(%s / %s)", humanBytes(done), humanBytes(total))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
