// Package tui implements the full-screen terminal client for LemurPouch. It
// is a thin view layer over internal/client: the client owns all protocol
// state and emits events; this package renders them and translates key
// presses into client command calls. Running it replaces the browser as the
// daemon for users who want a low-overhead native client.
package tui

import (
	"encoding/hex"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/steelbrain/lemur-pouch/internal/client"
)

type peerState int

const (
	peerNone     peerState = iota // discovered, no relationship
	peerInvited                   // we sent an invite, awaiting their decision
	peerIncoming                  // they invited us, awaiting our decision
	peerFriend                    // mutual friendship established
)

type uiMode int

const (
	modeNormal uiMode = iota
	modePath          // entering a file path to send
)

type xferStatus int

const (
	xferOffered xferStatus = iota
	xferActive
	xferDone
	xferFailed
)

// xfer is the display state of a single transfer.
type xfer struct {
	id       string
	dir      client.Direction
	filename string
	status   xferStatus
	done     int64
	total    int64
	detail   string // path on done, reason on failed
}

type model struct {
	client      *client.Client
	self        client.PeerInfo
	relayURL    string
	downloadDir string

	width, height int

	peers  []client.PeerInfo
	states map[string]peerState
	cursor int

	xfers    []*xfer
	xferByID map[string]*xfer

	offers []client.TransferOfferReceived // pending incoming offers (decision queue)

	mode       uiMode
	input      textinput.Model
	sendTarget string // hex ed25519 of the peer we're composing a send to

	status        string
	disconnected  bool
	disconnectErr error
}

// eventMsg wraps a client event for the bubbletea update loop.
type eventMsg struct{ ev client.Event }

// Run starts the full-screen TUI over an already-connected client and blocks
// until the user quits. It closes the client on exit.
func Run(c *client.Client, relayURL string) error {
	m := newModel(c, relayURL)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	c.Close()
	return err
}

func newModel(c *client.Client, relayURL string) model {
	ti := textinput.New()
	ti.Placeholder = "/path/to/file"
	ti.CharLimit = 4096
	ti.Prompt = "send file: "
	return model{
		client:      c,
		self:        c.Self(),
		relayURL:    relayURL,
		downloadDir: c.DownloadDir(),
		states:      make(map[string]peerState),
		xferByID:    make(map[string]*xfer),
		input:       ti,
		status:      "Use ↑/↓ to move, [c]onnect, [s]end, [q]uit.",
	}
}

func (m model) Init() tea.Cmd {
	return waitForEvent(m.client)
}

// waitForEvent blocks on the next client event and delivers it as a message.
func waitForEvent(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-c.Events()
		if !ok {
			return nil
		}
		return eventMsg{ev}
	}
}

func hexOf(ed []byte) string { return hex.EncodeToString(ed) }

func (m *model) stateOf(ed []byte) peerState { return m.states[hexOf(ed)] }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case eventMsg:
		return m.handleEvent(msg.ev)
	case tea.KeyMsg:
		if m.mode == modePath {
			return m.updatePathInput(msg)
		}
		return m.updateNormal(msg)
	}
	return m, nil
}

func (m model) updateNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.peers)-1 {
			m.cursor++
		}
	case "c":
		m.connectSelected()
	case "x":
		m.rejectSelected()
	case "s":
		return m.startSend()
	case "a":
		m.acceptOffer()
	case "r":
		m.rejectOffer()
	}
	return m, nil
}

func (m *model) selectedPeer() (client.PeerInfo, bool) {
	if m.cursor < 0 || m.cursor >= len(m.peers) {
		return client.PeerInfo{}, false
	}
	return m.peers[m.cursor], true
}

func (m *model) connectSelected() {
	p, ok := m.selectedPeer()
	if !ok {
		return
	}
	switch m.stateOf(p.Ed25519Pub) {
	case peerIncoming:
		if err := m.client.Accept(p.Ed25519Pub); err != nil {
			m.status = "accept failed: " + err.Error()
			return
		}
		m.status = "Accepted " + shortFP(p.Fingerprint)
	case peerFriend:
		m.status = "Already connected to " + shortFP(p.Fingerprint)
	case peerInvited:
		m.status = "Invite already pending for " + shortFP(p.Fingerprint)
	default:
		if err := m.client.Invite(p.Ed25519Pub); err != nil {
			m.status = "invite failed: " + err.Error()
			return
		}
		m.states[hexOf(p.Ed25519Pub)] = peerInvited
		m.status = "Invite sent to " + shortFP(p.Fingerprint)
	}
}

func (m *model) rejectSelected() {
	p, ok := m.selectedPeer()
	if !ok {
		return
	}
	if m.stateOf(p.Ed25519Pub) == peerIncoming {
		if err := m.client.Reject(p.Ed25519Pub); err != nil {
			m.status = "reject failed: " + err.Error()
			return
		}
		m.states[hexOf(p.Ed25519Pub)] = peerNone
		m.status = "Rejected invite from " + shortFP(p.Fingerprint)
		return
	}
	m.status = "Friendships are session-only and can't be torn down — disconnect to end them."
}

func (m model) startSend() (tea.Model, tea.Cmd) {
	p, ok := m.selectedPeer()
	if !ok {
		return m, nil
	}
	if m.stateOf(p.Ed25519Pub) != peerFriend {
		m.status = "Connect to " + shortFP(p.Fingerprint) + " first ([c]) before sending."
		return m, nil
	}
	m.mode = modePath
	m.sendTarget = hexOf(p.Ed25519Pub)
	m.input.SetValue("")
	m.input.Focus()
	m.status = "Enter a file path, then Enter to send (Esc to cancel)."
	return m, textinput.Blink
}

func (m model) updatePathInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeNormal
		m.input.Blur()
		m.status = "Send cancelled."
		return m, nil
	case "enter":
		path := cleanPath(m.input.Value())
		m.mode = modeNormal
		m.input.Blur()
		if path == "" {
			m.status = "No path entered."
			return m, nil
		}
		target, _ := hex.DecodeString(m.sendTarget)
		id, err := m.client.SendFile(target, path)
		if err != nil {
			m.status = "send failed: " + err.Error()
			return m, nil
		}
		x := &xfer{id: hexOf(id), dir: client.Outbound, filename: baseName(path), status: xferOffered}
		m.addXfer(x)
		m.status = "Offered " + x.filename + " — waiting for the peer to accept."
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *model) acceptOffer() {
	if len(m.offers) == 0 {
		return
	}
	off := m.offers[0]
	if err := m.client.AcceptTransfer(off.TransferID); err != nil {
		m.status = "accept failed: " + err.Error()
		return
	}
	m.offers = m.offers[1:]
	m.status = "Accepting " + off.Filename + "…"
}

func (m *model) rejectOffer() {
	if len(m.offers) == 0 {
		return
	}
	off := m.offers[0]
	if err := m.client.RejectTransfer(off.TransferID, "declined"); err != nil {
		m.status = "reject failed: " + err.Error()
		return
	}
	m.offers = m.offers[1:]
	if x := m.xferByID[hexOf(off.TransferID)]; x != nil {
		x.status = xferFailed
		x.detail = "declined"
	}
	m.status = "Declined " + off.Filename
}

func (m *model) addXfer(x *xfer) {
	m.xfers = append(m.xfers, x)
	m.xferByID[x.id] = x
}
