package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// withStubs swaps serveFn/connectFn/pickerFn for recorders and restores them after.
func withStubs(t *testing.T) (served *string, connected *[2]string, pickerCalled *bool) {
	t.Helper()
	origServe, origConnect, origPicker, origTTY := serveFn, connectFn, pickerFn, isTTY
	t.Cleanup(func() {
		serveFn, connectFn, pickerFn, isTTY = origServe, origConnect, origPicker, origTTY
	})

	var serveListen string
	var conn [2]string
	var picker bool
	// Default non-TTY so bare dispatch stays help (no hang in tests).
	isTTY = func() bool { return false }
	serveFn = func(listen string, _ io.Writer) int {
		serveListen = listen
		return 0
	}
	connectFn = func(url, out string, _, _ io.Writer) int {
		conn[0], conn[1] = url, out
		return 0
	}
	pickerFn = func(_, _ io.Writer) int {
		picker = true
		return 0
	}
	return &serveListen, &conn, &picker
}

func TestDispatchNoArgsPrintsHelp(t *testing.T) {
	withStubs(t)
	var out, errb bytes.Buffer
	code := dispatch(nil, &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("help not printed to stdout:\n%s", out.String())
	}
}

func TestDispatchBareTTYCallsPicker(t *testing.T) {
	_, _, picker := withStubs(t)
	isTTY = func() bool { return true }
	var out, errb bytes.Buffer
	code := dispatch(nil, &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !*picker {
		t.Fatal("expected interactive picker on dual-TTY bare invocation")
	}
}

func TestDispatchBareNonTTYNoPicker(t *testing.T) {
	_, _, picker := withStubs(t)
	isTTY = func() bool { return false }
	var out, errb bytes.Buffer
	code := dispatch(nil, &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if *picker {
		t.Fatal("picker must not run when not a TTY")
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("expected help:\n%s", out.String())
	}
}

func TestDispatchServeBypassesPicker(t *testing.T) {
	served, _, picker := withStubs(t)
	isTTY = func() bool { return true }
	var out, errb bytes.Buffer
	code := dispatch([]string{"--serve"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if *picker {
		t.Fatal("--serve must bypass picker")
	}
	if *served != ":8080" {
		t.Fatalf("serve listen = %q", *served)
	}
}

func TestDispatchServe(t *testing.T) {
	served, _, _ := withStubs(t)
	var out, errb bytes.Buffer
	code := dispatch([]string{"--serve", "--listen", "0.0.0.0:9000"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if *served != "0.0.0.0:9000" {
		t.Fatalf("serve listen = %q, want 0.0.0.0:9000", *served)
	}
}

func TestDispatchServeDefaultListen(t *testing.T) {
	served, _, _ := withStubs(t)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"--serve"}, &out, &errb); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if *served != ":8080" {
		t.Fatalf("default listen = %q, want :8080", *served)
	}
}

func TestDispatchConnect(t *testing.T) {
	_, connected, _ := withStubs(t)
	var out, errb bytes.Buffer
	code := dispatch([]string{"--connect", "http://host:8080/", "--out", "/tmp/x"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if connected[0] != "http://host:8080/" || connected[1] != "/tmp/x" {
		t.Fatalf("connect args = %v", connected)
	}
}

func TestDispatchMutuallyExclusive(t *testing.T) {
	withStubs(t)
	var out, errb bytes.Buffer
	code := dispatch([]string{"--serve", "--connect", "http://host/"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "mutually exclusive") {
		t.Fatalf("missing error message: %q", errb.String())
	}
}

func TestDispatchUnknownFlag(t *testing.T) {
	withStubs(t)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"--nope"}, &out, &errb); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestDispatchHelpFlag(t *testing.T) {
	withStubs(t)
	var out, errb bytes.Buffer
	if code := dispatch([]string{"-h"}, &out, &errb); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}
