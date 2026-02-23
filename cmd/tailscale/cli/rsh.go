// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale/apitype"
)

var rshArgs struct {
	loginUser string // -l flag: SSH login user
	sshOption string // -o flag: SSH option (ignored, for compatibility)
}

var rshCmd = &ffcli.Command{
	Name:       "rsh",
	ShortUsage: "tailscale rsh [-l user] [user@]<host> [command...]",
	ShortHelp:  "Execute a remote command over Tailscale without SSH overhead",
	LongHelp: strings.TrimSpace(`
The 'tailscale rsh' command executes a command on a remote Tailscale node
using a direct TCP connection over the Tailscale network. Unlike SSH, it
avoids double encryption (SSH + WireGuard) and SSH's suboptimal buffering.

It is designed to be used as an rsync -e transport replacement:

  rsync -e 'tailscale rsh' -avz ./local/ user@host:/remote/

The remote node must have Tailscale SSH enabled, as rsh reuses the same
SSH access policy for authorization.

SSH-compatible flags (-l user, -o option) are accepted and handled
appropriately so that rsync and similar tools can invoke rsh as a
drop-in remote shell replacement.

When used without a command, it starts the user's default login shell.
`),
	FlagSet: func() *flag.FlagSet {
		fs := newFlagSet("rsh")
		fs.StringVar(&rshArgs.loginUser, "l", "", "remote login user (SSH-compatible)")
		fs.StringVar(&rshArgs.sshOption, "o", "", "SSH option (ignored, for compatibility)")
		return fs
	}(),
	Exec: runRsh,
}

// rshFraming constants matching feature/rsh/protocol.go.
const (
	rshChanStdin    byte = 0x00
	rshChanStdout   byte = 0x01
	rshChanStderr   byte = 0x02
	rshChanExit     byte = 0x03
	rshTokenLen          = 32
	rshMaxFrame          = 256 * 1024
	rshFrameHdrSize      = 5
)

func runRsh(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: tailscale rsh [user@]<host> [command...]")
	}

	// Check tailscaled is running.
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}

	username, host, cmdArgs, err := parseRshArgs(args)
	if err != nil {
		return err
	}

	// The -l flag parsed by ffcli takes priority over user@host.
	// This handles cases like: tailscale rsh -l ubuntu james-ai
	// where ffcli parses -l before runRsh sees the args.
	if rshArgs.loginUser != "" {
		username = rshArgs.loginUser
	}

	// If no explicit user, default to the current OS user.
	if username == "" {
		u, err := currentUser()
		if err != nil {
			return fmt.Errorf("cannot determine current user: %w", err)
		}
		username = u
	}

	// Resolve host to a peer.
	ps, ok := peerStatusFromArg(st, host)
	if !ok {
		return fmt.Errorf("unknown host %q; not found in Tailscale network", host)
	}

	// Build the command string (rsync passes it as separate args).
	command := strings.Join(cmdArgs, " ")

	// Request an rsh session via the LocalAPI.
	type localRshRequest struct {
		PeerID  string `json:"peer"`
		User    string `json:"user"`
		Command string `json:"command,omitempty"`
	}
	reqBody := localRshRequest{
		PeerID:  string(ps.ID),
		User:    username,
		Command: command,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"http://"+apitype.LocalAPIHost+"/localapi/v0/rsh",
		bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := localClient.DoLocalRequest(req)
	if err != nil {
		return fmt.Errorf("rsh setup: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("rsh setup failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	type rshResponse struct {
		Addr  string `json:"addr"`
		Token string `json:"token"`
	}
	type rshStatusMessage struct {
		Status string `json:"status"`
	}

	var rshResp rshResponse
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-ndjson") {
		// Streaming check mode: read newline-delimited JSON lines.
		// Status messages go to stderr, the final rshResponse has addr+token.
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			// Try to decode as rshResponse (has "addr" field).
			var candidate rshResponse
			if err := json.Unmarshal(line, &candidate); err == nil && candidate.Addr != "" {
				rshResp = candidate
				continue
			}
			// Otherwise, treat as a status message.
			var msg rshStatusMessage
			if err := json.Unmarshal(line, &msg); err == nil && msg.Status != "" {
				fmt.Fprintf(os.Stderr, "rsh: %s\n", msg.Status)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("rsh: reading streaming response: %w", err)
		}
	} else {
		// Simple JSON response.
		if err := json.NewDecoder(resp.Body).Decode(&rshResp); err != nil {
			return fmt.Errorf("rsh: invalid response: %w", err)
		}
	}
	resp.Body.Close()

	if rshResp.Addr == "" || rshResp.Token == "" {
		return errors.New("rsh: server returned empty address or token")
	}

	// Parse the address to get host and port for DialTCP.
	addrHost, portStr, err := splitHostPort(rshResp.Addr)
	if err != nil {
		return fmt.Errorf("rsh: invalid address %q: %w", rshResp.Addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("rsh: invalid port %q: %w", portStr, err)
	}

	// Decode the token.
	token, err := hex.DecodeString(rshResp.Token)
	if err != nil || len(token) != rshTokenLen {
		return fmt.Errorf("rsh: invalid token")
	}

	// Connect to the data channel via tailscaled.
	conn, err := localClient.DialTCP(ctx, addrHost, uint16(port))
	if err != nil {
		return fmt.Errorf("rsh: connect to %s: %w", rshResp.Addr, err)
	}
	defer conn.Close()

	// Send the authentication token.
	if _, err := conn.Write(token); err != nil {
		return fmt.Errorf("rsh: send token: %w", err)
	}

	// Run the framing protocol.
	return rshPumpIO(conn)
}

// rshPumpIO handles the framing protocol between the local stdin/stdout/stderr
// and the remote process over the connection.
func rshPumpIO(conn io.ReadWriteCloser) error {
	// Goroutine: read stdin and send as ChanStdin frames.
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		buf := make([]byte, 64*1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if werr := writeFrame(conn, rshChanStdin, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				// Send a zero-length stdin frame to signal EOF.
				writeFrame(conn, rshChanStdin, nil)
				return
			}
		}
	}()

	// Main loop: read frames from the connection and dispatch.
	var hdr [rshFrameHdrSize]byte
	for {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// Connection closed without exit code.
				return fmt.Errorf("rsh: connection closed unexpectedly")
			}
			return fmt.Errorf("rsh: read frame: %w", err)
		}
		ch := hdr[0]
		n := binary.BigEndian.Uint32(hdr[1:])
		if n > rshMaxFrame {
			return fmt.Errorf("rsh: frame too large: %d", n)
		}

		switch ch {
		case rshChanStdout:
			if _, err := io.CopyN(os.Stdout, conn, int64(n)); err != nil {
				return fmt.Errorf("rsh: stdout: %w", err)
			}
		case rshChanStderr:
			if _, err := io.CopyN(os.Stderr, conn, int64(n)); err != nil {
				return fmt.Errorf("rsh: stderr: %w", err)
			}
		case rshChanExit:
			if n != 4 {
				return fmt.Errorf("rsh: invalid exit frame size: %d", n)
			}
			var exitBuf [4]byte
			if _, err := io.ReadFull(conn, exitBuf[:]); err != nil {
				return fmt.Errorf("rsh: read exit code: %w", err)
			}
			code := int(binary.BigEndian.Uint32(exitBuf[:]))
			if code != 0 {
				os.Exit(code)
			}
			return nil
		default:
			// Unknown channel, skip the payload.
			if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
				return fmt.Errorf("rsh: skip unknown frame: %w", err)
			}
		}
	}
}

// writeFrame writes a single rsh protocol frame to w.
func writeFrame(w io.Writer, ch byte, data []byte) error {
	var hdr [rshFrameHdrSize]byte
	hdr[0] = ch
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// parseRshArgs parses SSH-compatible arguments as passed by rsync and
// similar tools when using rsh as a remote shell transport.
//
// rsync invokes the remote shell as:
//
//	tailscale rsh [user@host] [-l user] [-o option]... <host> <command...>
//
// The user@host may appear as the first positional arg (from the rsync
// URI), while -l overrides the username. The bare hostname after flags
// is the actual target. Everything after that is the remote command.
//
// Returns the resolved username (may be empty if none specified), host,
// and command args.
func parseRshArgs(args []string) (username, host string, cmdArgs []string, err error) {
	if len(args) == 0 {
		return "", "", nil, errors.New("usage: tailscale rsh [-l user] [user@]<host> [command...]")
	}

	// First, check if args[0] is a user@host or bare host (not a flag).
	// rsync passes the user@host from the rsync URI as the first arg,
	// before any -l flag.
	i := 0
	if !strings.HasPrefix(args[0], "-") {
		u, h, hasAt := strings.Cut(args[0], "@")
		if hasAt {
			username = u
			host = h
		} else {
			// Bare hostname (no @). Record it; it may be
			// overridden if a second bare hostname appears
			// after flags (the rsync pattern).
			host = args[0]
		}
		i = 1
	}

	// Parse SSH-compatible flags.
	flagUser := ""
	hadFlags := false
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") {
			break // first non-flag is the host
		}
		hadFlags = true
		switch {
		case a == "-l":
			// -l <user>
			i++
			if i >= len(args) {
				return "", "", nil, errors.New("rsh: -l requires an argument")
			}
			flagUser = args[i]
			i++
		case strings.HasPrefix(a, "-l"):
			// -l<user> (no space)
			flagUser = a[2:]
			i++
		case a == "-o":
			// -o <option>: SSH option, ignore.
			i++
			if i < len(args) {
				i++ // skip the option value
			}
		case strings.HasPrefix(a, "-o"):
			// -o<option>: SSH option, ignore.
			i++
		default:
			// Unknown flag (e.g. -4, -6, -p, etc.); skip it.
			// SSH has many flags; we silently ignore ones we
			// don't understand since we don't need them.
			i++
		}
	}

	// After flags, the next non-flag arg is the host. rsync passes
	// the bare hostname after -l flags, so we expect it here when
	// flags were present. When there were no flags and we already
	// have a host from args[0], the remaining args are the command.
	if hadFlags && i < len(args) && !strings.HasPrefix(args[i], "-") {
		host = args[i]
		i++
	}

	// Everything remaining is the command.
	cmdArgs = args[i:]

	// -l flag overrides any user from user@host.
	if flagUser != "" {
		username = flagUser
	}

	if host == "" {
		return "", "", nil, errors.New("usage: tailscale rsh [-l user] [user@]<host> [command...]")
	}

	return username, host, cmdArgs, nil
}

// splitHostPort splits a host:port string. Unlike net.SplitHostPort,
// it handles bare IPv4 addresses with port (100.1.2.3:1234) as well
// as [IPv6]:port format.
func splitHostPort(addr string) (host, port string, err error) {
	// Handle IPv6 [::]:port format.
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]:")
		if end < 0 {
			return "", "", fmt.Errorf("invalid address: %s", addr)
		}
		return addr[1:end], addr[end+2:], nil
	}
	// Handle IPv4 host:port.
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("no port in address: %s", addr)
	}
	return addr[:i], addr[i+1:], nil
}

// currentUser returns the current OS username.
func currentUser() (string, error) {
	// os/user.Current() can fail in some environments (static builds, etc).
	// Try it first, fall back to env vars.
	if u := os.Getenv("USER"); u != "" {
		return u, nil
	}
	return "", errors.New("cannot determine current user")
}
