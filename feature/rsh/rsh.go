// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package rsh

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/backoff"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/osuser"
)

var (
	metricRshCalls   = clientmetric.NewCounter("peerapi_rsh")
	metricRshAccepts = clientmetric.NewCounter("peerapi_rsh_accept")
	metricRshRejects = clientmetric.NewCounter("peerapi_rsh_reject")
)

func init() {
	ipnlocal.RegisterPeerAPIHandler("/v0/rsh", handleRsh)
}

// rshRequest is the JSON body sent to POST /v0/rsh.
type rshRequest struct {
	// User is the requested SSH user (will be mapped via SSHUsers policy).
	User string `json:"user"`

	// Command is the command to execute. If empty, the user's default
	// login shell is started.
	Command string `json:"command,omitempty"`
}

// rshResponse is returned by a successful POST /v0/rsh.
// In streaming mode (check mode), this is the final JSON line in
// the newline-delimited JSON stream.
type rshResponse struct {
	// Addr is the Tailscale IP:port to connect to for the data channel.
	Addr string `json:"addr"`

	// Token is the hex-encoded one-time authentication token that must
	// be sent as the first bytes on the data channel connection.
	Token string `json:"token"`
}

// rshStatusMessage is sent as a streaming JSON line during the
// HoldAndDelegate (check mode) flow before the final rshResponse.
// Each message is a newline-delimited JSON object.
type rshStatusMessage struct {
	// Status is a human-readable status message to display to the user.
	Status string `json:"status"`
}

// netstackTCPListenerFunc is the type of a function that creates a TCP
// listener on the netstack (gVisor) network stack. It is set by the
// netstack package at init time.
//
// We use a function hook instead of a type assertion on NetstackImpl
// because netstack.Impl.ListenTCP returns *gonet.TCPListener (not
// net.Listener), and importing gonet would create an unwanted gVisor
// dependency.
var netstackListenTCP func(b *ipnlocal.LocalBackend, network, address string) (net.Listener, error)

const linux = "linux"

func handleRsh(ph ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	metricRshCalls.Add(1)
	logf := ph.Logf

	if r.Method != "POST" {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	b := ph.LocalBackend()

	// Check that SSH is enabled on this node.
	if !b.ShouldRunSSH() {
		logf("rsh: denied; SSH not enabled")
		metricRshRejects.Add(1)
		http.Error(w, "SSH not enabled on this node", http.StatusForbidden)
		return
	}

	// Parse request.
	var req rshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logf("rsh: bad request body: %v", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.User == "" {
		http.Error(w, "user is required", http.StatusBadRequest)
		return
	}

	// Evaluate SSH policy.
	peerNode := ph.Peer()
	peerAddr := ph.RemoteAddr().Addr()

	nm := b.NetMap()
	if nm == nil {
		logf("rsh: no netmap")
		http.Error(w, "no netmap available", http.StatusInternalServerError)
		return
	}

	sshPol := nm.SSHPolicy
	if sshPol == nil {
		logf("rsh: no SSH policy")
		metricRshRejects.Add(1)
		http.Error(w, "no SSH policy configured", http.StatusForbidden)
		return
	}

	// Look up the peer's user profile for policy matching.
	_, uprof, ok := b.WhoIs("tcp", ph.RemoteAddr())
	if !ok {
		logf("rsh: unknown peer %v", ph.RemoteAddr())
		metricRshRejects.Add(1)
		http.Error(w, "unknown peer", http.StatusForbidden)
		return
	}

	action, localUser, result := evalSSHPolicy(sshPol, peerNode, uprof, peerAddr, req.User, time.Now())

	switch result {
	case evalAccepted:
		if action.Reject {
			logf("rsh: policy explicitly rejects %v -> %s@%s", peerAddr, req.User, localUser)
			metricRshRejects.Add(1)
			http.Error(w, "access denied by policy", http.StatusForbidden)
			return
		}
		// Good, accepted. action may still have a Message to send.
	case evalHoldDelegate:
		// Check mode: we need to poll the control plane for approval.
		// The response uses streaming newline-delimited JSON so
		// status messages can be sent while we wait.
	case evalRejectedUser:
		logf("rsh: user %q not mapped for peer %v", req.User, peerAddr)
		metricRshRejects.Add(1)
		http.Error(w, fmt.Sprintf("user %q not permitted", req.User), http.StatusForbidden)
		return
	case evalRejected:
		logf("rsh: policy rejects %v -> %s", peerAddr, req.User)
		metricRshRejects.Add(1)
		http.Error(w, "access denied by policy", http.StatusForbidden)
		return
	}

	// Look up the local user. We need this for both the immediate accept
	// path and the HoldAndDelegate path (to expand delegate URL variables).
	lu, loginShell, err := osuser.LookupByUsernameWithShell(localUser)
	if err != nil {
		logf("rsh: user lookup failed for %q: %v", localUser, err)
		http.Error(w, fmt.Sprintf("user %q not found", localUser), http.StatusInternalServerError)
		return
	}
	groupIDs, err := osuser.GetGroupIds(lu)
	if err != nil {
		logf("rsh: group lookup failed for %q: %v", localUser, err)
		http.Error(w, "failed to look up user groups", http.StatusInternalServerError)
		return
	}

	// If HoldAndDelegate, run the check mode loop to get a terminal action.
	// We use streaming JSON so status messages can be sent to the client.
	if result == evalHoldDelegate {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)

		action, err = resolveCheckMode(r.Context(), b, action, nm, peerNode, peerAddr, req.User, lu, w, flusher, logf)
		if err != nil {
			// Connection is already streaming; send error as a status message.
			logf("rsh: check mode failed: %v", err)
			writeNDJSON(w, flusher, rshStatusMessage{Status: fmt.Sprintf("check mode error: %v", err)})
			return
		}
		if action.Reject {
			logf("rsh: check mode rejected %v -> %s", peerAddr, req.User)
			metricRshRejects.Add(1)
			msg := "access denied"
			if action.Message != "" {
				msg = action.Message
			}
			writeNDJSON(w, flusher, rshStatusMessage{Status: msg})
			return
		}
		if !action.Accept {
			logf("rsh: check mode returned non-terminal action for %v -> %s", peerAddr, req.User)
			metricRshRejects.Add(1)
			writeNDJSON(w, flusher, rshStatusMessage{Status: "unexpected response from control"})
			return
		}
	}

	// Find a local Tailscale IP to listen on.
	listenAddr, err := pickListenAddr(nm, peerAddr)
	if err != nil {
		logf("rsh: no listen address: %v", err)
		if result == evalHoldDelegate {
			flusher, _ := w.(http.Flusher)
			writeNDJSON(w, flusher, rshStatusMessage{Status: "no suitable listen address"})
		} else {
			http.Error(w, "no suitable listen address", http.StatusInternalServerError)
		}
		return
	}

	// Create the listener.
	ln, err := listenTailscale(b, listenAddr)
	if err != nil {
		logf("rsh: listen failed: %v", err)
		if result == evalHoldDelegate {
			flusher, _ := w.(http.Flusher)
			writeNDJSON(w, flusher, rshStatusMessage{Status: "failed to create listener"})
		} else {
			http.Error(w, "failed to create listener", http.StatusInternalServerError)
		}
		return
	}

	// Generate one-time token.
	var tokenBytes [tokenLen]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		ln.Close()
		logf("rsh: rand failed: %v", err)
		if result == evalHoldDelegate {
			flusher, _ := w.(http.Flusher)
			writeNDJSON(w, flusher, rshStatusMessage{Status: "internal error"})
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	tokenHex := hex.EncodeToString(tokenBytes[:])

	metricRshAccepts.Add(1)

	// Start the session handler in a goroutine. It will accept one
	// connection, verify the token, and wire up the incubator process.
	go handleRshSession(b, ln, tokenBytes[:], peerAddr, lu, loginShell, groupIDs, req, ph, logf)

	// Return the listen address and token to the client.
	resp := rshResponse{
		Addr:  ln.Addr().String(),
		Token: tokenHex,
	}
	if result == evalHoldDelegate {
		// Streaming mode: send a final accept message then the response.
		flusher, _ := w.(http.Flusher)
		if action.Message != "" {
			writeNDJSON(w, flusher, rshStatusMessage{Status: action.Message})
		}
		writeNDJSON(w, flusher, resp)
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// writeNDJSON writes v as a single newline-delimited JSON line to w
// and flushes. This is used for the streaming check mode response.
func writeNDJSON(w io.Writer, flusher http.Flusher, v any) {
	json.NewEncoder(w).Encode(v) // Encode appends '\n'
	if flusher != nil {
		flusher.Flush()
	}
}

// resolveCheckMode runs the HoldAndDelegate loop, polling the control plane
// until a terminal action (Accept or Reject) is returned. It sends status
// messages to the client as streaming JSON lines while waiting.
//
// This is the rsh equivalent of SSH's clientAuth HoldAndDelegate loop.
func resolveCheckMode(
	ctx context.Context,
	b *ipnlocal.LocalBackend,
	action *tailcfg.SSHAction,
	nm *netmap.NetworkMap,
	peerNode tailcfg.NodeView,
	peerAddr netip.Addr,
	sshUser string,
	lu *user.User,
	w io.Writer,
	flusher http.Flusher,
	logf func(string, ...any),
) (*tailcfg.SSHAction, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	for {
		if action.Message != "" {
			writeNDJSON(w, flusher, rshStatusMessage{Status: action.Message})
		}

		if action.Accept || action.Reject {
			return action, nil
		}
		if action.HoldAndDelegate == "" {
			return nil, fmt.Errorf("action has neither Accept, Reject, nor HoldAndDelegate")
		}

		delegateURL := expandDelegateURL(action.HoldAndDelegate, nm, peerNode, peerAddr, sshUser, lu)
		logf("rsh: check mode: polling %s", delegateURL)
		writeNDJSON(w, flusher, rshStatusMessage{Status: "Waiting for approval..."})

		var err error
		action, err = fetchSSHAction(ctx, b, delegateURL, logf)
		if err != nil {
			return nil, fmt.Errorf("fetching SSH action: %w", err)
		}
	}
}

// expandDelegateURL expands the variables in a HoldAndDelegate URL.
// The variables match those used by SSH: $SRC_NODE_IP, $SRC_NODE_ID,
// $DST_NODE_IP, $DST_NODE_ID, $SSH_USER, $LOCAL_USER.
func expandDelegateURL(
	actionURL string,
	nm *netmap.NetworkMap,
	peerNode tailcfg.NodeView,
	peerAddr netip.Addr,
	sshUser string,
	lu *user.User,
) string {
	var dstNodeID string
	if nm != nil {
		dstNodeID = fmt.Sprint(int64(nm.SelfNode.ID()))
	}
	var srcNodeID string
	if peerNode.Valid() {
		srcNodeID = fmt.Sprint(int64(peerNode.ID()))
	}
	var dstNodeIP string
	if nm != nil {
		addrs := nm.GetAddresses()
		for _, pfx := range addrs.All() {
			if pfx.IsSingleIP() {
				dstNodeIP = pfx.Addr().String()
				break
			}
		}
	}
	return strings.NewReplacer(
		"$SRC_NODE_IP", url.QueryEscape(peerAddr.String()),
		"$SRC_NODE_ID", srcNodeID,
		"$DST_NODE_IP", url.QueryEscape(dstNodeIP),
		"$DST_NODE_ID", dstNodeID,
		"$SSH_USER", url.QueryEscape(sshUser),
		"$LOCAL_USER", url.QueryEscape(lu.Username),
	).Replace(actionURL)
}

// fetchSSHAction polls a control plane URL over the Noise transport
// and returns the SSHAction. It retries with exponential backoff on
// transient errors, matching the behavior of SSH's fetchSSHAction.
func fetchSSHAction(ctx context.Context, b *ipnlocal.LocalBackend, url string, logf func(string, ...any)) (*tailcfg.SSHAction, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	bo := backoff.NewBackoff("rsh-fetch-ssh-action", logf, 10*time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		res, err := b.DoNoiseRequest(req)
		if err != nil {
			bo.BackOff(ctx, err)
			continue
		}
		if res.StatusCode != 200 {
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if len(body) > 1<<10 {
				body = body[:1<<10]
			}
			logf("rsh: fetch of %v: %s, %s", url, res.Status, body)
			bo.BackOff(ctx, fmt.Errorf("unexpected status: %v", res.Status))
			continue
		}
		a := new(tailcfg.SSHAction)
		err = json.NewDecoder(res.Body).Decode(a)
		res.Body.Close()
		if err != nil {
			logf("rsh: invalid SSHAction JSON from %v: %v", url, err)
			bo.BackOff(ctx, err)
			continue
		}
		return a, nil
	}
}

// pickListenAddr selects a local Tailscale IP address that matches the
// address family of the peer. This ensures the data channel connection
// uses the same protocol version.
func pickListenAddr(nm *netmap.NetworkMap, peerAddr netip.Addr) (netip.Addr, error) {
	addrs := nm.GetAddresses()
	wantV4 := peerAddr.Is4()

	for _, pfx := range addrs.All() {
		if !pfx.IsSingleIP() {
			continue
		}
		a := pfx.Addr()
		if wantV4 && a.Is4() {
			return a, nil
		}
		if !wantV4 && a.Is6() {
			return a, nil
		}
	}
	// Fallback: return any address.
	for _, pfx := range addrs.All() {
		if pfx.IsSingleIP() {
			return pfx.Addr(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no Tailscale addresses available")
}

// listenTailscale creates a TCP listener on the given Tailscale IP.
// In netstack mode, it uses the gVisor stack via the netstackListenTCP hook.
// In kernel TUN mode, it uses the standard library.
func listenTailscale(b *ipnlocal.LocalBackend, addr netip.Addr) (net.Listener, error) {
	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}
	listenAddr := netip.AddrPortFrom(addr, 0).String()

	if b.Sys().IsNetstack() {
		// In full netstack mode, we need to use the gVisor stack to listen
		// since all local IP traffic is handled by netstack.
		if netstackListenTCP == nil {
			return nil, fmt.Errorf("netstack listener not available (rsh_netstack not linked)")
		}
		return netstackListenTCP(b, network, listenAddr)
	}

	// In kernel TUN mode, the Tailscale IP is assigned to the TUN device
	// and the kernel handles routing. Standard net.Listen works.
	return net.Listen(network, listenAddr)
}

// handleRshSession is run in a goroutine. It accepts a single connection
// from the listener, verifies the token and source, then spawns the
// remote command via the incubator.
func handleRshSession(
	b *ipnlocal.LocalBackend,
	ln net.Listener,
	token []byte,
	expectedPeer netip.Addr,
	lu *user.User,
	loginShell string,
	groupIDs []string,
	req rshRequest,
	ph ipnlocal.PeerAPIHandler,
	logf func(string, ...any),
) {
	defer ln.Close()

	// Set a deadline for the client to connect.
	if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		dl.SetDeadline(time.Now().Add(30 * time.Second))
	}

	conn, err := ln.Accept()
	if err != nil {
		logf("rsh: accept failed: %v", err)
		return
	}
	ln.Close() // Only accept one connection.

	defer conn.Close()

	// Verify source IP.
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		logf("rsh: unexpected remote addr type: %T", conn.RemoteAddr())
		return
	}
	remoteIP, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		logf("rsh: invalid remote IP")
		return
	}
	remoteIP = remoteIP.Unmap()
	if remoteIP != expectedPeer {
		logf("rsh: unexpected peer %v, expected %v", remoteIP, expectedPeer)
		return
	}

	// Read and verify token.
	var gotToken [tokenLen]byte
	if _, err := io.ReadFull(conn, gotToken[:]); err != nil {
		logf("rsh: failed to read token: %v", err)
		return
	}
	if subtle.ConstantTimeCompare(gotToken[:], token) != 1 {
		logf("rsh: invalid token from %v", remoteIP)
		return
	}

	// Set TCP_NODELAY for low-latency rsync control messages.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	logf("rsh: session accepted from %v as %s, command=%q", remoteIP, lu.Username, req.Command)

	// Build and run the incubator command.
	runIncubator(b, conn, lu, loginShell, groupIDs, req, ph, logf)
}

// runIncubator spawns the remote command using the existing SSH incubator
// mechanism for privilege dropping and PAM integration.
func runIncubator(
	b *ipnlocal.LocalBackend,
	conn net.Conn,
	lu *user.User,
	loginShell string,
	groupIDs []string,
	req rshRequest,
	ph ipnlocal.PeerAPIHandler,
	logf func(string, ...any),
) {
	tailscaledPath, err := os.Executable()
	if err != nil {
		logf("rsh: os.Executable: %v", err)
		sendExitCode(conn, 1)
		return
	}

	peerNode := ph.Peer()
	remoteUser := "unknown"
	if peerNode.Valid() {
		if peerNode.IsTagged() {
			remoteUser = strings.Join(peerNode.Tags().AsSlice(), ",")
		} else {
			_, uprof, ok := b.WhoIs("tcp", ph.RemoteAddr())
			if ok {
				remoteUser = uprof.LoginName
			}
		}
	}

	groups := strings.Join(groupIDs, ",")
	isShell := req.Command == ""

	incubatorArgs := []string{
		"be-child",
		"ssh",
		"--login-shell=" + loginShell,
		"--uid=" + lu.Uid,
		"--gid=" + lu.Gid,
		"--groups=" + groups,
		"--local-user=" + lu.Username,
		"--home-dir=" + lu.HomeDir,
		"--remote-user=" + remoteUser,
		"--remote-ip=" + ph.RemoteAddr().Addr().String(),
		"--has-tty=false",
		"--tty-name=",
	}

	if runtime.GOOS == linux && hostinfo.IsSELinuxEnforcing() {
		incubatorArgs = append(incubatorArgs, "--is-selinux-enforcing")
	}

	nm := b.NetMap()
	if nm != nil && nm.HasCap(tailcfg.NodeAttrSSHBehaviorV1) && !nm.HasCap(tailcfg.NodeAttrSSHBehaviorV2) {
		incubatorArgs = append(incubatorArgs, "--force-v1-behavior")
	}

	if isShell {
		incubatorArgs = append(incubatorArgs, "--shell")
	} else {
		incubatorArgs = append(incubatorArgs, "--cmd="+req.Command)
	}

	cmd := exec.Command(tailscaledPath, incubatorArgs...)
	cmd.Dir = "/"

	// Set up the environment for the child.
	cmd.Env = []string{
		"SHELL=" + loginShell,
		"USER=" + lu.Username,
		"HOME=" + lu.HomeDir,
		"PATH=" + defaultPathForUser(lu),
	}

	// Create stdin/stdout/stderr pipes.
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		logf("rsh: stdin pipe: %v", err)
		sendExitCode(conn, 1)
		return
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		logf("rsh: stdout pipe: %v", err)
		sendExitCode(conn, 1)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		logf("rsh: stderr pipe: %v", err)
		sendExitCode(conn, 1)
		return
	}

	if err := cmd.Start(); err != nil {
		logf("rsh: start incubator: %v", err)
		sendExitCode(conn, 1)
		return
	}

	fw := newFrameWriter(conn)
	fr := newFrameReader(conn)

	// Goroutine: read frames from client, write stdin to incubator.
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		defer stdinPipe.Close()
		for {
			ch, data, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if ch == ChanStdin {
				if _, err := stdinPipe.Write(data); err != nil {
					return
				}
			}
		}
	}()

	// Goroutine: read stdout from incubator, write frames to client.
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		buf := make([]byte, 64*1024)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				if werr := fw.WriteFrame(ChanStdout, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Goroutine: read stderr from incubator, write frames to client.
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		buf := make([]byte, 64*1024)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				if werr := fw.WriteFrame(ChanStderr, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for the process to exit.
	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			logf("rsh: wait: %v", err)
			exitCode = 1
		}
	}

	// Wait for output goroutines to drain.
	<-stdoutDone
	<-stderrDone

	// Send exit code and close.
	logf("rsh: session ended for %s, exit code %d", lu.Username, exitCode)
	fw.WriteExitCode(exitCode)
}

// sendExitCode is a helper used before the framing writer is set up.
func sendExitCode(conn net.Conn, code int) {
	fw := newFrameWriter(conn)
	fw.WriteExitCode(code)
}

// defaultPathForUser returns an appropriate default PATH for the user.
// This is a simplified version of the logic in ssh/tailssh/user.go.
func defaultPathForUser(u *user.User) string {
	if u.Uid == "0" {
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return "/usr/local/bin:/usr/bin:/bin"
}

// envknobs for debugging.
var rshVerbose = envknob.RegisterBool("TS_DEBUG_RSH_VLOG")
