// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package rsh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"tailscale.com/ipn/localapi"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
)

var (
	metricLocalAPIRshCalls = clientmetric.NewCounter("localapi_rsh")
)

func init() {
	localapi.Register("rsh", serveRsh)
}

// localRshRequest is the JSON body the CLI sends to POST /localapi/v0/rsh.
// It includes the target peer information.
type localRshRequest struct {
	// PeerID is the StableNodeID of the target peer.
	PeerID tailcfg.StableNodeID `json:"peer"`

	// User is the SSH user to connect as.
	User string `json:"user"`

	// Command is the command to execute on the remote.
	Command string `json:"command,omitempty"`
}

// serveRsh proxies an rsh setup request to the target peer's PeerAPI.
//
// POST /localapi/v0/rsh
//
// Request body: JSON localRshRequest
// Response body: JSON rshResponse (addr + token from the remote)
func serveRsh(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	metricLocalAPIRshCalls.Add(1)

	if !h.PermitRead {
		http.Error(w, "rsh access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	var req localRshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PeerID == "" {
		http.Error(w, "peer is required", http.StatusBadRequest)
		return
	}
	if req.User == "" {
		http.Error(w, "user is required", http.StatusBadRequest)
		return
	}

	b := h.LocalBackend()
	nm := b.NetMap()
	if nm == nil {
		http.Error(w, "no netmap available", http.StatusInternalServerError)
		return
	}

	// Find the peer and its PeerAPI base URL.
	var peerAPIBaseURL string
	for _, p := range nm.Peers {
		if p.StableID() == req.PeerID {
			peerAPIBaseURL = b.PeerAPIBase(p)
			break
		}
	}
	if peerAPIBaseURL == "" {
		http.Error(w, "peer not found or no PeerAPI available", http.StatusNotFound)
		return
	}

	// Build the PeerAPI request.
	peerReqBody := rshRequest{
		User:    req.User,
		Command: req.Command,
	}
	bodyBytes, err := json.Marshal(peerReqBody)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	peerURL := strings.TrimRight(peerAPIBaseURL, "/") + "/v0/rsh"
	peerReq, err := http.NewRequestWithContext(r.Context(), "POST", peerURL, bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	peerReq.Header.Set("Content-Type", "application/json")

	// Use the PeerAPI transport to dial the remote peer.
	tr := b.Dialer().PeerAPITransport()
	resp, err := tr.RoundTrip(peerReq)
	if err != nil {
		h.Logf("rsh: failed to reach peer %s: %v", req.PeerID, err)
		http.Error(w, fmt.Sprintf("failed to reach peer: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		h.Logf("rsh: peer returned status %d: %s", resp.StatusCode, string(body))
		http.Error(w, fmt.Sprintf("peer error: %s", string(body)), resp.StatusCode)
		return
	}

	// Pass through the response from the peer. If the peer is using
	// streaming NDJSON (check mode / HoldAndDelegate), we forward
	// each line as it arrives so the CLI can display status messages.
	ct := resp.Header.Get("Content-Type")
	w.Header().Set("Content-Type", ct)
	if strings.HasPrefix(ct, "application/x-ndjson") {
		// Streaming mode: flush each line as it arrives.
		flusher, _ := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	} else {
		// Simple JSON response: pass through directly.
		io.Copy(w, resp.Body)
	}
}
