// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package rsh

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/netip"
	"os/user"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
)

func TestExpandDelegateURL(t *testing.T) {
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:       42,
			StableID: "self-stable",
			Key:      key.NewNode().Public(),
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
		}).View(),
	}

	peerNode := (&tailcfg.Node{
		ID:       99,
		StableID: "peer-stable",
		Key:      key.NewNode().Public(),
	}).View()

	peerAddr := netip.MustParseAddr("100.64.1.2")
	lu := &user.User{Username: "localice"}

	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "all_variables",
			url:  "https://control.example.com/check?src=$SRC_NODE_IP&srcid=$SRC_NODE_ID&dst=$DST_NODE_IP&dstid=$DST_NODE_ID&sshuser=$SSH_USER&local=$LOCAL_USER",
			want: "https://control.example.com/check?src=100.64.1.2&srcid=99&dst=100.64.0.1&dstid=42&sshuser=alice&local=localice",
		},
		{
			name: "no_variables",
			url:  "https://control.example.com/check?static=true",
			want: "https://control.example.com/check?static=true",
		},
		{
			name: "url_encoding",
			url:  "https://control.example.com/check?user=$SSH_USER",
			want: "https://control.example.com/check?user=alice%40example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshUser := "alice"
			if tt.name == "url_encoding" {
				sshUser = "alice@example.com"
			}
			got := expandDelegateURL(tt.url, nm, peerNode, peerAddr, sshUser, lu)
			if got != tt.want {
				t.Errorf("expandDelegateURL() =\n  %s\nwant:\n  %s", got, tt.want)
			}
		})
	}
}

func TestWriteNDJSON(t *testing.T) {
	var buf bytes.Buffer

	// Write a status message.
	writeNDJSON(&buf, nil, rshStatusMessage{Status: "waiting"})

	// Write an rshResponse.
	writeNDJSON(&buf, nil, rshResponse{Addr: "100.64.0.1:1234", Token: "abcd"})

	// Verify output is two newline-delimited JSON lines.
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), buf.String())
	}

	// Verify first line is a status message.
	var msg rshStatusMessage
	if err := json.Unmarshal([]byte(lines[0]), &msg); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if msg.Status != "waiting" {
		t.Errorf("status = %q, want %q", msg.Status, "waiting")
	}

	// Verify second line is a response.
	var resp rshResponse
	if err := json.Unmarshal([]byte(lines[1]), &resp); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if resp.Addr != "100.64.0.1:1234" {
		t.Errorf("addr = %q, want %q", resp.Addr, "100.64.0.1:1234")
	}
	if resp.Token != "abcd" {
		t.Errorf("token = %q, want %q", resp.Token, "abcd")
	}
}

func TestNDJSONStreamParsing(t *testing.T) {
	// Simulate a streaming NDJSON response as the CLI would see it.
	var buf bytes.Buffer
	writeNDJSON(&buf, nil, rshStatusMessage{Status: "Checking with control plane..."})
	writeNDJSON(&buf, nil, rshStatusMessage{Status: "Waiting for approval..."})
	writeNDJSON(&buf, nil, rshStatusMessage{Status: "Access approved"})
	writeNDJSON(&buf, nil, rshResponse{Addr: "100.64.0.5:4567", Token: "deadbeef"})

	// Parse like the CLI does.
	scanner := bufio.NewScanner(&buf)
	var statusMessages []string
	var finalResp rshResponse

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var candidate rshResponse
		if err := json.Unmarshal(line, &candidate); err == nil && candidate.Addr != "" {
			finalResp = candidate
			continue
		}
		var msg rshStatusMessage
		if err := json.Unmarshal(line, &msg); err == nil && msg.Status != "" {
			statusMessages = append(statusMessages, msg.Status)
		}
	}

	if len(statusMessages) != 3 {
		t.Fatalf("got %d status messages, want 3", len(statusMessages))
	}
	if statusMessages[0] != "Checking with control plane..." {
		t.Errorf("status[0] = %q, want %q", statusMessages[0], "Checking with control plane...")
	}
	if statusMessages[2] != "Access approved" {
		t.Errorf("status[2] = %q, want %q", statusMessages[2], "Access approved")
	}
	if finalResp.Addr != "100.64.0.5:4567" {
		t.Errorf("addr = %q, want %q", finalResp.Addr, "100.64.0.5:4567")
	}
	if finalResp.Token != "deadbeef" {
		t.Errorf("token = %q, want %q", finalResp.Token, "deadbeef")
	}
}

func TestEvalSSHPolicyHoldAndDelegate(t *testing.T) {
	now := timeVal(2025, 1, 1)

	node := (&tailcfg.Node{
		ID:       1,
		StableID: "stable1",
		Key:      key.NewNode().Public(),
	}).View()

	uprof := tailcfg.UserProfile{
		LoginName: "alice@example.com",
	}

	srcAddr := netip.MustParseAddr("100.64.1.2")

	tests := []struct {
		name       string
		pol        *tailcfg.SSHPolicy
		sshUser    string
		wantResult evalResult
		wantUser   string
		wantURL    string
	}{
		{
			name: "hold_and_delegate_with_message",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"*": "="},
						Action: &tailcfg.SSHAction{
							HoldAndDelegate: "https://control.example.com/approve?user=$SSH_USER",
							Message:         "Please approve in the admin panel",
						},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalHoldDelegate,
			wantUser:   "alice",
			wantURL:    "https://control.example.com/approve?user=$SSH_USER",
		},
		{
			name: "hold_with_specific_user_mapping",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{UserLogin: "alice@example.com"}},
						SSHUsers:   map[string]string{"root": "admin"},
						Action: &tailcfg.SSHAction{
							HoldAndDelegate: "https://control.example.com/check",
						},
					},
				},
			},
			sshUser:    "root",
			wantResult: evalHoldDelegate,
			wantUser:   "admin",
			wantURL:    "https://control.example.com/check",
		},
		{
			name: "hold_rejects_unmapped_user",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"root": "admin"},
						Action: &tailcfg.SSHAction{
							HoldAndDelegate: "https://control.example.com/check",
						},
					},
				},
			},
			sshUser:    "unknown",
			wantResult: evalRejectedUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, localUser, result := evalSSHPolicy(tt.pol, node, uprof, srcAddr, tt.sshUser, now)
			if result != tt.wantResult {
				t.Errorf("result = %v, want %v", result, tt.wantResult)
			}
			if tt.wantUser != "" && localUser != tt.wantUser {
				t.Errorf("localUser = %q, want %q", localUser, tt.wantUser)
			}
			if tt.wantURL != "" && action != nil && action.HoldAndDelegate != tt.wantURL {
				t.Errorf("HoldAndDelegate = %q, want %q", action.HoldAndDelegate, tt.wantURL)
			}
			if tt.wantResult == evalHoldDelegate && action == nil {
				t.Error("expected non-nil action for evalHoldDelegate result")
			}
		})
	}
}

func TestExpandDelegateURLNilFields(t *testing.T) {
	// Test with minimal/nil fields to ensure no panics.
	lu := &user.User{Username: "bob"}
	peerAddr := netip.MustParseAddr("100.64.0.2")

	// Nil netmap, invalid peer node.
	got := expandDelegateURL(
		"https://control.example.com/check?dst=$DST_NODE_ID&src=$SRC_NODE_ID",
		nil,
		tailcfg.NodeView{}, // invalid
		peerAddr,
		"bob",
		lu,
	)
	// Should not panic; missing IDs should be empty strings.
	if strings.Contains(got, "$DST_NODE_ID") {
		t.Errorf("unexpanded variable in URL: %s", got)
	}
	if strings.Contains(got, "$SRC_NODE_ID") {
		t.Errorf("unexpanded variable in URL: %s", got)
	}
}

func timeVal(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}
