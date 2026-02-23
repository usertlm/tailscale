// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package rsh

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestEvalSSHPolicy(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

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
	}{
		{
			name:       "nil_policy",
			pol:        nil,
			sshUser:    "root",
			wantResult: evalRejected,
		},
		{
			name:       "empty_policy",
			pol:        &tailcfg.SSHPolicy{},
			sshUser:    "root",
			wantResult: evalRejected,
		},
		{
			name: "accept_any_wildcard_user",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalAccepted,
			wantUser:   "alice",
		},
		{
			name: "accept_specific_user_mapping",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"root": "admin"},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "root",
			wantResult: evalAccepted,
			wantUser:   "admin",
		},
		{
			name: "reject_unmapped_user",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"root": "admin"},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "unknown",
			wantResult: evalRejectedUser,
		},
		{
			name: "match_by_node_stable_id",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Node: "stable1"}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "bob",
			wantResult: evalAccepted,
			wantUser:   "bob",
		},
		{
			name: "reject_wrong_node",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Node: "other-node"}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "bob",
			wantResult: evalRejected,
		},
		{
			name: "match_by_node_ip",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.1.2"}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalAccepted,
			wantUser:   "alice",
		},
		{
			name: "match_by_user_login",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{UserLogin: "alice@example.com"}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalAccepted,
			wantUser:   "alice",
		},
		{
			name: "hold_and_delegate_returns_eval_hold",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{HoldAndDelegate: "https://example.com/approve"},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalHoldDelegate,
		},
		{
			name: "explicit_reject_action",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						Action:     &tailcfg.SSHAction{Reject: true},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalAccepted, // matchRule succeeds for Reject rules (no SSHUsers check)
		},
		{
			name: "expired_rule_skipped",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						RuleExpires: timePtr(now.Add(-time.Hour)),
						Principals:  []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:    map[string]string{"*": "="},
						Action:      &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalRejected,
		},
		{
			name: "first_matching_rule_wins",
			pol: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.1.2"}},
						SSHUsers:   map[string]string{"alice": "localice"},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
					{
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers:   map[string]string{"*": "="},
						Action:     &tailcfg.SSHAction{Accept: true},
					},
				},
			},
			sshUser:    "alice",
			wantResult: evalAccepted,
			wantUser:   "localice",
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
			_ = action // not checked in most tests
		})
	}
}

func TestMapLocalUser(t *testing.T) {
	tests := []struct {
		name       string
		sshUsers   map[string]string
		reqUser    string
		wantResult string
	}{
		{"exact_match", map[string]string{"root": "admin"}, "root", "admin"},
		{"wildcard_match", map[string]string{"*": "defaultuser"}, "anyone", "defaultuser"},
		{"identity_match", map[string]string{"*": "="}, "alice", "alice"},
		{"no_match", map[string]string{"root": "admin"}, "unknown", ""},
		{"exact_over_wildcard", map[string]string{"root": "admin", "*": "default"}, "root", "admin"},
		{"nil_map", nil, "alice", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapLocalUser(tt.sshUsers, tt.reqUser)
			if got != tt.wantResult {
				t.Errorf("mapLocalUser(%v, %q) = %q, want %q", tt.sshUsers, tt.reqUser, got, tt.wantResult)
			}
		})
	}
}

func timePtr(t time.Time) *time.Time { return &t }
