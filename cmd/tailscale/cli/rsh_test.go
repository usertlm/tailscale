// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"
)

func TestParseRshArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantUser string
		wantHost string
		wantCmd  string // joined with space
		wantErr  bool
	}{
		{
			name:     "simple_user_at_host_with_command",
			args:     []string{"alice@myhost", "ls", "-la"},
			wantUser: "alice",
			wantHost: "myhost",
			wantCmd:  "ls -la",
		},
		{
			name:     "bare_host_with_command",
			args:     []string{"myhost", "ls"},
			wantUser: "",
			wantHost: "myhost",
			wantCmd:  "ls",
		},
		{
			name:     "bare_host_no_command",
			args:     []string{"myhost"},
			wantUser: "",
			wantHost: "myhost",
			wantCmd:  "",
		},
		{
			// This is the exact pattern from rsync:
			// tailscale rsh ubuntu@james-ai -l ubuntu james-ai rsync --server --sender -vlogDtpre.iLsfxCIvu . ai/
			name:     "rsync_pattern",
			args:     []string{"ubuntu@james-ai", "-l", "ubuntu", "james-ai", "rsync", "--server", "--sender", "-vlogDtpre.iLsfxCIvu", ".", "ai/"},
			wantUser: "ubuntu",
			wantHost: "james-ai",
			wantCmd:  "rsync --server --sender -vlogDtpre.iLsfxCIvu . ai/",
		},
		{
			name:     "l_flag_overrides_user_at_host",
			args:     []string{"alice@myhost", "-l", "bob", "myhost", "echo", "hi"},
			wantUser: "bob",
			wantHost: "myhost",
			wantCmd:  "echo hi",
		},
		{
			name:     "l_flag_no_space",
			args:     []string{"myhost", "-lubuntu", "myhost", "ls"},
			wantUser: "ubuntu",
			wantHost: "myhost",
			wantCmd:  "ls",
		},
		{
			name:     "l_flag_without_user_at_host",
			args:     []string{"-l", "ubuntu", "myhost", "rsync", "--server"},
			wantUser: "ubuntu",
			wantHost: "myhost",
			wantCmd:  "rsync --server",
		},
		{
			name:     "o_flag_ignored",
			args:     []string{"alice@myhost", "-o", "StrictHostKeyChecking=no", "myhost", "ls"},
			wantUser: "alice",
			wantHost: "myhost",
			wantCmd:  "ls",
		},
		{
			name:     "o_flag_no_space_ignored",
			args:     []string{"alice@myhost", "-oStrictHostKeyChecking=no", "myhost", "ls"},
			wantUser: "alice",
			wantHost: "myhost",
			wantCmd:  "ls",
		},
		{
			name:     "multiple_flags",
			args:     []string{"alice@myhost", "-o", "BatchMode=yes", "-l", "root", "myhost", "uptime"},
			wantUser: "root",
			wantHost: "myhost",
			wantCmd:  "uptime",
		},
		{
			name:     "unknown_flags_skipped",
			args:     []string{"alice@myhost", "-4", "-p", "myhost", "ls"},
			wantUser: "alice",
			wantHost: "myhost",
			wantCmd:  "ls",
		},
		{
			name:     "double_dash_separator",
			args:     []string{"myhost", "--", "-l", "this-is-command"},
			wantUser: "",
			wantHost: "myhost",
			wantCmd:  "-l this-is-command",
		},
		{
			name:    "empty_args",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "l_flag_missing_value",
			args:    []string{"myhost", "-l"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, host, cmdArgs, err := parseRshArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if user != tt.wantUser {
				t.Errorf("user = %q, want %q", user, tt.wantUser)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			gotCmd := strings.Join(cmdArgs, " ")
			if gotCmd != tt.wantCmd {
				t.Errorf("command = %q, want %q", gotCmd, tt.wantCmd)
			}
		})
	}
}
