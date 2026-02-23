// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package rsh

import (
	"errors"
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
)

// evalResult is the result of SSH policy evaluation.
type evalResult int

const (
	evalAccepted     evalResult = iota // rule matched with Accept
	evalRejected                       // no matching rule, or explicit Reject
	evalRejectedUser                   // principal matched but user mapping failed
	evalHoldDelegate                   // rule matched with HoldAndDelegate (check mode)
)

// evalSSHPolicy evaluates the SSH policy for the given parameters.
// This replicates the core matching logic from ssh/tailssh without
// depending on the SSH connection type.
//
// It returns the matching action, the mapped local user, and the evaluation result.
func evalSSHPolicy(
	pol *tailcfg.SSHPolicy,
	node tailcfg.NodeView,
	uprof tailcfg.UserProfile,
	srcAddr netip.Addr,
	sshUser string,
	now time.Time,
) (action *tailcfg.SSHAction, localUser string, result evalResult) {
	if pol == nil {
		return nil, "", evalRejected
	}
	failedOnUser := false
	for _, r := range pol.Rules {
		if a, lu, err := matchRule(r, node, uprof, srcAddr, sshUser, now); err == nil {
			if a.HoldAndDelegate != "" {
				return a, lu, evalHoldDelegate
			}
			return a, lu, evalAccepted
		} else if errors.Is(err, errUserMatch) {
			failedOnUser = true
		}
	}
	if failedOnUser {
		return nil, "", evalRejectedUser
	}
	return nil, "", evalRejected
}

var (
	errNilRule        = errors.New("nil rule")
	errNilAction      = errors.New("nil action")
	errRuleExpired    = errors.New("rule expired")
	errPrincipalMatch = errors.New("principal didn't match")
	errUserMatch      = errors.New("user didn't match")
)

// matchRule checks whether a single SSHRule matches the given parameters.
func matchRule(
	r *tailcfg.SSHRule,
	node tailcfg.NodeView,
	uprof tailcfg.UserProfile,
	srcAddr netip.Addr,
	sshUser string,
	now time.Time,
) (action *tailcfg.SSHAction, localUser string, err error) {
	if r == nil {
		return nil, "", errNilRule
	}
	if r.Action == nil {
		return nil, "", errNilAction
	}
	if r.RuleExpires != nil && r.RuleExpires.Before(now) {
		return nil, "", errRuleExpired
	}
	if !anyPrincipalMatches(r.Principals, node, uprof, srcAddr) {
		return nil, "", errPrincipalMatch
	}
	if !r.Action.Reject {
		localUser = mapLocalUser(r.SSHUsers, sshUser)
		if localUser == "" {
			return nil, "", errUserMatch
		}
	}
	return r.Action, localUser, nil
}

// anyPrincipalMatches reports whether any of the given principals match
// the Tailscale identity of the connecting peer.
func anyPrincipalMatches(
	ps []*tailcfg.SSHPrincipal,
	node tailcfg.NodeView,
	uprof tailcfg.UserProfile,
	srcAddr netip.Addr,
) bool {
	for _, p := range ps {
		if p == nil {
			continue
		}
		if principalMatchesTailscaleIdentity(p, node, uprof, srcAddr) {
			return true
		}
	}
	return false
}

// principalMatchesTailscaleIdentity reports whether a principal matches
// the Tailscale identity of the connecting peer.
func principalMatchesTailscaleIdentity(
	p *tailcfg.SSHPrincipal,
	node tailcfg.NodeView,
	uprof tailcfg.UserProfile,
	srcAddr netip.Addr,
) bool {
	if p.Any {
		return true
	}
	if !p.Node.IsZero() && node.Valid() && p.Node == node.StableID() {
		return true
	}
	if p.NodeIP != "" {
		if ip, _ := netip.ParseAddr(p.NodeIP); ip == srcAddr {
			return true
		}
	}
	if p.UserLogin != "" && uprof.LoginName == p.UserLogin {
		return true
	}
	return false
}

// mapLocalUser maps an SSH user to a local user using the SSHUsers map
// from a policy rule.
func mapLocalUser(ruleSSHUsers map[string]string, reqSSHUser string) string {
	v, ok := ruleSSHUsers[reqSSHUser]
	if !ok {
		v = ruleSSHUsers["*"]
	}
	if v == "=" {
		return reqSSHUser
	}
	return v
}
