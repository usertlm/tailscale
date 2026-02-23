// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package rsh

import (
	"net"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/wgengine/netstack"
)

func init() {
	netstackListenTCP = netstackListenTCPImpl
}

func netstackListenTCPImpl(b *ipnlocal.LocalBackend, network, address string) (net.Listener, error) {
	ns, ok := b.Sys().Netstack.GetOK()
	if !ok {
		return nil, net.ErrClosed
	}
	// Type-assert to *netstack.Impl which has the ListenTCP method.
	impl, ok := ns.(*netstack.Impl)
	if !ok {
		return nil, net.ErrClosed
	}
	return impl.ListenTCP(network, address)
}
