// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ((linux && !android) || (darwin && !ios) || freebsd || openbsd) && !ts_omit_rsh

package condregister

import _ "tailscale.com/feature/rsh"
