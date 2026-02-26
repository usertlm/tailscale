// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"testing"
	"time"
)

func TestQDTracker(t *testing.T) {
	const packetsPerSecond = 10
	const timeout = 2 * time.Second
	tracker := newQDTracker(packetsPerSecond, timeout)

	// Verify capacity calculation
	wantCap := 21 // ceil(10 * 2.0) + 1
	if got := cap(tracker.records); got != wantCap {
		t.Fatalf("capacity = %d, want %d", got, wantCap)
	}

	// Add some records
	now := time.Now()
	for i := range uint64(5) {
		if tracker.add(i, now.Add(time.Duration(i)*100*time.Millisecond)) {
			t.Fatalf("unexpected overflow on add %d", i)
		}
	}

	// Find and remove existing record
	sentAt, found := tracker.findAndRemove(2)
	if !found {
		t.Fatal("expected to find seq 2")
	}
	if want := now.Add(200 * time.Millisecond); sentAt != want {
		t.Errorf("sentAt = %v, want %v", sentAt, want)
	}

	// Try to find already-removed record
	if _, found := tracker.findAndRemove(2); found {
		t.Error("found seq 2 after removal")
	}

	// Find non-existent future record
	if _, found := tracker.findAndRemove(100); found {
		t.Error("found seq 100 which was never added")
	}

	// Advance time and apply timeouts
	now = now.Add(timeout + time.Second)
	dropped := tracker.applyTimeouts(now)
	if dropped != 4 { // 5 added - 1 already removed = 4
		t.Errorf("dropped = %d, want 4", dropped)
	}

	// Verify all records expired
	if len(tracker.records) != 0 {
		t.Errorf("len(records) = %d, want 0", len(tracker.records))
	}
}

func TestQDTrackerOverflow(t *testing.T) {
	tracker := newQDTracker(2, time.Second) // cap = 3
	now := time.Now()

	// Fill to capacity
	for i := range uint64(3) {
		if tracker.add(i, now) {
			t.Fatalf("unexpected overflow at %d/3", i)
		}
	}

	// Next add should overflow
	if !tracker.add(3, now) {
		t.Error("expected overflow, got none")
	}

	// Oldest record (seq=0) should be gone
	if _, found := tracker.findAndRemove(0); found {
		t.Error("found seq 0 after overflow eviction")
	}

	// Newer records should exist
	if _, found := tracker.findAndRemove(1); !found {
		t.Error("expected to find seq 1")
	}
}

func TestQDTrackerTimeoutEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		packetsPerSec int
		timeout       time.Duration
		wantCap       int
	}{
		{"whole_seconds", 10, 2 * time.Second, 21},
		{"fractional", 10, 1500 * time.Millisecond, 16},
		{"subsecond", 100, 500 * time.Millisecond, 51},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := newQDTracker(tt.packetsPerSec, tt.timeout)
			if got := cap(tracker.records); got != tt.wantCap {
				t.Errorf("capacity = %d, want %d", got, tt.wantCap)
			}
		})
	}
}

func TestQDTrackerPartialTimeout(t *testing.T) {
	tracker := newQDTracker(10, time.Second)
	now := time.Now()

	// Add records at different times
	tracker.add(0, now)
	tracker.add(1, now.Add(100*time.Millisecond))
	tracker.add(2, now.Add(500*time.Millisecond))
	tracker.add(3, now.Add(900*time.Millisecond))

	// Advance past timeout for first two records only
	checkTime := now.Add(1200 * time.Millisecond)
	dropped := tracker.applyTimeouts(checkTime)
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}

	// Verify correct records remain
	tests := []struct {
		seq   uint64
		found bool
	}{
		{0, false}, // timed out
		{1, false}, // timed out
		{2, true},  // still valid
		{3, true},  // still valid
	}

	for _, tt := range tests {
		_, found := tracker.findAndRemove(tt.seq)
		if found != tt.found {
			t.Errorf("seq %d: found = %v, want %v", tt.seq, found, tt.found)
		}
	}
}
