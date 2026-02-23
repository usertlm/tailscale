// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rsh

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	var buf bytes.Buffer

	fw := newFrameWriter(&buf)
	fr := newFrameReader(&buf)

	// Write several frames.
	if err := fw.WriteFrame(ChanStdout, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame stdout: %v", err)
	}
	if err := fw.WriteFrame(ChanStderr, []byte("world")); err != nil {
		t.Fatalf("WriteFrame stderr: %v", err)
	}
	if err := fw.WriteFrame(ChanStdin, []byte("input")); err != nil {
		t.Fatalf("WriteFrame stdin: %v", err)
	}
	if err := fw.WriteExitCode(42); err != nil {
		t.Fatalf("WriteExitCode: %v", err)
	}

	// Read them back.
	ch, data, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	if ch != ChanStdout || string(data) != "hello" {
		t.Errorf("frame 1: got ch=%d data=%q, want ch=%d data=%q", ch, data, ChanStdout, "hello")
	}

	ch, data, err = fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	if ch != ChanStderr || string(data) != "world" {
		t.Errorf("frame 2: got ch=%d data=%q, want ch=%d data=%q", ch, data, ChanStderr, "world")
	}

	ch, data, err = fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 3: %v", err)
	}
	if ch != ChanStdin || string(data) != "input" {
		t.Errorf("frame 3: got ch=%d data=%q, want ch=%d data=%q", ch, data, ChanStdin, "input")
	}

	ch, data, err = fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 4: %v", err)
	}
	if ch != ChanExit {
		t.Errorf("frame 4: got ch=%d, want ch=%d", ch, ChanExit)
	}
	if len(data) != 4 {
		t.Fatalf("exit frame data len = %d, want 4", len(data))
	}
	code := int(binary.BigEndian.Uint32(data))
	if code != 42 {
		t.Errorf("exit code = %d, want 42", code)
	}

	// Should get EOF now.
	_, _, err = fr.ReadFrame()
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Errorf("expected EOF after all frames, got: %v", err)
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	fw := newFrameWriter(&buf)
	fr := newFrameReader(&buf)

	if err := fw.WriteFrame(ChanStdin, nil); err != nil {
		t.Fatalf("WriteFrame empty: %v", err)
	}

	ch, data, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if ch != ChanStdin {
		t.Errorf("ch = %d, want %d", ch, ChanStdin)
	}
	if len(data) != 0 {
		t.Errorf("data len = %d, want 0", len(data))
	}
}

func TestFrameTooLarge(t *testing.T) {
	fw := newFrameWriter(io.Discard)
	data := make([]byte, maxFrameSize+1)
	if err := fw.WriteFrame(ChanStdout, data); err == nil {
		t.Error("expected error for oversized frame, got nil")
	}
}

func TestFrameReaderTooLarge(t *testing.T) {
	// Construct a frame with length > maxFrameSize.
	var buf bytes.Buffer
	var hdr [frameHeaderSize]byte
	hdr[0] = ChanStdout
	binary.BigEndian.PutUint32(hdr[1:], maxFrameSize+1)
	buf.Write(hdr[:])

	fr := newFrameReader(&buf)
	_, _, err := fr.ReadFrame()
	if err == nil {
		t.Error("expected error for oversized frame in reader, got nil")
	}
}

func TestChannelWriter(t *testing.T) {
	var buf bytes.Buffer
	fw := newFrameWriter(&buf)
	cw := newChannelWriter(fw, ChanStdout)

	data := []byte("hello world from channel writer")
	n, err := cw.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("n = %d, want %d", n, len(data))
	}

	fr := newFrameReader(&buf)
	ch, got, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if ch != ChanStdout {
		t.Errorf("ch = %d, want %d", ch, ChanStdout)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("data mismatch: got %q, want %q", got, data)
	}
}

func TestChannelWriterChunking(t *testing.T) {
	var buf bytes.Buffer
	fw := newFrameWriter(&buf)
	cw := newChannelWriter(fw, ChanStdout)

	// Write more than maxFrameSize to verify chunking.
	data := make([]byte, maxFrameSize+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	n, err := cw.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("n = %d, want %d", n, len(data))
	}

	// Should produce two frames.
	fr := newFrameReader(&buf)

	ch, chunk1, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	if ch != ChanStdout || len(chunk1) != maxFrameSize {
		t.Errorf("frame 1: ch=%d len=%d, want ch=%d len=%d", ch, len(chunk1), ChanStdout, maxFrameSize)
	}

	ch, chunk2, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	if ch != ChanStdout || len(chunk2) != 100 {
		t.Errorf("frame 2: ch=%d len=%d, want ch=%d len=%d", ch, len(chunk2), ChanStdout, 100)
	}
}
