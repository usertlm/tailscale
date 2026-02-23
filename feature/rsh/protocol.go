// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package rsh implements a fast remote shell transport over Tailscale,
// designed as an rsync -e compatible replacement for SSH. It uses a PeerAPI
// endpoint for session setup and a raw TCP data channel for I/O,
// avoiding SSH's double encryption and suboptimal buffering.
package rsh

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Channel type constants for the wire protocol.
// The protocol is length-prefixed framing:
//
//	[1 byte: channel] [4 bytes: length (big-endian)] [N bytes: payload]
const (
	// ChanStdin is data from client to server (remote process stdin).
	ChanStdin byte = 0x00

	// ChanStdout is data from server to client (remote process stdout).
	ChanStdout byte = 0x01

	// ChanStderr is data from server to client (remote process stderr).
	ChanStderr byte = 0x02

	// ChanExit is the exit code from the remote process.
	// Payload is a 4-byte big-endian signed integer exit code.
	// Sent by server to client, then the server closes the connection.
	ChanExit byte = 0x03
)

const (
	// tokenLen is the length of the one-time authentication token.
	tokenLen = 32

	// maxFrameSize is the maximum payload size for a single frame.
	// 256KB is a good balance between throughput and memory usage,
	// matching typical rsync block sizes.
	maxFrameSize = 256 * 1024

	// frameHeaderSize is the size of the frame header (channel + length).
	frameHeaderSize = 5
)

// frameWriter writes length-prefixed frames to an underlying writer.
// It is safe for concurrent use.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// newFrameWriter creates a new frameWriter that writes to w.
func newFrameWriter(w io.Writer) *frameWriter {
	return &frameWriter{w: w}
}

// WriteFrame writes a single frame with the given channel and payload.
func (fw *frameWriter) WriteFrame(ch byte, data []byte) error {
	if len(data) > maxFrameSize {
		return fmt.Errorf("rsh: frame payload too large: %d > %d", len(data), maxFrameSize)
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()

	var hdr [frameHeaderSize]byte
	hdr[0] = ch
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(data)))

	if _, err := fw.w.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := fw.w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// WriteExitCode writes an exit code frame and is a convenience wrapper.
func (fw *frameWriter) WriteExitCode(code int) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(code))
	return fw.WriteFrame(ChanExit, buf[:])
}

// frameReader reads length-prefixed frames from an underlying reader.
type frameReader struct {
	r   io.Reader
	buf []byte // reusable buffer for payloads
}

// newFrameReader creates a new frameReader that reads from r.
func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{
		r:   r,
		buf: make([]byte, 0, 32*1024), // start small, grow as needed
	}
}

// ReadFrame reads the next frame, returning the channel type and payload.
// The returned payload slice is valid until the next call to ReadFrame.
func (fr *frameReader) ReadFrame() (ch byte, data []byte, err error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	ch = hdr[0]
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrameSize {
		return 0, nil, fmt.Errorf("rsh: frame too large: %d > %d", n, maxFrameSize)
	}
	if int(n) > cap(fr.buf) {
		fr.buf = make([]byte, n)
	} else {
		fr.buf = fr.buf[:n]
	}
	if n > 0 {
		if _, err := io.ReadFull(fr.r, fr.buf); err != nil {
			return 0, nil, err
		}
	}
	return ch, fr.buf, nil
}

// channelWriter wraps a frameWriter to implement io.Writer for a specific channel.
type channelWriter struct {
	fw *frameWriter
	ch byte
}

// newChannelWriter returns an io.Writer that writes all data as frames on
// the given channel.
func newChannelWriter(fw *frameWriter, ch byte) io.Writer {
	return &channelWriter{fw: fw, ch: ch}
}

func (cw *channelWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
		}
		if err := cw.fw.WriteFrame(cw.ch, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}
