package ether

import (
	"bytes"
	"net"

	"github.com/songgao/packets/ethernet"
)

// FrameFilter defines filter used for filtering incoming frames. It is used by
// Dev.Read() on each incoming frame. Return false to discard the frame, or
// true to take the frame.
type FrameFilter func(frame ethernet.Frame) bool

func equalMAC(a, b net.HardwareAddr) bool {
	return bytes.Equal([]byte(a), []byte(b))
}
