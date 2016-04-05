package ether

import (
	"net"

	"github.com/songgao/packets/ethernet"
)

// Dev represents a network interface.
type Dev interface {
	// Read reads a ethernet frame into *to. *to is expanded or re-allocated if
	// needed. As a result, a non-nil to pointed to a nil *to would work. If read
	// is successful, *to is resized to properly reflect the frame length.
	Read(to *ethernet.Frame) (err error)

	// Write writes a ethernet frame into the device. from should include
	// ethernet frame header as well as payload, but not ethernet CRC. See
	// ethernet.Frame document for constructing the frame. Caller needs to make
	// sure from has proper length. That is, the slice should be resized to
	// cover exact number of bytes of the frame.
	Write(from ethernet.Frame) error

	// Interface returns the *net.Interface that this Dev operates on.
	Interface() *net.Interface

	// Close closes the device fd. After calling this, this Dev cannot read from
	// or write into the device anymore. This means both Read() Write() should
	// fail on AF_PACKET based systems. On BPF based systems, Write() should
	// fail, and Read() can read until all frames in read buffer are consumed
	// before failing.
	Close() error
}

// NewDev creates a new Dev that operates on ifce, with frameFilter used as a
// filter on incoming frames for Read(). If frameFilter is nil, all frames will
// be returned from Read().
func NewDev(ifce *net.Interface, frameFilter FrameFilter) (dev Dev, err error) {
	return newDev(ifce, frameFilter)
}
