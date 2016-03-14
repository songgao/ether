package ether

import "net"

type Dev interface {
	// Read reads a ethernet frame into *to. *to needs to have a capacity
	// sufficiently large to hold a MAC frame with its header and payload,
	// normally 1514 assuming a MTU of 1500 and no tagging. If read is
	// successful, *to is resized to properly reflect the frame length.
	Read(to *Frame) (err error)

	// Write writes a ethernet frame into the device. from should include
	// ethernet frame header as well as payload, but not ethernet CRC. See
	// FillFrameHeader() for filling frame headers. Since ethernet frames don't
	// have a length field, caller needs to make sure from has proper length.
	// That is, the slice should be resized to cover exact number of bytes of the
	// frame.
	Write(from Frame) error

	// Name returns the device name, e.g., en0, eth0, enp0s1, etc.
	Name() string

	// GetMTU returns MAC layer MTU of the device.
	GetMTU() int

	// GetHardwareAddr returns the MAC address of the device.
	GetHardwareAddr() net.HardwareAddr

	// Close closes the device fd. After calling this, this Dev cannot read from
	// or write into the device anymore. This means both Read() Write() should
	// fail on AF_PACKET based systems. On BPF based systems, Write() should
	// fail, and Read() can read until all cached frames are consumed before
	// failing.
	Close() error
}
