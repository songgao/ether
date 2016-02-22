package ether

import (
	"net"
	"time"
)

type Dev interface {
	// Read reads a ethernet frame into to, and returns its timestamp if
	// successfull. to needs to be sufficiently large to hold a MAC frame with
	// its header and payload, normally 1514 assuming a MTU of 1500 and no
	// tagging.
	Read(to Frame) (ts time.Time, err error)

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

	// Close closes the device fd. After calling this, this Dev cannot be used to
	// read from or write into the device anymore.
	Close() error
}
