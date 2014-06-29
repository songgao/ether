package ether

import "net"

type Dev interface {
	Reader() <-chan *FrameWithTime
	Writer() chan<- *FrameBuf
	Name() string
	GetMTU() (int, error)
	GetHardwareAddr() (net.HardwareAddr, error)
}
