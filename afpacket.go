// +build linux

package ether

import (
	"net"
	"unsafe"

	"github.com/songgao/packets/ethernet"

	"golang.org/x/sys/unix"
)

func htons(h int) (n int) {
	a := uint16(42)
	if *(*byte)(unsafe.Pointer(&a)) == 42 { // little-endian
		a = uint16(h)
		n = int(a>>8 | a<<8)
	} else { // big-endian
		n = h
	}
	return
}

type afpacket struct {
	ifce   *net.Interface
	filter FrameFilter

	fd int

	// for outgoing frames
	sockaddrLL *unix.SockaddrLinklayer
}

func newDev(ifce *net.Interface, frameFilter FrameFilter) (dev Dev, err error) {
	d := new(afpacket)
	d.ifce = ifce
	d.filter = frameFilter

	d.fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, htons(unix.ETH_P_ALL))
	if err != nil {
		return
	}

	d.sockaddrLL = new(unix.SockaddrLinklayer)
	d.sockaddrLL.Ifindex = ifce.Index
	d.sockaddrLL.Halen = 6

	dev = d
	return
}

func (d *afpacket) Interface() *net.Interface {
	return d.ifce
}

func (d *afpacket) Close() error {
	return unix.Close(d.fd)
}

func (d *afpacket) Write(from ethernet.Frame) (err error) {
	copy(d.sockaddrLL.Addr[:6], []byte(from.Destination()))
	err = unix.Sendto(d.fd, []byte(from), 0, d.sockaddrLL)
	if err != nil {
		return
	}
	return
}

func (d *afpacket) Read(to *ethernet.Frame) (err error) {
	to.Resize(d.ifce.MTU)
	for {
		*to = (*to)[:cap(*to)]
		var n int
		n, _, err = unix.Recvfrom(d.fd, []byte(*to), 0)
		if err != nil {
			return
		}
		*to = (*to)[:n]
		if !equalMAC(to.Source(), d.ifce.HardwareAddr) && (d.filter == nil || d.filter(*to)) {
			return
		}
	}
}
