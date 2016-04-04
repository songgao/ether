// +build linux

package ether

import (
	"errors"
	"fmt"
	"net"
	"syscall"
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
	name   string
	filter FrameFilter

	fd   int
	mtu  int
	addr net.HardwareAddr

	// for outgoing frames
	sockaddrLL *unix.SockaddrLinklayer

	maxFrameSize int
}

func newDev(ifName string, frameFilter FrameFilter) (dev Dev, err error) {
	if len([]byte(ifName)) > unix.IFNAMSIZ {
		err = errors.New("invalid ifName")
		return
	}

	d := new(afpacket)
	d.name = ifName
	d.filter = frameFilter

	d.fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, htons(unix.ETH_P_ALL))
	if err != nil {
		return
	}

	// get interface index
	ifindexSt := struct {
		ifrName    [unix.IFNAMSIZ]byte
		ifrIfindex uint32
	}{}
	copy(ifindexSt.ifrName[:], []byte(ifName))
	var errno syscall.Errno
	_, _, errno = unix.Syscall(syscall.SYS_IOCTL, uintptr(d.fd), uintptr(syscall.SIOCGIFINDEX), uintptr(unsafe.Pointer(&ifindexSt)))
	if errno != 0 {
		err = errno
		return
	}
	index := int(ifindexSt.ifrIfindex)

	// get MAC address
	ifhaddrSt := struct {
		ifrName   [unix.IFNAMSIZ]byte
		ifrHwaddr unix.RawSockaddr
	}{}
	copy(ifhaddrSt.ifrName[:], []byte(ifName))
	_, _, errno = unix.Syscall(syscall.SYS_IOCTL, uintptr(d.fd), uintptr(syscall.SIOCGIFHWADDR), uintptr(unsafe.Pointer(&ifhaddrSt)))
	if errno != 0 {
		err = errno
		return
	}
	for i := 0; i < 6; i++ {
		d.addr = append(d.addr, byte(ifhaddrSt.ifrHwaddr.Data[i]))
	}

	// get MTU
	ifmtuSt := struct {
		ifrName [unix.IFNAMSIZ]byte
		ifrMTU  uint32
	}{}
	copy(ifmtuSt.ifrName[:], []byte(ifName))
	_, _, errno = unix.Syscall(syscall.SYS_IOCTL, uintptr(d.fd), uintptr(syscall.SIOCGIFMTU), uintptr(unsafe.Pointer(&ifmtuSt)))
	if errno != 0 {
		err = errno
		return
	}
	d.mtu = int(ifmtuSt.ifrMTU)

	d.sockaddrLL = new(unix.SockaddrLinklayer)
	d.sockaddrLL.Ifindex = index
	d.sockaddrLL.Halen = 6

	// 6 bytes src, 6 bytes dst, 2 bytes length, plus 802.11q which can be can be
	// up to 8 bytes
	d.maxFrameSize = d.mtu + 22

	dev = d
	return
}

func (d *afpacket) Name() string {
	return d.name
}

func (d *afpacket) GetMTU() int {
	return d.mtu
}

func (d *afpacket) GetHardwareAddr() net.HardwareAddr {
	return append(net.HardwareAddr(nil), d.addr...)
}

func (d *afpacket) Close() error {
	return unix.Close(d.fd)
}

func (d *afpacket) Write(from ethernet.Frame) (err error) {
	if len(from) > d.maxFrameSize {
		err = fmt.Errorf("frame too large (%d); MTU: (%d)", len(from), d.mtu)
	}
	copy(d.sockaddrLL.Addr[:6], []byte(from.Destination()))
	err = unix.Sendto(d.fd, []byte(from), 0, d.sockaddrLL)
	if err != nil {
		return
	}
	return
}

func (d *afpacket) Read(to *ethernet.Frame) (err error) {
	if cap(*to) < d.maxFrameSize {
		*to = make(ethernet.Frame, d.maxFrameSize)
	}
	for {
		*to = (*to)[:cap(*to)]
		var n int
		n, _, err = unix.Recvfrom(d.fd, []byte(*to), 0)
		if err != nil {
			return
		}
		*to = (*to)[:n]
		if !equalMAC(to.Source(), d.addr) && (d.filter == nil || d.filter(*to)) {
			return
		}
	}
}
