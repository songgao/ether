// +build linux

package ether

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

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
	sockaddr_ll *unix.SockaddrLinklayer

	// for incoming frames
	buf []byte
}

func NewDev(ifName string, frameFilter FrameFilter) (dev Dev, err error) {
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
	ifindex_st := struct {
		ifr_name    [unix.IFNAMSIZ]byte
		ifr_ifindex uint32
	}{}
	copy(ifindex_st.ifr_name[:], []byte(ifName))
	var errno syscall.Errno
	_, _, errno = unix.Syscall(syscall.SYS_IOCTL, uintptr(d.fd), uintptr(syscall.SIOCGIFINDEX), uintptr(unsafe.Pointer(&ifindex_st)))
	if errno != 0 {
		err = errno
		return
	}
	index := int(ifindex_st.ifr_ifindex)

	// get MAC address
	ifhaddr_st := struct {
		ifr_name   [unix.IFNAMSIZ]byte
		ifr_hwaddr unix.RawSockaddr
	}{}
	copy(ifhaddr_st.ifr_name[:], []byte(ifName))
	_, _, errno = unix.Syscall(syscall.SYS_IOCTL, uintptr(d.fd), uintptr(syscall.SIOCGIFHWADDR), uintptr(unsafe.Pointer(&ifhaddr_st)))
	if errno != 0 {
		err = errno
		return
	}
	for i := 0; i < 6; i++ {
		d.addr = append(d.addr, byte(ifhaddr_st.ifr_hwaddr.Data[i]))
	}

	// get MTU
	ifmtu_st := struct {
		ifr_name [unix.IFNAMSIZ]byte
		ifr_mtu  uint32
	}{}
	copy(ifmtu_st.ifr_name[:], []byte(ifName))
	_, _, errno = unix.Syscall(syscall.SYS_IOCTL, uintptr(d.fd), uintptr(syscall.SIOCGIFMTU), uintptr(unsafe.Pointer(&ifmtu_st)))
	if errno != 0 {
		err = errno
		return
	}
	d.mtu = int(ifmtu_st.ifr_mtu)

	d.sockaddr_ll = new(unix.SockaddrLinklayer)
	d.sockaddr_ll.Ifindex = index
	d.sockaddr_ll.Halen = 6

	d.buf = make([]byte, d.mtu+20)

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

func (d *afpacket) Write(from Frame) (err error) {
	if len(from) > d.mtu {
		err = fmt.Errorf("frame too large (%d); MTU: (%d)", len(from), d.mtu)
	}
	copy(d.sockaddr_ll.Addr[:6], []byte(from.Destination()))
	err = unix.Sendto(d.fd, []byte(from), 0, d.sockaddr_ll)
	if err != nil {
		return
	}
	return
}

func (d *afpacket) Read(to *Frame) (err error) {
	for {
		var n int
		n, _, err = unix.Recvfrom(d.fd, d.buf, 0)
		if err != nil {
			return
		}
		if cap(*to) < n {
			err = fmt.Errorf("destination buffer too small (%d); need (%d)\n", len(*to), n)
			return
		}
		*to = (*to)[:n]
		copy(*to, d.buf[:n])
		if !equalMAC(to.Source(), d.addr) && (d.filter == nil || d.filter(*to)) {
			return
		}
	}
}
