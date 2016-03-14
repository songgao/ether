// +build darwin freebsd

package ether

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func getBpfFd() (file *os.File, err error) {
	for i := 0; i < 99; i++ {
		file, err = os.OpenFile(fmt.Sprintf("/dev/bpf%d", i), os.O_RDWR, 0)
		if err == nil {
			return
		}
	}
	return
}

func ifReq(fd *os.File, ifName string) (err error) {
	if len(ifName) > 0x10 {
		return errors.New("Invalid ifname.")
	}
	req := struct {
		Name [0x10]byte
		pad  [0x28 - 0x10]byte
	}{}
	copy(req.Name[:], ifName)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		err = errno
		return err
	}
	return
}

func ioCtl(fd *os.File) (buf_len int, err error) {
	buf_len = 1
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCIMMEDIATE), uintptr(unsafe.Pointer(&buf_len)))
	if errno != 0 {
		err = errno
		return
	}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCGBLEN), uintptr(unsafe.Pointer(&buf_len)))
	if errno != 0 {
		err = errno
	}
	return
}

func bpf_wordalign(x int) int {
	return (((x) + (word_length - 1)) &^ (word_length - 1))
}

type bpfDev struct {
	name   string
	addr   net.HardwareAddr
	fd     *os.File
	filter FrameFilter
	mtu    int

	// bpf may return more than one frame per read() call
	readBuf []byte
	p       int
	n       int
}

// NewDev returns a handle to BPF device. ifName is the interface name to be
// listened on, and frameFilter is used to determine whether a frame should be
// discarded when reading. Set it to nil to disable filtering.
// TODO: use kernel for filtering
func NewDev(ifName string, frameFilter FrameFilter) (dev Dev, err error) {
	d := new(bpfDev)
	d.name = ifName
	d.filter = frameFilter
	d.fd, err = getBpfFd()
	if err != nil {
		return
	}
	err = ifReq(d.fd, ifName)
	if err != nil {
		return
	}

	var bufLen int
	bufLen, err = ioCtl(d.fd)
	if err != nil {
		return
	}
	_, err = d.getMTU()
	if err != nil {
		return
	}
	_, err = d.getHardwareAddr()
	if err != nil {
		return
	}

	d.readBuf = make([]byte, bufLen)

	dev = d

	return
}

func (d *bpfDev) Name() string {
	return d.name
}

func (d *bpfDev) GetHardwareAddr() net.HardwareAddr {
	return append(net.HardwareAddr(nil), d.addr...)
}

func (d *bpfDev) getHardwareAddr() (net.HardwareAddr, error) {
	if d.addr != nil {
		return d.addr, nil
	}
	out, err := exec.Command("ifconfig", d.name).Output()
	if err != nil {
		return nil, err
	}
	str := string(out)
	pos := strings.Index(str, "ether ")
	if pos < 0 || pos+6+17 > len(str) {
		return nil, errors.New("ether keyword not found in ifconfig output")
	}
	d.addr, err = net.ParseMAC(str[pos+6 : pos+6+17])
	return d.addr, err
}

func (d *bpfDev) GetMTU() int {
	return d.mtu
}

func (d *bpfDev) getMTU() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	req := struct {
		Name [0x10]byte
		Mtu  int32
		pad  [0x28 - 0x10 - 0x4]byte
	}{}
	copy(req.Name[:], d.name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCGIFMTU), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		err = errno
		return -1, err
	}
	d.mtu = int(req.Mtu)
	return d.mtu, err
}

func (d *bpfDev) Read(to *Frame) (err error) {
	for {
		for d.p < d.n {
			hdr := (*bpf_hdr)(unsafe.Pointer(&d.readBuf[d.p]))
			frameStart := d.p + int(hdr.bh_hdrlen)
			n := int(hdr.bh_caplen)
			if cap(*to) < n {
				err = fmt.Errorf("destination buffer too small (%d); need (%d)\n", len(*to), n)
				return
			}
			*to = (*to)[:n]
			copy(*to, d.readBuf[frameStart:frameStart+n])
			d.p += bpf_wordalign(int(hdr.bh_hdrlen) + int(hdr.bh_caplen))
			if !equalMAC(to.Source(), d.addr) && (d.filter == nil || d.filter(*to)) {
				return
			}
		}

		d.n, err = d.fd.Read([]byte(d.readBuf))
		if err != nil {
			return
		}
		d.p = 0
	}
}

func (d *bpfDev) Write(from Frame) (err error) {
	if len(from) > d.mtu {
		err = fmt.Errorf("frame too large (%d); MTU: (%d)", len(from), d.mtu)
	}
	var n int
	n, err = d.fd.Write([]byte(from))
	if err != nil {
		return
	}
	if n != len(from) {
		err = fmt.Errorf("writing frame may have failed. written [%d] != len(frame) [%d]", n, len(from))
		return
	}
	return
}

func (d *bpfDev) Close() error {
	return d.fd.Close()
}
