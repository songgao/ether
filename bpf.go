// +build darwin freebsd

package ether

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/songgao/packets/ethernet"

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

func ioCtl(fd *os.File) (bufLen int, err error) {
	bufLen = 1
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCIMMEDIATE), uintptr(unsafe.Pointer(&bufLen)))
	if errno != 0 {
		err = errno
		return
	}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd.Fd(), uintptr(unix.BIOCGBLEN), uintptr(unsafe.Pointer(&bufLen)))
	if errno != 0 {
		err = errno
	}
	return
}

func bpfWordalign(x int) int {
	return (((x) + (wordLength - 1)) &^ (wordLength - 1))
}

type bpfDev struct {
	ifce   *net.Interface
	fd     *os.File
	filter FrameFilter

	// bpf may return more than one frame per read() call
	readBuf []byte
	p       int
	n       int
}

// NewDev returns a handle to BPF device. ifName is the interface name to be
// listened on, and frameFilter is used to determine whether a frame should be
// discarded when reading. Set it to nil to disable filtering.
// TODO: use kernel for filtering
func newDev(ifce *net.Interface, frameFilter FrameFilter) (dev Dev, err error) {
	d := new(bpfDev)
	d.ifce = ifce
	d.filter = frameFilter
	d.fd, err = getBpfFd()
	if err != nil {
		return
	}
	err = ifReq(d.fd, ifce.Name)
	if err != nil {
		return
	}

	var bufLen int
	bufLen, err = ioCtl(d.fd)
	if err != nil {
		return
	}

	d.readBuf = make([]byte, bufLen)

	dev = d

	return
}

func (d *bpfDev) Interface() *net.Interface {
	return d.ifce
}

func (d *bpfDev) Read(to *ethernet.Frame) (err error) {
	to.Resize(d.ifce.MTU)
	for {
		for d.p < d.n {
			hdr := (*bpfHdr)(unsafe.Pointer(&d.readBuf[d.p]))
			frameStart := d.p + int(hdr.hdrlen)
			n := int(hdr.caplen)
			*to = (*to)[:n]
			copy(*to, d.readBuf[frameStart:frameStart+n])
			d.p += bpfWordalign(int(hdr.hdrlen) + int(hdr.caplen))
			if !equalMAC(to.Source(), d.ifce.HardwareAddr) && (d.filter == nil || d.filter(*to)) {
				return
			}
		}

		d.n, err = d.fd.Read(d.readBuf)
		if err != nil {
			return
		}
		d.p = 0
	}
}

func (d *bpfDev) Write(from ethernet.Frame) (err error) {
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
