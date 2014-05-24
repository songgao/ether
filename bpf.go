// +build darwin freebsd
package ether

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"
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
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), uintptr(syscall.BIOCSETIF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		err = errno
		return err
	}
	return
}

func ioCtl(fd *os.File) (buf_len int, err error) {
	buf_len = 1
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), uintptr(syscall.BIOCIMMEDIATE), uintptr(unsafe.Pointer(&buf_len)))
	if errno != 0 {
		err = errno
		return
	}
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), uintptr(syscall.BIOCGBLEN), uintptr(unsafe.Pointer(&buf_len)))
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
	fd     *os.File
	reader chan *FrameWithTime
	writer chan *FrameBuf
	filter FrameFilter
}

// NewDev returns a handle to BPF device. ifName is the interface name to be
// listened on, and frameFilter is used to determine whether a frame should be
// passed into reading channel (Reader()).
func NewDev(ifName string, frameFilter FrameFilter) (dev *bpfDev, err error) {
	dev = new(bpfDev)
	dev.name = ifName
	dev.filter = frameFilter
	dev.fd, err = getBpfFd()
	if err != nil {
		return nil, err
	}
	err = ifReq(dev.fd, ifName)
	if err != nil {
		return nil, err
	}
	dev.reader = make(chan *FrameWithTime, bufferSize)
	dev.writer = make(chan *FrameBuf, bufferSize)

	bufLen, err := ioCtl(dev.fd)
	if err != nil {
		return nil, err
	}
	mtu, err := dev.GetMTU()
	if err != nil {
		return nil, err
	}

	go dev.readFrames(bufLen)
	go dev.writeFrames(mtu)

	return
}

func (d bpfDev) Name() string {
	return d.name
}

func (d bpfDev) GetMTU() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	req := struct {
		Name [0x10]byte
		Mtu  int32
		pad  [0x28 - 0x10 - 0x4]byte
	}{}
	copy(req.Name[:], d.name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.SIOCGIFMTU), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		err = errno
		return -1, err
	}
	return int(req.Mtu), err
}

// Reader returns a channel for reading incoming frames.
func (d bpfDev) Reader() <-chan *FrameWithTime {
	return d.reader
}

// Writer returns a channel for sending frames. Frames sent into the channel
// have to be smaller than MTU, otherwise they are silently discarded.
func (d bpfDev) Writer() chan<- *FrameBuf {
	return d.writer
}

func (d bpfDev) readFrames(bufLen int) {
	buf := make([]byte, bufLen)
	for {
		n, err := d.fd.Read(buf)
		if err != nil {
			return
		}
		p := int(0)
		for p < n {
			hdr := (*bpf_hdr)(unsafe.Pointer(&buf[p]))
			frameStart := p + int(hdr.bh_hdrlen)
			frame := getFrameWithTime(int(hdr.bh_caplen))
			frame.Time = time.Unix(hdr.bh_tstamp.Unix())
			copy(frame.Frame.Data, buf[frameStart:frameStart+int(hdr.bh_caplen)])
			if d.filter != nil && d.filter(frame) {
				d.reader <- frame
			} else {
				frame.ReUse()
			}
			p += bpf_wordalign(int(hdr.bh_hdrlen) + int(hdr.bh_caplen))
		}
	}
}

func (d bpfDev) writeFrames(mtu int) {
	for {
		buf := <-d.writer
		if len(buf.Data) > mtu {
			continue
		}
		n, err := d.fd.Write(buf.Data)
		if n != len(buf.Data) || err != nil {
			log.Printf("Writing frame may have failed. n: %d; len(frame): %d; err: %v\n", n, len(buf.Data), err)
		}
	}
}
