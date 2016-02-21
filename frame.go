package ether

import (
	"fmt"
	"net"
)

type Frame []byte

// Indicating whether/how a frame is tagged. The value is number of bytes taken
// by tagging.
type Tagging int

const (
	NotTagged    Tagging = 0
	Tagged       Tagging = 4
	DoubleTagged Tagging = 8
)

// Destination returns the destination address field of the frame.
func (f Frame) Destination() net.HardwareAddr {
	return net.HardwareAddr(f[:6:6])
}

// Source returns the source address field of the frame.
func (f Frame) Source() net.HardwareAddr {
	return net.HardwareAddr(f[6:12:12])
}

// Tagging returns whether/how the frame has 802.1Q tag(s).
func (f Frame) Tagging() Tagging {
	if f[12] == 0x81 && f[13] == 0x00 {
		return Tagged
	} else if f[12] == 0x88 && f[13] == 0xa8 {
		return DoubleTagged
	}
	return NotTagged
}

// Tag returns a slice holding the tag part of the frame, if any. Upper
// layer should use the returned slice for both reading and writing.
func (f Frame) Tag() []byte {
	tagging := f.Tagging()
	return f[12 : 12+tagging : 12+tagging]
}

// Ethertype returns the ethertype field of the frame.
func (f Frame) Ethertype() Ethertype {
	ethertypePos := 12 + f.Tagging()
	return Ethertype{f[ethertypePos], f[ethertypePos+1]}
}

// Payload returns a slice holding the payload part of the frame. Upper layer
// should use the returned slice for both reading and writing purposes.
func (f Frame) Payload() []byte {
	return f[12+f.Tagging()+2:]
}

// FillFrameHeader fills ethernet header in frame, starting from index 0, and
// returns length of the header written. If length of frame is not large
// enough for the header, an error is returned. This funcion does not change
// length of frame slice. Caller is responsible of resizing the slice according
// to header length as well as payload size.
func FillFrameHeader(frame Frame, dst net.HardwareAddr, src net.HardwareAddr, tagging Tagging, ethertype Ethertype) (headerLength int, err error) {
	headerLength = 6 + 6 + int(tagging) + 2
	if headerLength > len(frame) {
		err = fmt.Errorf("frame buffer length [%d] is smaller than required frame header length [%d]", len(frame), headerLength)
	}
	copy(frame[0:6:6], dst)
	copy(frame[6:12:12], src)
	if tagging == Tagged {
		frame[12] = 0x81
		frame[13] = 0x00
	} else if tagging == DoubleTagged {
		frame[12] = 0x88
		frame[13] = 0xa8
	}
	frame[12+tagging] = ethertype[0]
	frame[12+tagging+1] = ethertype[1]
	return
}

type FrameFilter func(frame Frame) bool
