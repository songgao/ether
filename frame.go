package ether

import (
	"net"
)

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
// layer should use the returned slice for both reading and writing
// purposes.
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

// BuildFrame returns a FrameBuf instance with proper length, with
// destination/source addresses, tagging, ethertype filled.
func BuildFrame(dst net.HardwareAddr, src net.HardwareAddr, tagging Tagging, ethertype Ethertype, payloadLength int) *FrameBuf {
	buf := getFrameBuf(6 + 6 + int(tagging) + 2 + payloadLength)
	copy(buf.Data[0:6:6], dst)
	copy(buf.Data[6:12:12], src)
	if tagging == Tagged {
		buf.Data[12] = 0x81
		buf.Data[13] = 0x00
	} else if tagging == DoubleTagged {
		buf.Data[12] = 0x88
		buf.Data[13] = 0xa8
	}
	buf.Data[12+tagging] = ethertype[0]
	buf.Data[12+tagging+1] = ethertype[1]
	return buf
}

type FrameFilter func(frame *FrameWithTime) bool
