package ether

import "time"

type FrameWithTime struct {
	Time  time.Time
	Frame *FrameBuf
}

var frameWithTimeBuffer chan *FrameWithTime

// ReUse puts the FrameWithTime, along with the FrameBuf instance in it, back
// to internal buffer. It should only be called when the information held in
// the instance will never be used in the future. This is to reduce pressure on
// GC.
func (f *FrameWithTime) ReUse() {
	if frameWithTimeBuffer == nil {
		frameWithTimeBuffer = make(chan *FrameWithTime, bufferSize)
	}
	f.Frame.ReUse()
	select {
	case frameWithTimeBuffer <- f:
	default:
	}
}

func getFrameWithTime(bufSize int) *FrameWithTime {
	if frameWithTimeBuffer == nil {
		frameWithTimeBuffer = make(chan *FrameWithTime, bufferSize)
	}
	var ret *FrameWithTime
	select {
	case ret = <-frameWithTimeBuffer:
	default:
		ret = new(FrameWithTime)
	}
	ret.Frame = getFrameBuf(bufSize)
	return ret
}

type FrameBuf struct {
	Data Frame
	data Frame
}

type Frame []byte

var frameBufBuffer chan *FrameBuf

// ReUse puts the FrameBuf back to internal buffer. It should only be called
// when the information held in the instance will never be used in the future.
// This is to reduce pressure on GC.
func (f *FrameBuf) ReUse() {
	if frameBufBuffer == nil {
		frameBufBuffer = make(chan *FrameBuf, bufferSize)
	}
	select {
	case frameBufBuffer <- f:
	default:
	}
}

// GetFrameBuf gets a FrameBuf instance, either by constructing a new one or by
// re-use one on which ReUse() method has been called.
func getFrameBuf(bufSize int) *FrameBuf {
	if frameBufBuffer == nil {
		frameBufBuffer = make(chan *FrameBuf, bufferSize)
	}
	var ret *FrameBuf
	select {
	case ret = <-frameBufBuffer:
	default:
		ret = &FrameBuf{data: make([]byte, bufSize)}
	}
	if bufSize > len(ret.data) {
		ret.data = make([]byte, bufSize)
	}
	ret.Data = ret.data[0:bufSize:bufSize]
	return ret
}
