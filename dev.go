package ether

type Dev interface {
	Reader() <-chan *FrameWithTime
	Writer() chan<- *FrameBuf
	Name() string
	GetMTU() (int, error)
}
