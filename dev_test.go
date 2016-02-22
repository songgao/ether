package ether

import (
	"flag"
	"net"
	"os"
	"testing"
)

var dev = flag.String("dev", "en0", "interface name")

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestNewDev(t *testing.T) {
	dev, err := NewDev(*dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = dev.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadFrame(t *testing.T) {
	dev, err := NewDev(*dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	to := make(Frame, 1600)
	for i := 0; i < 16; i++ {
		_, err = dev.Read(to)
		if err != nil {
			t.Fatal(err)
		}
	}

	err = dev.Close()
	if err != nil {
		t.Fatal(err)
	}

	_, err = dev.Read(to)
	if err == nil {
		t.Fatal("closed Dev can still read")
	}
}

func TestWriteFrame(t *testing.T) {
	dev, err := NewDev(*dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if err != nil {
		t.Fatal(err)
	}
	src, err := net.ParseMAC("12:34:56:78:9a:bc")
	if err != nil {
		t.Fatal(err)
	}
	frame := make(Frame, 1514)
	w := func() (err error) {
		_, err = FillFrameHeader(frame, dst, src, NotTagged, WSMP)
		if err != nil {
			return
		}
		copy(frame.Payload(), "Hello, World!")
		err = dev.Write(frame)
		if err != nil {
			return
		}
		return
	}
	for i := 0; i < 16; i++ {
		if nil != w() {
			t.Fatal(err)
		}
	}

	err = dev.Close()
	if err != nil {
		t.Fatal(err)
	}

	if nil == w() {
		t.Fatal("closed Dev can still write")
	}
}
