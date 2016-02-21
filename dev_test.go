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
	addr, err := dev.GetHardwareAddr()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("hardware addr: %v\n", addr)
	mtu, err := dev.GetMTU()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MTU: %v\n", mtu)
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
}

func TestWriteFrame(t *testing.T) {
	dev, err := NewDev(*dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if err != nil {
		t.Fatal("Invalid mac address")
	}
	src, err := net.ParseMAC("12:34:56:78:9a:bc")
	if err != nil {
		t.Fatal("Invalid mac address")
	}
	frame := make(Frame, 1514)
	for i := 0; i < 16; i++ {
		_, err = FillFrameHeader(frame, dst, src, NotTagged, WSMP)
		if err != nil {
			t.Fatal(err)
		}
		copy(frame.Payload(), "Hello, World!")
		err = dev.Write(frame)
		if err != nil {
			t.Fatal("Invalid mac address")
		}
	}
}
