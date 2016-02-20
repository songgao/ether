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
	_, err = dev.GetHardwareAddr()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadFrame(t *testing.T) {
	dev, err := NewDev(*dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := dev.Reader()
	for i := 0; i < 16; i++ {
		_ = <-reader
	}
}

func TestWriteFrame(t *testing.T) {
	dev, err := NewDev(*dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := dev.Reader()
	writer := dev.Writer()
	go func() {
		for {
			_ = <-reader
		}
	}()
	dst, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if err != nil {
		t.Fatal("Invalid mac address")
	}
	src, err := net.ParseMAC("12:34:56:78:9a:bc")
	if err != nil {
		t.Fatal("Invalid mac address")
	}
	for i := 0; i < 16; i++ {
		buf := BuildFrame(dst, src, NotTagged, WSMP, 13)
		copy(buf.Data.Payload(), "Hello, World!")
		writer <- buf
	}
}
