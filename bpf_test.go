// +build darwin
//
package ether

import (
	"net"
	"testing"
)

func TestNewDev(t *testing.T) {
	dev, err := NewDev("en0", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dev.GetHardwareAddr()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadFrame(t *testing.T) {
	dev, err := NewDev("en0", nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := dev.Reader()
	for i := 0; i < 64; i++ {
		f := <-reader
		if f.Frame.Data.Ethertype() == IPv4 {
			t.Logf("IPv4 packet. Src: %v; Dst: %v\n", f.Frame.Data.Source(), f.Frame.Data.Destination())
		}
	}
}

func TestWriteFrame(t *testing.T) {
	dev, err := NewDev("en0", nil)
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
	for i := 0; i < 8; i++ {
		buf := BuildFrame(dst, src, NotTagged, WSMP, 13)
		copy(buf.Data.Payload(), "Hello, World!")
		writer <- buf
	}
}
