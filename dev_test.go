package ether

import (
	"flag"
	"net"
	"os"
	"testing"

	"github.com/songgao/packets/ethernet"
)

var dev = flag.String("dev", "en0", "interface name")
var ifce *net.Interface

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestNewDev(t *testing.T) {
	var (
		ifce *net.Interface
		err  error
		d    Dev
	)
	if ifce, err = net.InterfaceByName(*dev); err != nil {
		t.Fatalf("getting interface error: %v", err)
	}
	d, err = NewDev(ifce, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadFrame(t *testing.T) {
	var (
		ifce *net.Interface
		err  error
		d    Dev
	)
	if ifce, err = net.InterfaceByName(*dev); err != nil {
		t.Fatalf("getting interface error: %v", err)
	}
	d, err = NewDev(ifce, nil)
	if err != nil {
		t.Fatal(err)
	}
	var to ethernet.Frame
	for i := 0; i < 16; i++ {
		err = d.Read(&to)
		t.Logf("got frame: from %v to %v (ethertype %v): % x\n", to.Source(), to.Destination(), to.Ethertype(), to.Payload())
		if err != nil {
			t.Fatal(err)
		}
	}

	err = d.Close()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 1024; i++ {
		err = d.Read(&to)
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("closed Dev can still read")
	}
}

func TestWriteFrame(t *testing.T) {
	var (
		ifce *net.Interface
		err  error
		d    Dev
	)
	if ifce, err = net.InterfaceByName(*dev); err != nil {
		t.Fatalf("getting interface error: %v", err)
	}
	d, err = NewDev(ifce, nil)
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
	var frame ethernet.Frame
	w := func() (err error) {
		(&frame).Prepare(dst, src, ethernet.NotTagged, ethernet.WSMP, 13)
		copy(frame.Payload(), "Hello, World!")
		err = d.Write(frame)
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

	err = d.Close()
	if err != nil {
		t.Fatal(err)
	}

	if err = w(); nil == err {
		t.Fatal("closed Dev can still write")
	}
}
