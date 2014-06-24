package ether

import "net"

const bufferSize = 16

func equalMAC(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i, k := range a {
		if b[i] != k {
			return false
		}
	}
	return true
}
