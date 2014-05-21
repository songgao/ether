package ether

import "syscall"

/*
 * From bpf.h:
 *
 *  struct bpf_hdr {
 *      struct BPF_TIMEVAL bh_tstamp;
 *      bpf_u_int32 bh_caplen;
 *      bpf_u_int32 bh_datalen;
 *      u_short bh_hdrlen;
 *  };
 *
 */
type bpf_hdr struct {
	bh_tstamp  syscall.Timeval // 8 bytes
	bh_caplen  uint32
	bh_datalen uint32
	bh_hdrlen  uint16
}

const word_length = 4
