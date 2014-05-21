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
	bh_tstamp  timeval // 8 bytes
	bh_caplen  uint32
	bh_datalen uint32
	bh_hdrlen  uint16
}

type timeval struct {
	syscall.Timeval32
}

func (t *timeval) Unix() (sec int64, nsec int64) {
	return int64(t.Sec), int64(t.Usec) * 1000
}

const word_length = 4
