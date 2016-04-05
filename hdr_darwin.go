package ether

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
type bpfHdr struct {
	_       timeval // 8 bytes
	caplen  uint32
	datalen uint32
	hdrlen  uint16
}

const wordLength = 4
