package ether

import "syscall"

/*
 * From bpf.h:
 *
 *   struct bpf_hdr {
 *      struct timeval   bh_tstamp;
 *  	uint32_t         bh_caplen;
 *  	uint32_t         bh_datalen;
 *  	u_short          bh_hdrlen;
 *   };
 *
 * Note: FreeBSD may deprecate bpf_hdr in favor of bpf_xhdr in the future
 *
 */
type bpf_hdr struct {
	bh_tstamp  syscall.Timeval // 8 or 16 bytes depending on arch
	bh_caplen  uint32
	bh_datalen uint32
	bh_hdrlen  uint16
}
