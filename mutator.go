package lfuzzo

import (
	"encoding/binary"

	"github.com/soypat/lneto/tcp"
)

const numTrigs = 8

type MutatorTCPBasic struct {
	RateACKNudge uint8
	RateSEQNudge uint8
	RateWNDNudge uint8
	RateCtlSet   uint8
	RateCtlFlip  uint8
	RateACKFlip  uint8
	Trigs        [numTrigs]uint8
	Deltas       [numTrigs]int32
}

// MutateTCP perturbs sequence numbers, window and flags of packet in place.
// The caller must recompute the TCP checksum, which covers the IP pseudo-header.
func (mut *MutatorTCPBasic) MutateTCP(packet tcp.Frame) (edit bool) {
	seg := packet.Segment(len(packet.Payload()))
	if mut.Trigs[0] < mut.RateACKNudge {
		seg.ACK += tcp.Value(mut.Deltas[0])
		edit = true
	}
	if mut.Trigs[1] < mut.RateSEQNudge {
		seg.SEQ += tcp.Value(mut.Deltas[1])
		edit = true
	}
	if mut.Trigs[2] < mut.RateCtlFlip && seg.Flags.HasAny(tcp.FlagFIN|tcp.FlagSYN|tcp.FlagRST) {
		seg.Flags ^= 1 << (mut.Deltas[2] & 3) // FIN, SYN, RST or PSH.
		edit = true
	}
	if mut.Trigs[3] < mut.RateACKFlip {
		seg.Flags ^= tcp.FlagACK
		edit = true
	}
	if mut.Trigs[4] < mut.RateWNDNudge {
		seg.WND = tcp.Size(uint16(seg.WND) + uint16(int8(mut.Deltas[4]))) // Wraps within the 16-bit header field.
		edit = true
	}
	if mut.Trigs[5] < mut.RateCtlSet {
		seg.Flags |= tcp.Flags(mut.Deltas[5]&3) << (mut.Deltas[5] & 3) // FIN, SYN, RST or PSH.
		edit = true
	}
	if edit {
		offset, _ := packet.OffsetAndFlags()
		packet.SetSegment(seg, offset)
	}
	return edit
}

// Load sets the mutation for the next segment from script and returns the
// unconsumed rest. script[0] is a bitmask of mutations to apply, each set bit
// followed by a little-endian int16 delta. An exhausted script mutates nothing.
func (mut *MutatorTCPBasic) Load(script []byte) []byte {
	for i := range mut.Trigs {
		mut.Trigs[i] = 255
	}
	if len(script) == 0 {
		return nil
	}
	mask := script[0]
	script = script[1:]
	for i := range numTrigs {
		if mask&(1<<i) == 0 || len(script) < 2 {
			continue
		}
		mut.Trigs[i] = 0 // Fires for any nonzero rate.
		mut.Deltas[i] = int32(int16(binary.LittleEndian.Uint16(script)))
		script = script[2:]
	}
	return script
}
