package io

import (
	"encoding/binary"
	"testing"

	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

func TestQueueRules(t *testing.T) {
	all := nfProtocolConfig{TCP: true, UDP: true, IPv4: true, IPv6: true}
	if got := all.queueRules(1); len(got) != 1 || got[0] != "counter queue num 100 bypass" {
		t.Fatalf("unexpected single-queue rule: %v", got)
	}
	if got := all.queueRules(4); len(got) != 1 || got[0] != "counter queue num 100-103 bypass" {
		t.Fatalf("unexpected multi-queue rule: %v", got)
	}

	ipv4TCP := nfProtocolConfig{TCP: true, IPv4: true}
	if got := ipv4TCP.queueRules(4); len(got) != 1 ||
		got[0] != "meta nfproto ipv4 meta l4proto tcp counter queue num 100-103 bypass" {
		t.Fatalf("unexpected selective rule: %v", got)
	}
}

func TestCtIDFromCtBytes(t *testing.T) {
	idAttr, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: 12, // CTA_ID
		Data: []byte{0, 0, 0x30, 0x39},
	}})
	if err != nil {
		t.Fatal(err)
	}
	otherAttr, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: 1,
		Data: []byte{1, 2},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ct := append(otherAttr, idAttr...)
	if got := ctIDFromCtBytes(ct); got != 0x3039 {
		t.Fatalf("ctIDFromCtBytes = %#x, want 0x3039", got)
	}
	if got := ctIDFromCtBytes(nil); got != 0 {
		t.Fatalf("ctIDFromCtBytes(nil) = %#x, want 0", got)
	}
	if got := ctIDFromCtBytes([]byte{1, 2}); got != 0 {
		t.Fatalf("ctIDFromCtBytes(short) = %#x, want 0", got)
	}
}

func TestAppendVerdictMessage(t *testing.T) {
	const queue = 103
	msgs := appendVerdictMessage(nil, queue, 0, verdictRequest{
		id:      42,
		verdict: nfqueue.NfAccept,
	})
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Header.Type != netlink.HeaderType((nfqnlSubsysQueue<<8)|nfqnlMsgVerdict) {
		t.Fatalf("unexpected header type %#x", uint16(m.Header.Type))
	}
	if m.Header.Flags != netlink.Request {
		t.Fatalf("unexpected header flags %#x", uint16(m.Header.Flags))
	}
	d := m.Data
	if len(d) != 16 {
		t.Fatalf("got %d bytes, want 16", len(d))
	}
	if d[0] != 0 || d[1] != nfnetlinkVersion || binary.BigEndian.Uint16(d[2:4]) != queue {
		t.Fatalf("unexpected nfgenmsg: % x", d[:4])
	}
	if binary.NativeEndian.Uint16(d[4:6]) != 12 || binary.NativeEndian.Uint16(d[6:8]) != nfqnlVerAttrHdr {
		t.Fatalf("unexpected verdict attr header: % x", d[4:8])
	}
	if got := binary.BigEndian.Uint32(d[8:12]); got != uint32(nfqueue.NfAccept) {
		t.Fatalf("verdict = %d, want %d", got, nfqueue.NfAccept)
	}
	if got := binary.BigEndian.Uint32(d[12:16]); got != 42 {
		t.Fatalf("id = %d, want 42", got)
	}
}

func TestAppendVerdictMessageWithConnMark(t *testing.T) {
	msgs := appendVerdictMessage(nil, 100, 0, verdictRequest{
		id:      7,
		verdict: nfqueue.NfAccept,
		mark:    nfqueueConnMarkAccept,
		hasMark: true,
	})
	d := msgs[0].Data
	if len(d) != 28 {
		t.Fatalf("got %d bytes, want 28", len(d))
	}
	// Nested conntrack attribute starts after the nfgenmsg and verdict attr.
	if got := binary.NativeEndian.Uint16(d[16:18]); got != 12 {
		t.Fatalf("ct attr length = %d, want 12", got)
	}
	if got := binary.NativeEndian.Uint16(d[18:20]); got != netlink.Nested|nfqnlAttrCt {
		t.Fatalf("ct attr type = %#x", got)
	}
	if got := binary.NativeEndian.Uint16(d[20:22]); got != 8 {
		t.Fatalf("mark attr length = %d, want 8", got)
	}
	if got := binary.NativeEndian.Uint16(d[22:24]); got != nfqnlAttrMark {
		t.Fatalf("mark attr type = %d, want %d", got, nfqnlAttrMark)
	}
	if got := binary.BigEndian.Uint32(d[24:28]); got != nfqueueConnMarkAccept {
		t.Fatalf("mark = %d, want %d", got, nfqueueConnMarkAccept)
	}
}

func TestAppendVerdictMessageWithPayload(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	msgs := appendVerdictMessage(nil, 100, 0, verdictRequest{
		id:      9,
		verdict: nfqueue.NfDrop,
		payload: payload,
	})
	d := msgs[0].Data
	// 4-byte nfgenmsg + 12-byte verdict attr + 4-byte payload header + 5 bytes + 3 pad.
	if len(d) != 28 {
		t.Fatalf("got %d bytes, want 28", len(d))
	}
	if got := binary.NativeEndian.Uint16(d[16:18]); got != 9 {
		t.Fatalf("payload attr length = %d, want 9", got)
	}
	if got := binary.NativeEndian.Uint16(d[18:20]); got != nfqnlAttrPayload {
		t.Fatalf("payload attr type = %d, want %d", got, nfqnlAttrPayload)
	}
	for i, b := range payload {
		if d[20+i] != b {
			t.Fatalf("payload[%d] = %d, want %d", i, d[20+i], b)
		}
	}
}
