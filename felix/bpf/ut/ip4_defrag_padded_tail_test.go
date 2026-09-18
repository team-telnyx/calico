// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ut_test

import (
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
)

// TestIP4DefragShortPaddedTail checks that reassembly returns exactly the bytes
// that were sent when the last fragment is shorter than the Ethernet minimum.
//
// A frame below 60 bytes is padded on the wire and the padding is still part of
// skb->len when the TC program runs - the IP stack trims to the IP total length
// later, but we run before it. If the fragment length is taken from skb->len the
// padding is stored as payload and the reassembled datagram grows by that many
// zero bytes. Seen live as 1473 -> 1494 and 1480 -> 1494 byte UDP payloads.
//
// It is deliberately a byte-for-byte comparison: "the packet was not dropped" is
// not enough to call reassembly correct.
func TestIP4DefragShortPaddedTail(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "DFPT"
	defer func() { bpfIfaceName = "" }()

	// First fragment: 8 bytes of UDP header + 1472 bytes of data = 1480 bytes of
	// IP payload, what a 1500 byte MTU produces.
	const firstData = 1472
	const ethMinFrame = 60

	for idx, tc := range []struct {
		tail      int
		tailFirst bool
	}{
		{tail: 1},
		{tail: 7},
		{tail: 8},
		{tail: 21},
		{tail: 1, tailFirst: true},
		{tail: 8, tailFirst: true},
	} {
		name := fmt.Sprintf("tail=%d tailFirst=%v", tc.tail, tc.tailFirst)

		cleanUpMaps()

		total := firstData + tc.tail
		data := make([]byte, total)
		for i := range data {
			// Never zero, so that appended zero padding cannot hide.
			data[i] = byte(i%251) + 1
		}

		opts := gopacket.SerializeOptions{ComputeChecksums: true}

		// The datagram as it was sent.
		ip := *ipv4Default
		ip.Id = uint16(0x4000 + idx)
		ip.Flags = 0
		ip.FragOffset = 0
		ip.Length = uint16(20 + 8 + total)
		udp := *udpDefault
		udp.Length = uint16(8 + total)
		_ = udp.SetNetworkLayerForChecksum(&ip)

		pktFull := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(pktFull, opts, ethDefault, &ip, &udp, gopacket.Payload(data))
		Expect(err).NotTo(HaveOccurred(), name)
		want := pktFull.Bytes()

		// First fragment.
		ip.Flags = layers.IPv4MoreFragments
		ip.FragOffset = 0
		ip.Length = uint16(20 + 8 + firstData)
		_ = udp.SetNetworkLayerForChecksum(&ip)

		frag0 := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(frag0, opts, ethDefault, &ip, &udp, gopacket.Payload(data[:firstData]))
		Expect(err).NotTo(HaveOccurred(), name)
		first := frag0.Bytes()
		copy(first[40:42], want[40:42]) // the UDP csum covers the entire datagram

		// Last fragment, no L4 header.
		ip.Flags = 0
		ip.FragOffset = uint16((8 + firstData) / 8)
		ip.Length = uint16(20 + tc.tail)

		fragT := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(fragT, opts, ethDefault, &ip, gopacket.Payload(data[firstData:]))
		Expect(err).NotTo(HaveOccurred(), name)
		tail := fragT.Bytes()
		// Whether or not the serializer padded it, hand the program the frame a NIC
		// delivers: padded with zeros to the Ethernet minimum, IP total length
		// untouched.
		for len(tail) < ethMinFrame {
			tail = append(tail, 0)
		}
		Expect(len(tail)).To(BeNumerically(">", 14+20+tc.tail), name+": test premise, the tail frame must carry padding")

		order := [][]byte{first, tail}
		if tc.tailFirst {
			order = [][]byte{tail, first}
		}

		skbMark = 0
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(order[0])
			Expect(err).NotTo(HaveOccurred(), name)
			Expect(res.Retval).To(Equal(resTC_ACT_SHOT), name+": an incomplete datagram is held, not forwarded")
		})

		skbMark = 0
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(order[1])
			Expect(err).NotTo(HaveOccurred(), name)
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC), name+": the datagram is complete and must be reassembled")

			Expect(res.dataOut).To(HaveLen(len(want)),
				fmt.Sprintf("%s: reassembled datagram is %d bytes, sent %d - Ethernet padding counted as payload?",
					name, len(res.dataOut), len(want)))
			Expect(res.dataOut).To(Equal(want), name+": reassembled bytes differ from the bytes sent")
		})
	}
}
