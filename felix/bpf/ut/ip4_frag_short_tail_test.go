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
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/routes"
)

// TestIP4FragShortTailFromWorkload checks that the last fragment of a locally
// fragmented datagram is not dropped when it is shorter than an L4 header.
// Such a fragment carries no L4 header at all - it used to be denied with
// CALI_REASON_SHORT by parse_packet_ip_v4() before it could be matched against
// the fragment tracking table.
func TestIP4FragShortTailFromWorkload(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "FRGT"
	defer func() { bpfIfaceName = "" }()

	defer resetBPFMaps()
	hostIP = node1ip

	// Route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err := rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	const (
		firstLen = 1472 // payload in the first fragment, after the UDP header
		tailLen  = 4    // shorter than UDP_SIZE!
	)

	data := make([]byte, firstLen+tailLen)

	ip := *ipv4Default
	ip.Id = 0x4242
	ip.Flags = layers.IPv4MoreFragments
	ip.FragOffset = 0
	ip.Length = 20 + 8 + firstLen

	udp := *udpDefault
	udp.Length = 8 + firstLen + tailLen
	_ = udp.SetNetworkLayerForChecksum(&ip)

	first := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(first, gopacket.SerializeOptions{},
		ethDefault, &ip, &udp, gopacket.Payload(data[:firstLen]))
	Expect(err).NotTo(HaveOccurred())

	ip.Flags = 0
	ip.FragOffset = uint16((8 + firstLen) / 8)
	ip.Length = uint16(20 + tailLen)

	tail := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tail, gopacket.SerializeOptions{},
		ethDefault, &ip, gopacket.Payload(data[firstLen:]))
	Expect(err).NotTo(HaveOccurred())

	// gopacket pads the frame out to the 60 byte Ethernet minimum; a veth does
	// not, so strip the padding to get the frame the workload really sends.
	tailBytes := tail.Bytes()[:14+20+tailLen]

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
		// The first fragment goes through policy and records the flow in the
		// fragment tracking table.
		res, err := bpfrun(first.Bytes())
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).NotTo(Equal("TC_ACT_SHOT"), "first fragment was dropped")

		// The trailing fragment has no L4 header and is too short to hold one.
		// It must be matched against the fragment tracking table, not dropped.
		res, err = bpfrun(tailBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).NotTo(Equal("TC_ACT_SHOT"), "short tail fragment was dropped")
	})
}
