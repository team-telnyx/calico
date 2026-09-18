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

	"github.com/projectcalico/calico/felix/bpf/routes"
)

// TestIP4FragFollowsFirstFragment checks that every fragment of a datagram sent
// by a workload is forwarded the same way as its first fragment.
//
// The first fragment carries the L4 header, so it goes through conntrack and
// policy, which decide whether it is forwarded by the BPF FIB lookup or handed
// to the host IP stack (CALI_ST_SKIP_FIB, NAT outgoing, ...). The other
// fragments are matched against the fragment tracking table only. They used to
// be forwarded by the FIB no matter what was decided for the first one. When the
// first fragment went through the host, it sat in the host's defragmentation
// queue (nf_defrag_ipv4) waiting for fragments that had been redirected straight
// to the wire, and the datagram was lost.
//
// Seen live with a workload sending from an address that is allowed by
// allowedSourcePrefixes but is not in any IP pool: whole packets were fine, every
// fragmented datagram was lost.
func TestIP4FragFollowsFirstFragment(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "FRGH"
	defer func() { bpfIfaceName = "" }()

	const (
		firstLen = 1472 // payload in the first fragment, after the UDP header
		tailLen  = 64
	)

	for idx, tc := range []struct {
		name    string
		rtFlags routes.Flags
	}{
		// Source is in an IP pool: nothing forces the flow through the host.
		{name: "source in IP pool", rtFlags: routes.FlagsLocalWorkload | routes.FlagInIPAMPool},
		// Source is a local workload address that is NOT in an IP pool and the
		// destination is outside the cluster: CALI_ST_SKIP_FIB, the first
		// fragment is passed to the host IP stack.
		{name: "source not in IP pool", rtFlags: routes.FlagsLocalWorkload},
	} {
		resetBPFMaps()
		hostIP = node1ip

		rtKey := routes.NewKey(srcV4CIDR).AsBytes()
		rtVal := routes.NewValueWithIfIndex(tc.rtFlags, 1).AsBytes()
		err := rtMap.Update(rtKey, rtVal)
		Expect(err).NotTo(HaveOccurred(), tc.name)

		data := make([]byte, firstLen+tailLen)

		ip := *ipv4Default
		ip.Id = uint16(0x5100 + idx)
		ip.Flags = layers.IPv4MoreFragments
		ip.FragOffset = 0
		ip.Length = 20 + 8 + firstLen

		udp := *udpDefault
		udp.Length = 8 + firstLen + tailLen
		_ = udp.SetNetworkLayerForChecksum(&ip)

		first := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(first, gopacket.SerializeOptions{},
			ethDefault, &ip, &udp, gopacket.Payload(data[:firstLen]))
		Expect(err).NotTo(HaveOccurred(), tc.name)

		ip.Flags = 0
		ip.FragOffset = uint16((8 + firstLen) / 8)
		ip.Length = uint16(20 + tailLen)

		tail := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(tail, gopacket.SerializeOptions{},
			ethDefault, &ip, gopacket.Payload(data[firstLen:]))
		Expect(err).NotTo(HaveOccurred(), tc.name)

		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesAllowUDP, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(first.Bytes())
			Expect(err).NotTo(HaveOccurred(), tc.name)
			firstVerdict := res.RetvalStr()
			Expect(firstVerdict).NotTo(Equal("TC_ACT_SHOT"), tc.name+": first fragment was dropped")

			res, err = bpfrun(tail.Bytes())
			Expect(err).NotTo(HaveOccurred(), tc.name)
			Expect(res.RetvalStr()).To(Equal(firstVerdict),
				fmt.Sprintf("%s: the first fragment got %s, the tail fragment must be forwarded the same way",
					tc.name, firstVerdict))
		})
	}
}
