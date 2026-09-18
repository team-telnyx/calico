// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/proto"
)

func TestIP4Defrag(t *testing.T) {
	RegisterTestingT(t)

	cleanUpMaps()

	bpfIfaceName = "DEFR"
	defer func() { bpfIfaceName = "" }()

	data := make([]byte, 2000)

	for i := range 1000 {
		data[i*2] = byte(uint16(i) >> 8)
		data[i*2+1] = byte(uint16(i) & 0xff)
	}

	ip := *ipv4Default
	ip.Id = 0x1234
	ip.Length = 20 + 8 + 2000
	ip.Flags = 0
	udp := *udpDefault
	udp.Length = 8 + 2000

	// compute ull packet
	payload := gopacket.Payload(data)
	_ = udp.SetNetworkLayerForChecksum(&ip)

	pktFull := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pktFull, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, &udp, payload)
	Expect(err).NotTo(HaveOccurred())

	dataLen := 1600
	dataOffset := 0

	ip.Flags = layers.IPv4MoreFragments
	ip.FragOffset = 0
	ip.Length = 20 + 8 + 1600

	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])
	_ = udp.SetNetworkLayerForChecksum(&ip)

	pkt0 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt0, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, &udp, payload)
	Expect(err).NotTo(HaveOccurred())

	dataOffset = dataLen
	dataLen = 192

	ip.FragOffset = uint16((8 + dataOffset) / 8)
	ip.Length = uint16(20 + dataLen)
	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])

	pkt1 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt1, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, payload)
	Expect(err).NotTo(HaveOccurred())

	dataOffset += dataLen
	dataLen = 80

	ip.Flags = layers.IPv4MoreFragments
	ip.FragOffset = uint16((8 + dataOffset) / 8)
	ip.Length = uint16(20 + dataLen)
	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])

	pkt2 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt2, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, payload)
	Expect(err).NotTo(HaveOccurred())

	dataOffset += dataLen
	dataLen = 2000 - dataOffset

	ip.Flags = 0
	ip.FragOffset = uint16((8 + dataOffset) / 8)
	ip.Length = uint16(20 + dataLen)
	payload = gopacket.Payload(data[dataOffset : dataOffset+dataLen])

	pkt3 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(pkt3, gopacket.SerializeOptions{ComputeChecksums: true}, ethDefault, &ip, payload)
	Expect(err).NotTo(HaveOccurred())

	pktFullR := gopacket.NewPacket(pktFull.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		bytes := pkt0.Bytes()
		copy(bytes[40:42], pktFull.Bytes()[40:42]) // patch in the udp csum for the entire packet
		res, err := bpfrun(bytes)
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt1.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt3.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pkt2.Bytes())
		Expect(err).NotTo(HaveOccurred())
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		fmt.Printf("pktFullR = %+v\n", pktFullR)
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		payloadL := pktR.ApplicationLayer()
		data := payloadL.Payload()

		for i := range 1000 {
			Expect(data[i*2]).To(Equal(byte(uint16(i)>>8)), fmt.Sprintf("wrong at index %d", i*2))
			Expect(data[i*2+1]).To(Equal(byte(uint16(i)&0xff)), fmt.Sprintf("wrong at index %d", i*2+1))
		}

		Expect(pktFull.Bytes()).To(Equal(res.dataOut))
	})
}

// Exercise real TC entrypoints: later fragments contain payload, not L4 headers.
func TestIP4ShortFragments(t *testing.T) {
	id := uint16(0x6000)
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolUDP, layers.IPProtocolICMPv4, layers.IPProtocolTCP} {
		for tail := 1; tail <= 19; tail++ {
			if protocol != layers.IPProtocolTCP && tail > 8 {
				continue
			}
			for _, padded := range []bool{false, true} {
				id++
				t.Run(fmt.Sprintf("%s/tail=%d/padded=%t", protocol, tail, padded), func(t *testing.T) {
					RegisterTestingT(t)
					cleanUpMaps()
					defer cleanUpMaps()
					first, last, full := shortIP4Fragments(t, protocol, id, tail, padded)
					skbMark = 0
					runBpfTest(t, "calico_from_host_ep", nil, func(run bpfProgRunFn) {
						res, err := run(first)
						Expect(err).NotTo(HaveOccurred())
						Expect(res.Retval).To(Equal(resTC_ACT_SHOT)) // waiting for last
						res, err = run(last)
						Expect(err).NotTo(HaveOccurred())
						Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
						Expect(res.dataOut).To(Equal(full)) // no Ethernet padding in IP payload
					})
					cleanUpMaps()
					Expect(rtMap.Update(rtKeySrc, rtValGood)).To(Succeed())
					skbMark = 0
					runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(run bpfProgRunFn) {
						res, err := run(last)
						Expect(err).NotTo(HaveOccurred())
						Expect(res.Retval).To(Equal(resTC_ACT_SHOT)) // orphan/reordered
						res, err = run(first)
						Expect(err).NotTo(HaveOccurred())
						Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
						res, err = run(last)
						Expect(err).NotTo(HaveOccurred())
						Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
						Expect(res.dataOut).To(Equal(last))
						res, err = run(last)
						Expect(err).NotTo(HaveOccurred())
						Expect(res.Retval).To(Equal(resTC_ACT_SHOT)) // CT consumed
					})
					cleanUpMaps()
					skbMark = 0
					hostDeny := denyAllRulesXDP
					hostDeny.ForXDP = false
					hostDeny.HostForwardTiers = hostDeny.HostNormalTiers
					runBpfTest(t, "calico_from_host_ep", &hostDeny, func(run bpfProgRunFn) {
						for _, fragment := range [][]byte{first, last} {
							res, err := run(fragment)
							Expect(err).NotTo(HaveOccurred())
							Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
						}
					})
					cleanUpMaps()
					Expect(rtMap.Update(rtKeySrc, rtValGood)).To(Succeed())
					skbMark = 0
					deny := &polprog.Rules{Tiers: []polprog.Tier{{Policies: []polprog.Policy{{Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Deny"}}}}}}}}
					runBpfTest(t, "calico_from_workload_ep", deny, func(run bpfProgRunFn) {
						for _, fragment := range [][]byte{first, last} {
							res, err := run(fragment)
							Expect(err).NotTo(HaveOccurred())
							Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
						}
					})
				})
			}
		}
	}
}

func shortIP4Fragments(t *testing.T, protocol layers.IPProtocol, id uint16, tail int, padded bool) (first, last, full []byte) {
	t.Helper()
	ip := *ipv4Default
	ip.Id, ip.Protocol, ip.Flags, ip.FragOffset = id, protocol, 0, 0
	var transport gopacket.SerializableLayer
	headerLen := 8
	switch protocol {
	case layers.IPProtocolUDP:
		udp := *udpDefault
		Expect(udp.SetNetworkLayerForChecksum(&ip)).To(Succeed())
		transport = &udp
	case layers.IPProtocolICMPv4:
		transport = &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 123, Seq: 1}
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 5678, SYN: true, Seq: 123, Window: 4096}
		Expect(tcp.SetNetworkLayerForChecksum(&ip)).To(Succeed())
		transport, headerLen = tcp, 20
	}
	data := make([]byte, 32+tail-headerLen)
	for i := range data {
		data[i] = byte(i + 1)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	Expect(gopacket.SerializeLayers(buf, opts, ethDefault, &ip, transport, gopacket.Payload(data))).To(Succeed())
	full = append([]byte(nil), buf.Bytes()...)
	fragment := func(offset, end int, more bool) []byte {
		ip.FragOffset, ip.Flags = uint16(offset/8), 0
		if more {
			ip.Flags = layers.IPv4MoreFragments
		}
		buf := gopacket.NewSerializeBuffer()
		// Serialize IP separately so gopacket does not add Ethernet padding.
		Expect(gopacket.SerializeLayers(buf, opts, &ip, gopacket.Payload(full[34+offset:34+end]))).To(Succeed())
		return append(append([]byte(nil), full[:14]...), buf.Bytes()...)
	}
	first, last = fragment(0, 32, true), fragment(32, 32+tail, false)
	if padded {
		for len(last) < 60 {
			last = append(last, 0xa5)
		}
	}
	return
}

// Malformed lengths must not be rescued by Ethernet padding or fragment CT.
func TestIP4MalformedFragments(t *testing.T) {
	RegisterTestingT(t)
	for _, section := range []string{"calico_from_workload_ep", "calico_from_host_ep"} {
		for _, kind := range []string{"empty", "truncated", "ihl", "unaligned"} {
			t.Run(section+"/"+kind, func(t *testing.T) {
				RegisterTestingT(t)
				cleanUpMaps()
				defer cleanUpMaps()
				Expect(rtMap.Update(rtKeySrc, rtValGood)).To(Succeed())
				first, last, _ := shortIP4Fragments(t, layers.IPProtocolUDP, 0x7000, 1, true)
				switch kind {
				case "empty":
					binary.BigEndian.PutUint16(last[16:18], 20)
				case "truncated":
					binary.BigEndian.PutUint16(last[16:18], 100)
				case "ihl":
					last[14] = 0x4f
				case "unaligned":
					binary.BigEndian.PutUint16(last[20:22], 0x2004)
				}
				// Recompute checksum so each case tests its length, not a bad checksum.
				last[24], last[25] = 0, 0
				sum := uint32(0)
				for i := 14; i < 34; i += 2 {
					sum += uint32(binary.BigEndian.Uint16(last[i : i+2]))
				}
				for sum > 0xffff {
					sum = (sum & 0xffff) + (sum >> 16)
				}
				binary.BigEndian.PutUint16(last[24:26], ^uint16(sum))
				skbMark = 0
				runBpfTest(t, section, rulesDefaultAllow, func(run bpfProgRunFn) {
					_, err := run(first)
					Expect(err).NotTo(HaveOccurred())
					res, err := run(last)
					Expect(err).NotTo(HaveOccurred())
					Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
				})
			})
		}
	}
}

func TestIP4ShortFirstTCPFragment(t *testing.T) {
	RegisterTestingT(t)
	cleanUpMaps()
	defer cleanUpMaps()
	Expect(rtMap.Update(rtKeySrc, rtValGood)).To(Succeed())
	first, _, _ := shortIP4Fragments(t, layers.IPProtocolTCP, 0x7100, 1, false)
	// Eight declared TCP bytes plus padding must not count as a full TCP header.
	first = first[:42]
	binary.BigEndian.PutUint16(first[16:18], 28)
	first[24], first[25] = 0, 0
	sum := uint32(0)
	for i := 14; i < 34; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(first[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(first[24:26], ^uint16(sum))
	first = append(first, make([]byte, 60-len(first))...)
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(run bpfProgRunFn) {
		res, err := run(first)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})
}
