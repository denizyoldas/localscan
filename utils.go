package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
)

func ScanNetwork(network string, timeout int) ([]string, error) {
	var targets []string

	arpPacket := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(arpPacket, opts,
		&layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			SourceProtAddress: net.IP{0x00, 0x00, 0x00, 0x00},
			DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			DstProtAddress:    net.IP{0x00, 0x00, 0x00, 0x00},
		},
	)

	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(network, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Send ARP request
	err = handle.WritePacketData(arpPacket.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	// Set filter for ARP responses
	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal(err)
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply {
				targets = append(targets, net.IP(arp.SourceProtAddress).String())
			}
		}
	}

	return targets, nil

}
