package arp

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type GatewayResolver struct {
	handle    *pcap.Handle
	iface     *net.Interface
	timeout   time.Duration
	retries   int
	srcIP     net.IP
	gatewayIP net.IP
}

func NewGatewayResolver(iface *net.Interface, srcIP, gatewayIP net.IP, handle *pcap.Handle) (*GatewayResolver, error) {
	return &GatewayResolver{
		handle:    handle,
		iface:     iface,
		timeout:   5 * time.Second,
		retries:   3,
		srcIP:     srcIP,
		gatewayIP: gatewayIP,
	}, nil
}

func (r *GatewayResolver) ResolveGatewayMAC() (net.HardwareAddr, error) {
	if err := r.handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("error setting BPF filter: %v", err)
	}

	for attempt := 0; attempt < r.retries; attempt++ {
		// Send ARP request
		if err := r.sendARPRequest(); err != nil {
			continue
		}

		// Wait for reply
		if mac, err := r.waitForARPReply(); err == nil {
			return mac, nil
		}
	}

	return nil, fmt.Errorf("gateway MAC resolution failed after %d attempts", r.retries)
}

func (r *GatewayResolver) sendARPRequest() error {
	eth := &layers.Ethernet{
		SrcMAC:       r.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(r.iface.HardwareAddr),
		SourceProtAddress: []byte(r.srcIP.To4()),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    []byte(r.gatewayIP.To4()),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, eth, arp); err != nil {
		return fmt.Errorf("error serializing ARP request: %v", err)
	}

	return r.handle.WritePacketData(buffer.Bytes())
}

func (r *GatewayResolver) waitForARPReply() (net.HardwareAddr, error) {
	packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())
	timeout := time.After(r.timeout)

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for ARP reply")
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				if err == io.EOF || err == pcap.NextErrorTimeoutExpired {
					continue
				}
				return nil, fmt.Errorf("error reading packet: %v", err)
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}

			if net.IP(arp.SourceProtAddress).Equal(r.gatewayIP) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}
