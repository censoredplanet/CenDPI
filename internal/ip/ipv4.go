package ip

import (
	"math/rand/v2"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type IPConfig struct {
	SrcIP net.IP
	DstIP net.IP
}

type IPLayer struct {
	config *IPConfig
}

func New(config *IPConfig) *IPLayer {
	return &IPLayer{config: config}
}

func (i *IPLayer) Build() (gopacket.SerializableLayer, error) {
	return &layers.IPv4{
		Version:  4,
		IHL:      5, // Internet Header Length (5 32-bit words = 20 bytes)
		TOS:      0,
		Id:       uint16(rand.Uint32() & 0xffff),
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    i.config.SrcIP,
		DstIP:    i.config.DstIP,
	}, nil
}
