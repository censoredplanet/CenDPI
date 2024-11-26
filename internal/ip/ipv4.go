package ip

import (
	"math/rand/v2"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type IPConfig struct {
	SrcIP      net.IP
	DstIP      net.IP
	Version    uint8
	IHL        uint8
	TOS        uint8
	Id         uint16
	FragOffset uint16
	TTL        uint8
	Options    []layers.IPv4Option
	Padding    []byte
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
		TOS:      i.config.TOS,
		Id:       uint16(rand.Uint32() & 0xffff),
		TTL:      i.config.TTL,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    i.config.SrcIP,
		DstIP:    i.config.DstIP,
	}, nil
}
