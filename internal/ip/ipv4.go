package ip

import (
	"net"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type IPConfig struct {
	SrcIP          net.IP
	DstIP          net.IP
	Version        uint8
	IHL            uint8
	TOS            uint8
	Id             uint16
	TTL            uint8
	Options        []layers.IPv4Option
	Padding        []byte
	FragmentOffset int
	MessageOffset  int
	MessageLength  int
	MoreFragments  bool
	RawPayload     []byte
}

type IPLayer struct {
	config *IPConfig
}

func New(config *IPConfig) *IPLayer {
	return &IPLayer{config: config}
}

func NewWithPayload(config *IPConfig, payload []byte) *IPLayer {
	config.RawPayload = payload
	return &IPLayer{config: config}
}

func (i *IPLayer) Config() *IPConfig {
    return i.config
}

func (i *IPLayer) Build() (gopacket.SerializableLayer, error) {
	// Construct the IPv4 layer
	ipLayer := &layers.IPv4{
		Version:    4,
		IHL:        5, // 5 words (20 bytes) by default
		TOS:        i.config.TOS,
		Id:         i.config.Id,
		TTL:        i.config.TTL,
		SrcIP:      i.config.SrcIP,
		DstIP:      i.config.DstIP,
		// we assume the Protocol is always TCP.
		Protocol: layers.IPProtocolTCP,
	}

	// Handle fragmentation fields if needed
	if i.config.MoreFragments {
		ipLayer.Flags = layers.IPv4MoreFragments
	}
	// fragmentOffset is assumed to already be in 8-byte units
	if i.config.FragmentOffset > 0 {
		ipLayer.FragOffset = uint16(i.config.FragmentOffset)
	}

	// i.config.RawPayload, if set, will be appended by the assembler as a payload layer.
	// The IP layer itself doesn't hold the payload bytes. The assembler will handle adding
	// gopacket.Payload(i.config.RawPayload) after serialization of IP.
	// The assembler will add it as a separate layer.

	return ipLayer, nil
}
