package ethernet

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type EthernetConfig struct {
	SrcMAC, DstMAC net.HardwareAddr
}

type EthernetLayer struct {
	config *EthernetConfig
}

func New(config *EthernetConfig) *EthernetLayer {
	return &EthernetLayer{
		config: config,
	}
}

func (e *EthernetLayer) Build() (gopacket.SerializableLayer, error) {
	return &layers.Ethernet{
		SrcMAC:       e.config.SrcMAC,
		DstMAC:       e.config.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}, nil
}
