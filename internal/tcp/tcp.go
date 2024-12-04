package tcp

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type TCPPacketType int

const (
	PacketSYN TCPPacketType = iota
	PacketSYNACK
	PacketACK
	PacketPSH
	PacketFIN
)

type TCPConfig struct {
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	Window  uint16
	Seq     uint32
	Ack     uint32
	SYN     bool
	ACK     bool
	PSH     bool
	FIN     bool
	RST     bool
	URG     bool
	ECE     bool
	Data    []byte
	Options  []layers.TCPOption
}

type TCPLayer struct {
	config *TCPConfig
}

func New(config *TCPConfig) *TCPLayer {
	return &TCPLayer{
		config: config,
	}
}

func (t *TCPLayer) Build() (gopacket.SerializableLayer, error) {
	tcp := &layers.TCP{
		SrcPort: t.config.SrcPort,
		DstPort: t.config.DstPort,
		Window:  t.config.Window,
		SYN:     t.config.SYN,
		ACK:     t.config.ACK,
		PSH:     t.config.PSH,
		FIN:     t.config.FIN,
		RST:     t.config.RST,
		URG:     t.config.URG,
		ECE:     t.config.ECE,
		Seq:     t.config.Seq,
		Ack:     t.config.Ack,
	}

	if len(t.config.Data) > 0 {
		tcp.Payload = t.config.Data
	}

	// Add options if they exist
	if len(t.config.Options) > 0 {
		tcp.Options = t.config.Options
	}
	
	return tcp, nil
}
