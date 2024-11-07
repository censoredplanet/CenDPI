package tcp

import (
	"math/rand/v2"

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
	Seq     uint32
	Ack     uint32
	PType   TCPPacketType
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
		Window:  64240,
	}
	switch t.config.PType {
	case PacketSYN:
		tcp.SYN = true
		tcp.Seq = rand.Uint32()
	case PacketSYNACK:
		tcp.SYN = true
		tcp.ACK = true
	case PacketACK:
		tcp.ACK = true
		tcp.Seq = t.config.Seq
		tcp.Ack = t.config.Ack + 1
	case PacketPSH:
		tcp.PSH = true
		tcp.ACK = true
	case PacketFIN:
		tcp.FIN = true
		tcp.ACK = true
	}

	return tcp, nil
}
