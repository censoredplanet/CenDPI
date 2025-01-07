package tcp

import (
	"net"

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
	SrcPort               layers.TCPPort
	DstPort               layers.TCPPort
	Window                uint16
	Urgent                uint16
	Seq                   uint32
	Ack                   uint32
	SYN                   bool
	ACK                   bool
	PSH                   bool
	FIN                   bool
	RST                   bool
	URG                   bool
	ECE                   bool
	SeqRelativeToInitial  int
	SeqRelativeToExpected int
	AckRelativeToExpected int
	MessageOffset         int
	MessageLength         int
	ReverseDomain         bool
	Data                  []byte
	Options               []layers.TCPOption
	CorruptChecksum       bool
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
		Urgent:  t.config.Urgent,
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

// BuildAndSerialize constructs a TCP packet from the given TCPConfig and source/dest IPs,
// computes checksums, and returns serialized bytes of the TCP segment.
func BuildAndSerialize(tcpConfig *TCPConfig, srcIP, dstIP net.IP) ([]byte, error) {
	// Create a dummy IPv4 layer for checksum calculation
	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: tcpConfig.SrcPort,
		DstPort: tcpConfig.DstPort,
		Seq:     tcpConfig.Seq,
		Ack:     tcpConfig.Ack,
		SYN:     tcpConfig.SYN,
		ACK:     tcpConfig.ACK,
		PSH:     tcpConfig.PSH,
		FIN:     tcpConfig.FIN,
		RST:     tcpConfig.RST,
		URG:     tcpConfig.URG,
		ECE:     tcpConfig.ECE,
		Window:  tcpConfig.Window,
		Urgent:  tcpConfig.Urgent,
	}

	if len(tcpConfig.Data) > 0 {
		tcpLayer.Payload = tcpConfig.Data
	}

	if len(tcpConfig.Options) > 0 {
		tcpLayer.Options = tcpConfig.Options
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, tcpLayer, gopacket.Payload(tcpLayer.Payload))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// RearrangeDomainIn16BitChunks takes a domain string (ASCII bytes). If the length of the domain is odd,
// we also skip the last byte as a suffix. This leaves a middle portion with an even
// number of bytes. We then break the middle portion into 2-byte chunks and reverse the
// order of those chunks.
func RearrangeDomainIn16BitChunks(domain string) string {
	dBytes := []byte(domain)
	n := len(dBytes)
	if n == 0 {
		return domain
	}

	suffix := []byte{}
	end := n
	if n%2 != 0 {
		// keep the last byte as suffix
		suffix = dBytes[n-1 : n]
		end = n - 1
	}
	middle := dBytes[0:end]
	if len(middle) <= 0 {
		return domain
	}
	reversed := reverseChunks2(middle)
	return string(reversed) + string(suffix)
}

func reverseChunks2(b []byte) []byte {
	length := len(b)
	if length%2 != 0 {
		// should not happen if called properly
		return b
	}
	chunkCount := length / 2

	rev := make([]byte, length)
	// i-th chunk from the front goes to i-th chunk from the back
	for i := 0; i < chunkCount; i++ {
		// chunk i => (b[2i], b[2i+1])
		srcIdx := 2 * i
		// chunk from the end => chunkCount-1 - i
		dstChunk := chunkCount - 1 - i
		dstIdx := 2 * dstChunk

		rev[dstIdx] = b[srcIdx]
		rev[dstIdx+1] = b[srcIdx+1]
	}
	return rev
}
