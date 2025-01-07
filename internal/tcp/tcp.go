package tcp

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"
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
	Window                uint16 `yaml:"window"`
	Urgent                uint16 `yaml:"urgentPointer"`
	Seq                   uint32
	Ack                   uint32
	SeqRelativeToInitial  int                `yaml:"seqRelativeToInitial"`
	SeqRelativeToExpected int                `yaml:"seqRelativeToExpected"`
	AckRelativeToExpected int                `yaml:"ackRelativeToExpected"`
	MessageOffset         int                `yaml:"messageOffset"`
	MessageLength         int                `yaml:"messageLength"`
	ReverseDomain         bool               `yaml:"reverseDomain"`
	Data                  []byte             `yaml:"-"`
	Options               []layers.TCPOption `yaml:"-"`
	CorruptChecksum       bool               `yaml:"corruptChecksum"`
	Flags                 TCPFlags           `yaml:"flags"`
}
type TCPFlags struct {
	SYN bool `yaml:"syn"`
	ACK bool `yaml:"ack"`
	PSH bool `yaml:"psh"`
	FIN bool `yaml:"fin"`
	RST bool `yaml:"rst"`
	URG bool `yaml:"urg"`
	ECE bool `yaml:"ece"`
}

type TCPOptions struct {
	TCPOptionType   uint8  `yaml:"tcpOptionType"`
	TCPOptionLength uint8  `yaml:"tcpOptionLength"`
	TCPOptionData   string `yaml:"tcpOptionData"`
}

type TCPLayer struct {
	config *TCPConfig
}

func (t *TCPConfig) UnmarshalYAML(node *yaml.Node) error {
	type base TCPConfig
	raw := struct {
		base    `yaml:",inline"`
		Data    string       `yaml:"data"`
		Options []TCPOptions `yaml:"tcpOptions"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	*t = TCPConfig(raw.base)
	t.Data = []byte(raw.Data)
	var tcpOpts layers.TCPOption
	for _, opt := range raw.Options {
		if opt.TCPOptionData != "" {
			optData, err := hex.DecodeString(opt.TCPOptionData)
			if err != nil {
				return fmt.Errorf("invalid hex in TCP Option data: '%s'", opt.TCPOptionData)
			}
			tcpOpts.OptionData = []byte(optData)
		}

		tcpOpts.OptionLength = opt.TCPOptionLength
		tcpOpts.OptionType = layers.TCPOptionKind(opt.TCPOptionType)
		t.Options = append(t.Options, tcpOpts)
	}

	return nil
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
		SYN:     t.config.Flags.SYN,
		ACK:     t.config.Flags.ACK,
		PSH:     t.config.Flags.PSH,
		FIN:     t.config.Flags.FIN,
		RST:     t.config.Flags.RST,
		URG:     t.config.Flags.URG,
		ECE:     t.config.Flags.ECE,
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
		SYN:     tcpConfig.Flags.SYN,
		ACK:     tcpConfig.Flags.ACK,
		PSH:     tcpConfig.Flags.PSH,
		FIN:     tcpConfig.Flags.FIN,
		RST:     tcpConfig.Flags.RST,
		URG:     tcpConfig.Flags.URG,
		ECE:     tcpConfig.Flags.ECE,
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
