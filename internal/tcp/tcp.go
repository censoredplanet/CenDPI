package tcp

import (
	"encoding/hex"
	"encoding/json"
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
	SrcPort               layers.TCPPort     `json:"SrcPort"`
	DstPort               layers.TCPPort     `json:"DstPort"`
	Window                uint16             `yaml:"window" json:"Window"`
	Urgent                uint16             `yaml:"urgentPointer" json:"Urgent"`
	Seq                   uint32             `json:"Seq"`
	Ack                   uint32             `json:"Ack"`
	SeqRelativeToInitial  int                `yaml:"seqRelativeToInitial" json:"SeqRelativeToInitial"`
	SeqRelativeToExpected int                `yaml:"seqRelativeToExpected" json:"SeqRelativeToExpected"`
	AckRelativeToExpected int                `yaml:"ackRelativeToExpected" json:"AckRelativeToExpected"`
	ZeroAck               bool               `yaml:"zeroAck" json:"ZeroAck"`
	MessageOffset         int                `yaml:"messageOffset" json:"MassageOffset"`
	MessageLength         int                `yaml:"messageLength" json:"MessageLength"`
	ReverseDomain         bool               `yaml:"reverseDomain" json:"ReverseDomain"`
	Data                  []byte             `yaml:"-" json:"Data"`
	DataString            string             `yaml:"dataString" json:"DataString"`
	Payload               []byte             `yaml:"-" json:"Payload"`
	Options               []layers.TCPOption `yaml:"-" json:"Options"`
	CorruptChecksum       bool               `yaml:"corruptChecksum" json:"CorruptChecksum"`
	Flags                 TCPFlags           `yaml:"flags" json:"Flags"`
}
type TCPFlags struct {
	SYN bool `yaml:"syn" json:"SYN"`
	ACK bool `yaml:"ack" json:"ACK"`
	PSH bool `yaml:"psh" json:"PSH"`
	FIN bool `yaml:"fin" json:"FIN"`
	RST bool `yaml:"rst" json:"RST"`
	URG bool `yaml:"urg" json:"URG"`
	ECE bool `yaml:"ece" json:"ECE"`
}

type TCPOptions struct {
	TCPOptionType   uint8  `yaml:"tcpOptionType" json:"TCPOptionType"`
	TCPOptionLength uint8  `yaml:"tcpOptionLength" json:"TCPOptionLength"`
	TCPOptionData   string `yaml:"tcpOptionData" json:"TCPOptionData"`
}

type TCPLayer struct {
	config *TCPConfig
}

func (t *TCPConfig) UnmarshalYAML(node *yaml.Node) error {
	type base TCPConfig
	raw := struct {
		base `yaml:",inline"`
		//Data    string       `yaml:"data"`
		Options []TCPOptions `yaml:"tcpOptions"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	*t = TCPConfig(raw.base)
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

func (tcp TCPConfig) MarshalJSON() ([]byte, error) {
	// Define an alias type to avoid infinite recursion when calling json.Marshal inside MarshalJSON.
	type Alias TCPConfig

	// Convert the byte slice to string for JSON output.
	// Everything else can marshal normally via the Alias.
	return json.Marshal(&struct {
		Alias
		DataString string `json:"DataString,omitempty"`
		// Payload string `json:"Payload"`
	}{
		Alias:      Alias(tcp),
		DataString: tcp.DataString,
		// Payload: string(tcp.Payload),
	})
}

func ParseTCPLayer(tcp *layers.TCP) TCPConfig {
	return TCPConfig{
		SrcPort:       tcp.SrcPort,
		DstPort:       tcp.DstPort,
		Window:        tcp.Window,
		Urgent:        tcp.Urgent,
		Seq:           tcp.Seq,
		Ack:           tcp.Ack,
		MessageOffset: int(tcp.DataOffset),
		Data:          tcp.Payload,
		Options:       tcp.Options,
		Flags: TCPFlags{
			SYN: tcp.SYN,
			ACK: tcp.ACK,
			PSH: tcp.PSH,
			FIN: tcp.FIN,
			RST: tcp.RST,
			URG: tcp.URG,
			ECE: tcp.ECE,
		},
	}
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
	} else if len(t.config.DataString) > 0 {
		tcpData, err := hex.DecodeString(t.config.DataString)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in TCP data: '%s'", t.config.DataString)
		}
		tcp.Payload = []byte(tcpData)
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
	} else if len(tcpConfig.DataString) > 0 {
		tcpData, err := hex.DecodeString(tcpConfig.DataString)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in TCP data: '%s'", tcpConfig.DataString)
		}
		tcpLayer.Payload = []byte(tcpData)
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
