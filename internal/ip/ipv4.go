package ip

import (
	"net"
	"strings"
	"encoding/hex"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"
)

type IPConfig struct {
	SrcIP          net.IP
	DstIP          net.IP
	Version        uint8
	IHL            uint8
	TOS            uint8               `yaml:"tos"`
	Id             uint16              `yaml:"id"`
	Protocol       layers.IPProtocol   `yaml:"-"`
	TTL            uint8               `yaml:"ttl"`
	Options        []layers.IPv4Option `yaml:"-"`
	Padding        []byte
	FragmentOffset int  `yaml:"fragmentOffset"`
	MessageOffset  int  `yaml:"messageOffset"`
	MessageLength  int  `yaml:"messageLength"`
	ReverseDomain  bool `yaml:"reverseDomain"`
	MoreFragments  bool `yaml:"moreFragments"`
	DontFragment   bool `yaml:"dontFragment"`
	EvilBit        bool `yaml:"evilBit"`
	RawPayload     []byte
}

type IPLayer struct {
	config *IPConfig
}

type IPOptions struct {
	IPOptionType   uint8  `yaml:"ipOptionType"`
	IPOptionLength uint8  `yaml:"ipOptionLength"`
	IPOptionData   string `yaml:"ipOptionData,omitempty"`
}

func (i *IPConfig) UnmarshalYAML(node *yaml.Node) error {
	type base IPConfig
	raw := struct {
		base  `yaml:",inline"`
		Proto string `yaml:"protocol"`
		Options []IPOptions `yaml:"ipOptions"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	*i = IPConfig(raw.base)

	switch strings.ToLower(strings.TrimSpace(raw.Proto)) {
	case "tcp":
		i.Protocol = layers.IPProtocolTCP
	case "udp":
		i.Protocol = layers.IPProtocolUDP
	default:
		// default to tcp
		i.Protocol = layers.IPProtocolTCP
	}

	for _, opt := range raw.Options {
		var optData []byte
		if opt.IPOptionData != "" {
			var err error
			optData, err = hex.DecodeString(opt.IPOptionData)
			if err != nil {
				return fmt.Errorf("invalid hex in IP Option data: '%s'", opt.IPOptionData)
			}
		}
		i.Options = append(i.Options, layers.IPv4Option{
			OptionType:   opt.IPOptionType,
			OptionLength: opt.IPOptionLength,
			OptionData:   optData,
		})
	}

	return nil
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
		Version:  4,
		IHL:      5, // 5 words (20 bytes) by default
		TOS:      i.config.TOS,
		Id:       i.config.Id,
		TTL:      i.config.TTL,
		SrcIP:    i.config.SrcIP,
		DstIP:    i.config.DstIP,
		Protocol: i.config.Protocol,
		Options:  i.config.Options,
	}

	if i.config.MoreFragments {
		ipLayer.Flags |= layers.IPv4MoreFragments
	}

	if i.config.DontFragment {
		ipLayer.Flags |= layers.IPv4DontFragment
	}

	if i.config.EvilBit {
		ipLayer.Flags |= layers.IPv4EvilBit
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
