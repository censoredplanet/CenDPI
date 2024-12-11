package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"github.com/censoredplanet/CenDPI/internal/service"
	"github.com/censoredplanet/CenDPI/internal/tcp"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Iface    string    `yaml:"interface"`
	PcapPath string    `yaml:"pcapPath"`
	BPF      string    `yaml:"bpf"`
	SrcMac   string    `yaml:"srcMac"`
	DstMac   string    `yaml:"dstMac"`
	Message  *Message  `yaml:"message,omitempty"`
	Packets  []Packet  `yaml:"packets"`
}

type Message struct {
	DataHex string   `yaml:"dataHex,omitempty"`
	TCP     *TCPYaml `yaml:"tcp,omitempty"`
}

type Packet struct {
	Ethernet EthernetYaml `yaml:"ethernet"`
	IP       IPYaml       `yaml:"ip"`
	TCP      *TCPYaml     `yaml:"tcp,omitempty"`
	Delay    *int         `yaml:"delay,omitempty"` // Add per-packet delay in seconds
}

type EthernetYaml struct {
	SrcMAC string `yaml:"srcMac"`
	DstMAC string `yaml:"dstMac"`
}

type IPYaml struct {
	SrcIP          string `yaml:"srcIp"`
	DstIP          string `yaml:"dstIp"`
	TOS            uint8  `yaml:"tos"`
	TTL            uint8  `yaml:"ttl"`
	Id			   uint16  `yaml:"id"`
	FragmentOffset *int   `yaml:"fragmentOffset,omitempty"`
	FragmentLength *int   `yaml:"fragmentLength,omitempty"`
	MoreFragments  bool   `yaml:"moreFragments,omitempty"`
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

type TCPOptionYaml struct {
	TCPOptionType   uint8  `yaml:"tcpOptionType"` 
	TCPOptionLength uint8  `yaml:"tcpOptionLength"`
	TCPOptionData   string `yaml:"tcpOptionData"` 
}

type TCPYaml struct {
	SrcPort       uint16          `yaml:"srcPort"`
	DstPort       uint16          `yaml:"dstPort"`
	Window        uint16          `yaml:"window"`
	Flags         TCPFlags        `yaml:"flags"`
	Data          string          `yaml:"data,omitempty"`
	TCPOptions    []TCPOptionYaml `yaml:"tcpOptions,omitempty"`
	SegmentOffset *int            `yaml:"segmentOffset,omitempty"`
	SegmentLength *int            `yaml:"segmentLength,omitempty"`
}

func parseConfig(data []byte) *service.ServiceConfig {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal(err)
	}

	serviceConfig := service.ServiceConfig{
		Iface:    config.Iface,
		PcapPath: config.PcapPath,
		BPF:      config.BPF,
		SrcMAC:   config.SrcMac,
		DstMAC:   config.DstMac,
	}

	// If a message is defined, store it for runtime construction
	if config.Message != nil {
		msg := service.ServiceMessage{
			DataHex: config.Message.DataHex,
		}

		if config.Message.TCP != nil {
			tcpConfig := tcp.TCPConfig{
				SrcPort: layers.TCPPort(config.Message.TCP.SrcPort),
				DstPort: layers.TCPPort(config.Message.TCP.DstPort),
				Window:  config.Message.TCP.Window,
				SYN:     config.Message.TCP.Flags.SYN,
				ACK:     config.Message.TCP.Flags.ACK,
				PSH:     config.Message.TCP.Flags.PSH,
				FIN:     config.Message.TCP.Flags.FIN,
				RST:     config.Message.TCP.Flags.RST,
				URG:     config.Message.TCP.Flags.URG,
				ECE:     config.Message.TCP.Flags.ECE,
			}

			if config.Message.TCP.Data != "" {
				decodedData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(config.Message.TCP.Data))
				if err != nil {
					log.Fatal("Error decoding message TCP data:", err)
				}
				tcpConfig.Data = decodedData
			}

			var err error
			// Parse TCP Options
			if config.Message.TCP.TCPOptions != nil {
				for _, option := range config.Message.TCP.TCPOptions {
					tcpOption := layers.TCPOption{
						OptionType:   layers.TCPOptionKind(option.TCPOptionType),
						OptionLength: uint8(option.TCPOptionLength),
					}
					if option.TCPOptionData != "" {
						tcpOption.OptionData, err = hex.DecodeString(option.TCPOptionData)
						if err != nil {
							log.Fatalf("Invalid hex in TCP Option data: %v", err)
						}
					}
					tcpConfig.Options = append(tcpConfig.Options, tcpOption)
				}
			}
			
			msg.TCP = &tcpConfig
		}

		serviceConfig.Message = &msg
	}

	packets := []service.ServicePacket{}
	for _, c := range config.Packets {
		p := service.ServicePacket{}

		srcMAC, err := net.ParseMAC(serviceConfig.SrcMAC)
		if err != nil {
			log.Fatal("invalid srcMAC: %w", err)
		}
		dstMAC, err := net.ParseMAC(serviceConfig.DstMAC)
		if err != nil {
			log.Fatal("invalid dstMAC: %w", err)
		}
		p.Ethernet.SrcMAC, p.Ethernet.DstMAC = srcMAC, dstMAC
		p.IP.SrcIP, p.IP.DstIP = net.ParseIP(c.IP.SrcIP), net.ParseIP(c.IP.DstIP)
		p.IP.TOS, p.IP.TTL, p.IP.Id = c.IP.TOS, c.IP.TTL, c.IP.Id

		if c.IP.FragmentOffset != nil {
			p.IP.FragmentOffset = *c.IP.FragmentOffset
		}
		if c.IP.FragmentLength != nil {
			p.IP.FragmentLength = *c.IP.FragmentLength
		}
		p.IP.MoreFragments = c.IP.MoreFragments

		// TCP might be omitted for IP-only packets
		if c.TCP != nil {
			p.TCP.SrcPort, p.TCP.DstPort = layers.TCPPort(c.TCP.SrcPort), layers.TCPPort(c.TCP.DstPort)
			p.TCP.Window = c.TCP.Window
			p.TCP.SYN, p.TCP.ACK, p.TCP.PSH, p.TCP.FIN = c.TCP.Flags.SYN, c.TCP.Flags.ACK, c.TCP.Flags.PSH, c.TCP.Flags.FIN
			p.TCP.RST, p.TCP.URG, p.TCP.ECE = c.TCP.Flags.RST, c.TCP.Flags.URG, c.TCP.Flags.ECE

			if c.TCP.SegmentOffset != nil {
				p.TCP.SegmentOffset = *c.TCP.SegmentOffset
			}
			if c.TCP.SegmentLength != nil {
				p.TCP.SegmentLength = *c.TCP.SegmentLength
			}

			// If no segment/fragment specified and direct data present, decode it now
			if c.TCP.Data != "" {
				p.TCP.Data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(c.TCP.Data))
				if err != nil {
					log.Fatal(err)
				}
			}

			// Parse TCP Options
			if c.TCP.TCPOptions != nil {
				for _, option := range c.TCP.TCPOptions {
					tcpOption := layers.TCPOption{
						OptionType:   layers.TCPOptionKind(option.TCPOptionType),
						OptionLength: option.TCPOptionLength,
					}
					if option.TCPOptionData != "" {
						tcpOption.OptionData, err = hex.DecodeString(option.TCPOptionData)
						if err != nil {
							log.Fatalf("Invalid hex in TCP Option data: %v", err)
						}
					}
					p.TCP.Options = append(p.TCP.Options, tcpOption)
				}
			}
		}

		// Parse per-packet delay if specified
		if c.Delay != nil {
			p.Delay = *c.Delay
		} else {
			// If no delay is specified for this packet, default to 0 seconds (consecutive sends)
			p.Delay = 0
		}

		packets = append(packets, p)
	}
	serviceConfig.Packets = packets
	return &serviceConfig
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	// New flags for command-line override
	srcIPFlag := flag.String("srcip", "", "Override source IP")
	dstIPFlag := flag.String("dstip", "", "Override destination IP")
	srcPortFlag := flag.Uint("srcport", 0, "Override source port")
	dstPortFlag := flag.Uint("dstport", 0, "Override destination port")

	configFile := flag.String("config", "", "Path to the YAML configuration file")
	flag.Parse()

	ymlData, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	config := parseConfig(ymlData)
	if err != nil {
		log.Fatal(err)
	}

	// If command line IPs and ports are provided, override
	var overrideSrcIP, overrideDstIP net.IP
	var overrideSrcPort, overrideDstPort layers.TCPPort

	if *srcIPFlag != "" {
		overrideSrcIP = net.ParseIP(*srcIPFlag)
	}
	if *dstIPFlag != "" {
		overrideDstIP = net.ParseIP(*dstIPFlag)
	}
	if *srcPortFlag != 0 {
		overrideSrcPort = layers.TCPPort(*srcPortFlag)
	}
	if *dstPortFlag != 0 {
		overrideDstPort = layers.TCPPort(*dstPortFlag)
	}

	// If overrideDstIP and overrideDstPort are provided, update the BPF
	if overrideDstIP != nil {
		config.BPF = "tcp and src host " + overrideDstIP.String()
	}

	// Apply overrides to all packets
	for i := range config.Packets {
		p := &config.Packets[i]
		if overrideSrcIP != nil {
			p.IP.SrcIP = overrideSrcIP
		}
		if overrideDstIP != nil {
			p.IP.DstIP = overrideDstIP
		}
		if p.TCP.SrcPort != 0 || p.TCP.DstPort != 0 { // TCP layer is defined
			if overrideSrcPort != 0 {
				p.TCP.SrcPort = overrideSrcPort
			}
			if overrideDstPort != 0 {
				p.TCP.DstPort = overrideDstPort
			}
		}
	}

	// Apply overrides to Message if TCP is present
	if config.Message != nil && config.Message.TCP != nil {
		if overrideSrcPort != 0 {
			config.Message.TCP.SrcPort = overrideSrcPort
		}
		if overrideDstPort != 0 {
			config.Message.TCP.DstPort = overrideDstPort
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	service.Start(*config)
}
