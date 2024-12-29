package main

import (
	"encoding/hex"
	"flag"
	"log"
	"fmt"
	"net"
	"os"
	"github.com/censoredplanet/CenDPI/internal/service"
	"github.com/censoredplanet/CenDPI/internal/http"
	"github.com/censoredplanet/CenDPI/internal/tls"
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
	Domain	 string
    Protocol string
}

type Message struct {
    HTTP    *HTTPMessageConf `yaml:"http,omitempty"`
    TLS     *TLSMessageConf  `yaml:"tls,omitempty"`
}

type HTTPMessageConf struct {
    Method  string            `yaml:"method"`
    Path    string            `yaml:"path"`
    Version string            `yaml:"version,omitempty"`
}

type TLSMessageConf struct {
    ClientHelloConfig ClientHelloYaml    `yaml:"clientHelloConfig"`
    Records           []TLSRecordYaml    `yaml:"records"`
}

type ClientHelloYaml struct {
    ChVersion 	 	 string `yaml:"chVersion"`
}

type TLSRecordYaml struct {
    ContentType     string `yaml:"contentType"`    // 2 hex digits
    RecordVersion   string `yaml:"recordVersion"`  // 4 hex digits
    PayloadType     string `yaml:"payloadType"`    // e.g. "clienthello"
    Offset          int    `yaml:"offset,omitempty"`
    Length          int    `yaml:"length,omitempty"`
    AlertReasonHex  string `yaml:"alertReasonHex,omitempty"`
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
	Id			   uint16 `yaml:"id"`
	Protocol       *uint8 `yaml:"protocol,omitempty"`
	FragmentOffset *int   `yaml:"fragmentOffset,omitempty"`
	MessageOffset  *int   `yaml:"messageOffset,omitempty"`
	MessageLength  *int   `yaml:"messageLength,omitempty"`
	ReverseDomain    bool   `yaml:"reverseDomain,omitempty"`
	MoreFragments  bool   `yaml:"moreFragments,omitempty"`
	IPOptions      []IPOptionYaml `yaml:"ipOptions,omitempty"`
}

type IPOptionYaml struct {
    IpOptionType   uint8  `yaml:"ipOptionType"`
    IpOptionLength uint8  `yaml:"ipOptionLength"`
    IpOptionData   string `yaml:"ipOptionData,omitempty"`
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
	UrgentPointer *int 			  `yaml:"urgentPointer,omitempty"`
	Data          string          `yaml:"data,omitempty"`
	TCPOptions    []TCPOptionYaml `yaml:"tcpOptions,omitempty"`
	SeqRelativeToInitial *int    `yaml:"seqRelativeToInitial,omitempty"`
	SeqRelativeToExpected *int    `yaml:"seqRelativeToExpected,omitempty"`
	AckRelativeToExpected *int    `yaml:"ackRelativeToExpected,omitempty"`
	MessageOffset *int            `yaml:"messageOffset,omitempty"`
	MessageLength *int            `yaml:"messageLength,omitempty"`
	ReverseDomain 	bool 		  `yaml:"reverseDomain,omitempty"`
	CorruptChecksum bool          `yaml:"corruptChecksum,omitempty"`
}

func valOrZero(p *int) int {
    if p == nil {
        return 0
    }
    return *p
}

func parseConfig(data []byte) (*Config, error) {
    var config Config
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, err
    }
    return &config, nil
}

func buildServiceConfig(config *Config) (*service.ServiceConfig, error) {

	serviceConfig := service.ServiceConfig{
		Iface:    	config.Iface,
		PcapPath: 	config.PcapPath,
		BPF:      	config.BPF,
		SrcMAC:   	config.SrcMac,
		DstMAC:   	config.DstMac,
		Domain:		config.Domain,
        Protocol:	config.Protocol,
	}

	if config.Message != nil {
        msg := service.ServiceMessage{}
        if config.Message.HTTP != nil {
            msg.HTTP = &http.HTTPConfig{
                Method:  config.Message.HTTP.Method,
                Path:    config.Message.HTTP.Path,
				Domain:  config.Domain,
				Version: config.Message.HTTP.Version,
            }
        }
        if config.Message.TLS != nil {
			ch := tls.ClientHelloConfig{
				SNI:		config.Domain,
                ChVersion:	config.Message.TLS.ClientHelloConfig.ChVersion,
            }

            var records []tls.TLSRecordConfig
            for _, r := range config.Message.TLS.Records {
				typeByte, err := hex.DecodeString(r.ContentType)
                if err != nil || len(typeByte) != 1 {
                    return nil, fmt.Errorf("invalid contentType '%s'", r.ContentType)
                }
                verBytes, err := hex.DecodeString(r.RecordVersion)
                if err != nil || len(verBytes) != 2 {
                    return nil, fmt.Errorf("invalid recordVersion '%s'", r.RecordVersion)
                }
                rec := tls.TLSRecordConfig{
                    ContentType:   	typeByte[0],
                    RecordVersion: 	[2]byte{verBytes[0], verBytes[1]},
                    PayloadType:   	tls.TLSRecordType(r.PayloadType),
                    Offset:        	r.Offset,
                    Length:        	r.Length,
                    AlertReasonHex: r.AlertReasonHex,
                }
                records = append(records, rec)
            }

            msg.TLS = &tls.TLSConfig{
                ClientHelloConfig: 	ch,
                Records:     		records,
            }
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
		protocol := layers.IPProtocolTCP // default to TCP
		if c.IP.Protocol != nil {
			protocol = layers.IPProtocol(*c.IP.Protocol)
		}
		p.IP.Protocol = protocol
		p.IP.FragmentOffset = valOrZero(c.IP.FragmentOffset)
		p.IP.MessageOffset = valOrZero(c.IP.MessageOffset)
		p.IP.MessageLength = valOrZero(c.IP.MessageLength)
		p.IP.MoreFragments = c.IP.MoreFragments
		p.IP.ReverseDomain = c.IP.ReverseDomain

		// Parse IP Options
		if len(c.IP.IPOptions) > 0 {
			for _, opt := range c.IP.IPOptions {
				var optData []byte
				if opt.IpOptionData != "" {
					var err error
					optData, err = hex.DecodeString(opt.IpOptionData)
					if err != nil {
						log.Fatalf("Invalid hex in IP Option data: %v", err)
					}
				}
				p.IP.Options = append(p.IP.Options, layers.IPv4Option{
					OptionType:   opt.IpOptionType,
					OptionLength: opt.IpOptionLength,
					OptionData:   optData,
				})
			}
		}

		// TCP might be omitted for IP-only packets
		if c.TCP != nil {
			p.TCP.SrcPort, p.TCP.DstPort = layers.TCPPort(c.TCP.SrcPort), layers.TCPPort(c.TCP.DstPort)
			p.TCP.Window = c.TCP.Window
			p.TCP.Urgent = uint16(valOrZero(c.TCP.UrgentPointer))
			p.TCP.SYN, p.TCP.ACK, p.TCP.PSH, p.TCP.FIN = c.TCP.Flags.SYN, c.TCP.Flags.ACK, c.TCP.Flags.PSH, c.TCP.Flags.FIN
			p.TCP.RST, p.TCP.URG, p.TCP.ECE = c.TCP.Flags.RST, c.TCP.Flags.URG, c.TCP.Flags.ECE
			p.TCP.SeqRelativeToInitial = valOrZero(c.TCP.SeqRelativeToInitial)
			p.TCP.SeqRelativeToExpected = valOrZero(c.TCP.SeqRelativeToExpected)
			p.TCP.AckRelativeToExpected = valOrZero(c.TCP.AckRelativeToExpected)
			p.TCP.MessageOffset = valOrZero(c.TCP.MessageOffset)
			p.TCP.MessageLength = valOrZero(c.TCP.MessageLength)
			p.TCP.CorruptChecksum = c.TCP.CorruptChecksum
			p.TCP.ReverseDomain = c.TCP.ReverseDomain

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
	return &serviceConfig, nil
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

	domainFlag := flag.String("domain", "", "Domain name to be used in Host header or SNI")
    httpFlag := flag.Bool("http", false, "HTTP mode")
    httpsFlag := flag.Bool("https", false, "HTTPS mode")

	configFile := flag.String("config", "", "Path to the YAML configuration file")
	flag.Parse()

	if (*httpFlag && *httpsFlag) || (!*httpFlag && !*httpsFlag) {
        log.Fatal("Error: You must specify exactly one of -http or -https.")
    }

    if *domainFlag == "" {
        log.Fatal("Error: -domain must be provided.")
    }

	ymlData, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := parseConfig(ymlData)
    if err != nil {
        log.Fatal(err)
    }

	cfg.Domain = *domainFlag
    if *httpFlag {
        cfg.Protocol = "http"
    } else if *httpsFlag {
        cfg.Protocol = "https"
    }

	// Convert to service config
    serviceConfig, err := buildServiceConfig(cfg)
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
		serviceConfig.BPF = "tcp and src host " + overrideDstIP.String()
	}

	// Apply overrides to all packets
	for i := range serviceConfig.Packets {
		p := &serviceConfig.Packets[i]
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

	err = service.Start(*serviceConfig)
    if err != nil {
        log.Fatal(err)
    }
}
