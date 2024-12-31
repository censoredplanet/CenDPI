package main

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"flag"
	"log"
	"fmt"
	"net"
	"os"
    "time"
	"bufio"
	"strings"
	"github.com/censoredplanet/CenDPI/internal/service"
	"github.com/censoredplanet/CenDPI/internal/http"
	"github.com/censoredplanet/CenDPI/internal/tls"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"
)

type GlobalMeasurementConfig struct {
    Interface  string   `yaml:"interface"`
    PcapPath   string   `yaml:"pcapPath"`
    SourceMAC  string   `yaml:"sourceMAC"`
    TargetMAC  string   `yaml:"targetMAC"`
	SourceIP   string   `yaml:"sourceIP"`
    Probelist  []string `yaml:"probelist"`
}

type Target struct {
    TargetIP      string `json:"TargetIP"`
    TargetPort    uint16 `json:"TargetPort"`
	SourcePort	  uint16 `json:"SourcePort,omitempty"`
    TestDomain    string `json:"TestDomain"`
    Protocol      string `json:"Protocol"`        // e.g. "http" or "https"
    ControlDomain string `json:"ControlDomain,omitempty"`
    Label         string `json:"Label,omitempty"`
}

type ProbeConfig struct {
	Protocol	string 	  `yaml:"protocol"` 
	Message  	*Message  `yaml:"message,omitempty"`
	Packets  	[]Packet  `yaml:"packets"`
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
	Delay    int          `yaml:"delay,omitempty"` // Add per-packet delay in seconds
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

type SourcePortOracle struct {
    ports []uint16
    pos   int
}

func NewSourcePortOracle(minPort, maxPort uint16) *SourcePortOracle {
    if minPort > maxPort {
        panic("minPort cannot be greater than maxPort")
    }
    total := maxPort - minPort + 1
    portSlice := make([]uint16, total)

    for i := range portSlice {
        portSlice[i] = uint16(minPort + uint16(i))
    }

    shufflePorts(portSlice)

    return &SourcePortOracle{
        ports: portSlice,
        pos:   0,
    }
}

func (o *SourcePortOracle) NextPort() uint16 {
    if o.pos >= len(o.ports) {
        o.pos = 0
    }
    p := o.ports[o.pos]
    o.pos++
    return p
}

func shufflePorts(ports []uint16) {
    rand.Seed(time.Now().UnixNano())
    for i := len(ports) - 1; i > 0; i-- {
        j := rand.Intn(i + 1)
        ports[i], ports[j] = ports[j], ports[i]
    }
}

func valOrZero(p *int) int {
    if p == nil {
        return 0
    }
    return *p
}

func parseGlobalMeasurementConfig(path string) (*GlobalMeasurementConfig, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var cfg GlobalMeasurementConfig
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    return &cfg, nil
}

func parseTargetsJSONL(path string) ([]Target, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var results []Target
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            // skip empty lines or comment lines
            continue
        }
        var tgt Target
        if err := json.Unmarshal([]byte(line), &tgt); err != nil {
            return nil, fmt.Errorf("json decode error on line: %s\n%v", line, err)
        }
        results = append(results, tgt)
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return results, nil
}

func parseProbeConfigYAML(path string) (*ProbeConfig, error) {
    ymlData, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
	var config ProbeConfig
    if err := yaml.Unmarshal(ymlData, &config); err != nil {
        return nil, err
    }
    return &config, nil
}

func buildServiceConfig(
	globalConfig *GlobalMeasurementConfig,
	target *Target, 
	probeConfig *ProbeConfig, 
	isControl bool,
	portOracle *SourcePortOracle,
) (*service.ServiceConfig, error) {

	serviceConfig := service.ServiceConfig{
		Iface:    	globalConfig.Interface,
		PcapPath: 	globalConfig.PcapPath,
		BPF:      	"tcp and src host " + target.TargetIP,
		SrcMAC:   	globalConfig.SourceMAC,
		DstMAC:   	globalConfig.TargetMAC,
		SrcIP:    	net.ParseIP(globalConfig.SourceIP),
		DstIP:		net.ParseIP(target.TargetIP),
		SrcPort:	layers.TCPPort(portOracle.NextPort()),
		DstPort:	layers.TCPPort(target.TargetPort),
        Protocol:	target.Protocol,
		IsControl:  isControl,
		Label:		target.Label,
	}

	currentDomain := target.TestDomain
	if isControl {
		currentDomain = target.ControlDomain
	}
	serviceConfig.Domain = currentDomain

	if probeConfig.Message != nil {
        msg := service.ServiceMessage{}
        if probeConfig.Message.HTTP != nil {
            msg.HTTP = &http.HTTPConfig{
                Method:  probeConfig.Message.HTTP.Method,
                Path:    probeConfig.Message.HTTP.Path,
				Domain:  serviceConfig.Domain,
				Version: probeConfig.Message.HTTP.Version,
            }
        }
        if probeConfig.Message.TLS != nil {
			ch := tls.ClientHelloConfig{
				SNI:		serviceConfig.Domain,
                ChVersion:	probeConfig.Message.TLS.ClientHelloConfig.ChVersion,
            }
            var records []tls.TLSRecordConfig
            for _, r := range probeConfig.Message.TLS.Records {
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
	for _, c := range probeConfig.Packets {
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
		p.IP.SrcIP, p.IP.DstIP = serviceConfig.SrcIP, serviceConfig.DstIP
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
			p.TCP.SrcPort, p.TCP.DstPort = serviceConfig.SrcPort, serviceConfig.DstPort
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
		p.Delay = c.Delay
		packets = append(packets, p)
	}
	serviceConfig.Packets = packets
	return &serviceConfig, nil
}


func main() {
    if os.Geteuid() != 0 {
        log.Fatal("This program must be run as root! (sudo)")
    }

    measurementConfigPath := flag.String("config", "", "Path to global measurement.config YAML")
    targetConfigPath := flag.String("target", "", "Path to target.jsonl (line-delimited JSON)")

    flag.Parse()
    if *measurementConfigPath == "" || *targetConfigPath == "" {
        log.Fatal("Usage: cendpi -measurement measurement.config -target target.jsonl")
    }

    globalCfg, err := parseGlobalMeasurementConfig(*measurementConfigPath)
    if err != nil {
        log.Fatalf("Error parsing measurement config: %v\n", err)
    }

    targets, err := parseTargetsJSONL(*targetConfigPath)
    if err != nil {
        log.Fatalf("Error parsing targets file: %v\n", err)
    }

	sourcePortOracle := NewSourcePortOracle(39152, 65535)

    // todo: add concurrency
	for _, probeFile := range globalCfg.Probelist {
		for _, tgt := range targets {
            log.Printf("Measuring target %s:%d (domain=%s) with probe '%s'\n",
                tgt.TargetIP, tgt.TargetPort, tgt.TestDomain, probeFile)

            probeCfg, err := parseProbeConfigYAML(probeFile)
            if err != nil {
                log.Printf("Skipping probe %s: %v\n", probeFile, err)
                continue
            }

			if probeCfg.Protocol != "both" && probeCfg.Protocol != tgt.Protocol {
				continue
			}

			serviceConfigControl, err := buildServiceConfig(globalCfg, &tgt, probeCfg, true, sourcePortOracle) // do control measurement first
			if err != nil {
				log.Fatal("Error building control service config: %v\n", err)
			}
			serviceConfigTest, err := buildServiceConfig(globalCfg, &tgt, probeCfg, false, sourcePortOracle)
			if err != nil {
				log.Fatal("Error building test service config: %v\n", err)
			}

            err = service.Start(*serviceConfigControl)
            if err != nil {
                log.Fatalf("Error starting control measurement: %v\n", err)
            }

			err = service.Start(*serviceConfigTest)
			if err != nil {
				log.Fatalf("Error starting test measurement: %v\n", err)
			}
        }
    }

    log.Println("All measurements done.")
}

