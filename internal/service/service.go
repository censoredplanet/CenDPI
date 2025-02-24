package service

import (
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/censoredplanet/CenDPI/internal/assembler"
	"github.com/censoredplanet/CenDPI/internal/ethernet"
	"github.com/censoredplanet/CenDPI/internal/http"
	"github.com/censoredplanet/CenDPI/internal/ip"
	"github.com/censoredplanet/CenDPI/internal/netcap"
	"github.com/censoredplanet/CenDPI/internal/tcp"
	"github.com/censoredplanet/CenDPI/internal/tls"
	"github.com/gopacket/gopacket/layers"

	//"github.com/gopacket/gopacket/tcpassembly"
	"gopkg.in/yaml.v3"
)

// Each service corresponds to one measurement (i.e., one TCP connection)
type ServiceConfig struct {
	Name      string
	Number    uint16
	Iface     string
	PcapPath  string
	BPF       string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   layers.TCPPort
	DstPort   layers.TCPPort
	Flowkey   netcap.FlowKey
	Packets   []ServicePacket `yaml:"packets"`
	Message   *ServiceMessage `yaml:"message"`
	Domain    string
	IsControl bool
	Protocol  string `yaml:"protocol"`
	Label     string
}

type ServiceMessage struct {
	HTTP                *http.HTTPConfig `yaml:"http"`
	TLS                 *tls.TLSConfig   `yaml:"tls"`
	DomainAllCaps       bool             `yaml:"domainAllCaps"`
	DomainRandomCase    bool             `yaml:"domainRandomCase"`
	DomainPrependStar   bool             `yaml:"domainPrependStar"`
	DomainAppendStar    bool             `yaml:"domainAppendStar"`
	DomainPrependSpace  bool             `yaml:"domainPrependSpace"`
	DomainAppendSpace   bool             `yaml:"domainAppendSpace"`
	PayloadBytes        []byte           // built with the original domain
	ReversePayloadBytes []byte           // built with the reversed domain
}

type ServicePacket struct {
	Ethernet     ethernet.EthernetConfig
	IP           ip.IPConfig    `yaml:"ip"`
	TCP          *tcp.TCPConfig `yaml:"tcp"`
	Delay        float64        `yaml:"delay"` // Per-packet delay in seconds
	ServerPacket bool           `yaml:"serverPacket"`
}

type Target struct {
	TargetIP      string `json:"TargetIP"`
	TargetPort    uint16 `json:"TargetPort"`
	SourcePort    uint16 `json:"SourcePort"`
	TestDomain    string `json:"TestDomain"`
	ControlDomain string `json:"ControlDomain"`
	Protocol      string `json:"Protocol"` // e.g. "http" or "https"
	Label         string `json:"Label"`
}

type tcpState struct {
	SeqNum     uint32
	AckNum     uint32
	InitialSeq uint32
}

// var tcpStates = make(map[netcap.FlowKey]tcpState)
var tcpStates sync.Map // key=FlowKey, value=tcpState

func loadTCPState(key netcap.FlowKey) (tcpState, bool) {
	value, ok := tcpStates.Load(key)
	if !ok {
		return tcpState{}, false
	}
	return value.(tcpState), true
}

func storeTCPState(key netcap.FlowKey, st tcpState) {
	tcpStates.Store(key, st)
}

func (s *ServiceConfig) UnmarshalYAML(node *yaml.Node) error {
	type base ServiceConfig
	raw := struct {
		base `yaml:",inline"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(raw.base.Protocol)) {
	// Since we dont handle the 'both' case anywhere in the code, should we remove it, or add support later on?
	case "both", "https", "http":
		s.Protocol = raw.base.Protocol
	default:
		return fmt.Errorf("invalid protocol field: %s, specified in probe yaml configration file", raw.base.Protocol)
	}

	*s = ServiceConfig(raw.base)

	return nil
}

func wrapError(err *error, str string, args ...any) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), *err)
		log.Println(*err)
	}
}

func sendAndWait(netCap *netcap.NetCap, pkt []byte, delay time.Duration, flowKey netcap.FlowKey) error {
	if err := netCap.SendPacket(pkt, flowKey); err != nil {
		return err
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	return nil
}

func buildSingleMessage(cfg ServiceConfig, domain string) ([]byte, error) {
	if cfg.Message == nil {
		return nil, fmt.Errorf("buildSingleMessage: no Message config present")
	}

	switch cfg.Protocol {
	case "http":
		if cfg.Message.HTTP == nil {
			return nil, fmt.Errorf("HTTP config is nil")
		}
		oldDomain := cfg.Message.HTTP.Domain
		cfg.Message.HTTP.Domain = domain

		httpBytes, err := http.BuildHTTPRequest(cfg.Message.HTTP)

		cfg.Message.HTTP.Domain = oldDomain
		if err != nil {
			return nil, fmt.Errorf("error building HTTP request: %w", err)
		}
		return []byte(httpBytes), nil

	case "https":
		if cfg.Message.TLS == nil {
			return nil, fmt.Errorf("TLS config is nil")
		}
		oldSNI := cfg.Message.TLS.ClientHelloConfig.SNI
		cfg.Message.TLS.ClientHelloConfig.SNI = domain

		tlsBytes, err := tls.BuildTLS(cfg.Message.TLS)

		cfg.Message.TLS.ClientHelloConfig.SNI = oldSNI
		if err != nil {
			return nil, fmt.Errorf("error building TLS handshake: %w", err)
		}
		return tlsBytes, nil

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}
}

// buildMessages builds both test and control payloads
func buildMessages(cfg ServiceConfig) ([]byte, []byte, error) {
	payloadBytes, err := buildSingleMessage(cfg, cfg.Domain)
	if err != nil {
		return nil, nil, fmt.Errorf("building test message: %w", err)
	}

	// reverse the domain
	reverseDomain := tcp.RearrangeDomainIn16BitChunks(cfg.Domain)

	reverseBytes, err := buildSingleMessage(cfg, reverseDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("building reverse domain message: %w", err)
	}

	return payloadBytes, reverseBytes, nil
}

func randomCase(s string) string {
	var b strings.Builder
	for _, r := range s {
		if rand.IntN(2) == 0 {
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}

func StartSingleMeasurement(netCap *netcap.NetCap, probe ServiceConfig, packetCh <-chan netcap.PacketInfo) {
	var err error
	defer wrapError(&err, "CenDPI")

	probe.Domain = "blocked.com"
	if probe.Message.DomainAllCaps {
		probe.Domain = strings.ToUpper(probe.Domain)
	} else if probe.Message.DomainRandomCase {
		probe.Domain = randomCase(probe.Domain)
	}
	if probe.Message.DomainPrependStar {
		probe.Domain = "*****" + probe.Domain
	}
	if probe.Message.DomainAppendStar {
		probe.Domain = probe.Domain + "*****"
	}
	if probe.Message.DomainPrependSpace {
		probe.Domain = "     " + probe.Domain
	}
	if probe.Message.DomainAppendSpace {
		probe.Domain = probe.Domain + "     "
	}

	flowKey := netcap.NormalizeFlowKey(probe.SrcIP, probe.SrcPort, probe.DstIP, probe.DstPort)
	probe.Flowkey = flowKey
	for n, p := range probe.Packets {

		if p.ServerPacket {
			// server sent packet
			// do some processing

			p.IP.SrcIP, p.IP.DstIP = probe.DstIP, probe.SrcIP
			p.TCP.SrcPort, p.TCP.DstPort = probe.DstPort, probe.SrcPort
			initAck := rand.Uint32()
			state, ok := loadTCPState(flowKey)
			if !ok {
				log.Printf("packet %d: no TCP state found for flow %v\n", n, flowKey)
				break
			}

			p.TCP.Seq, p.TCP.Ack = initAck, state.SeqNum+1
			storeTCPState(flowKey, tcpState{
				SeqNum:     state.SeqNum + 1,
				AckNum:     initAck + 1,
				InitialSeq: state.InitialSeq,
			})

			p.TCP.Flags = tcp.TCPFlags{SYN: true, ACK: true}

			// Build the Ethernet/IP/TCP layers
			packet, err := assembler.New().
				AddLayer(ethernet.New(&p.Ethernet)).
				AddLayer(ip.New(&p.IP)).
				AddLayer(tcp.New(p.TCP)).
				Build(p.TCP.CorruptChecksum)
			if err != nil {
				log.Printf("packet %d: Assembler Build error: %v\n", n, err)
				break
			}

			if err := sendAndWait(netCap, packet, time.Duration(p.Delay*float64(time.Second)), flowKey); err != nil {
				log.Printf("packet %d: sendAndWait error: %v\n", n, err)
				break
			}

			continue
		}

		if n == 0 {
			initSeq := rand.Uint32()
			storeTCPState(flowKey, tcpState{
				SeqNum:     initSeq,
				AckNum:     0,
				InitialSeq: initSeq,
			})
		}

		p.IP.SrcIP, p.IP.DstIP = probe.SrcIP, probe.DstIP

		hasTCP := false
		if p.TCP != nil {
			hasTCP = true
			p.TCP.SrcPort, p.TCP.DstPort = probe.SrcPort, probe.DstPort
		}

		if hasTCP {
			state, ok := loadTCPState(flowKey)
			if !ok {
				log.Printf("packet %d: no TCP state found for flow %v\n", n, flowKey)
				break
			}
			p.TCP.Seq, p.TCP.Ack = state.SeqNum, state.AckNum
			curIsq := state.InitialSeq

			if p.TCP.SeqRelativeToExpected != 0 {
				p.TCP.Seq = uint32(int64(p.TCP.Seq) + int64(p.TCP.SeqRelativeToExpected))
			}
			if p.TCP.AckRelativeToExpected != 0 {
				p.TCP.Ack = uint32(int64(p.TCP.Ack) + int64(p.TCP.AckRelativeToExpected))
			}
			if p.TCP.ZeroAck {
				p.TCP.Ack = 0
			}
			if p.TCP.SeqRelativeToInitial != 0 {
				p.TCP.Seq = uint32(int64(curIsq) + int64(p.TCP.SeqRelativeToInitial))
			}

			if p.TCP.SeqSetToInitial {
				p.TCP.Seq = curIsq
			}

			// If we have a "MessageLength" in the config, it means we want to slice
			// from the overall application message.
			if p.TCP.MessageLength != 0 {
				// We expect no raw data in p.TCP.Data if we plan to slice the message.
				if len(p.TCP.Data) != 0 {
					log.Printf("packet %d: asked for message slicing, but TCP.Data is not empty\n", n)
					break
				}
				if probe.Message == nil {
					log.Printf("packet %d: asked for message slicing, but config.Message is nil\n", n)
					break
				}
				// Build the application message if not done yet
				if len(probe.Message.PayloadBytes) == 0 {
					rawPayloadBytes, rawReversedPayloadBytes, buildErr := buildMessages(probe)
					if buildErr != nil {
						log.Printf("packet %d: buildMessages error: %v\n", n, buildErr)
						break
					}
					probe.Message.PayloadBytes = rawPayloadBytes
					probe.Message.ReversePayloadBytes = rawReversedPayloadBytes
				}

				messageOffsetBytes := p.TCP.MessageOffset // in bytes
				// Handle negative offset by padding zeros before the actual data
				padLen := 0
				if messageOffsetBytes < 0 {
					padLen = -messageOffsetBytes
					messageOffsetBytes = 0
				}
				var length int
				if p.TCP.MessageLength == -1 {
					// take entire remainder
					length = len(probe.Message.PayloadBytes) - messageOffsetBytes
					if length < 1 {
						log.Printf("packet %d: invalid segment offset (beyond message size)\n", n)
						break
					}
				} else {
					length = p.TCP.MessageLength
				}
				endPos := messageOffsetBytes + length
				if endPos > len(probe.Message.PayloadBytes) {
					log.Printf("packet %d: segment out of range. Current probe: %d\n", n, probe.Number)
					break
				}
				var raw []byte
				if p.TCP.ReverseDomain {
					raw = probe.Message.ReversePayloadBytes[messageOffsetBytes:endPos]
				} else {
					raw = probe.Message.PayloadBytes[messageOffsetBytes:endPos]
				}
				if padLen > 0 {
					pad := make([]byte, padLen)
					p.TCP.Data = append(pad, raw...)
				} else {
					p.TCP.Data = raw
				}
			}

			// Build the Ethernet/IP/TCP layers
			packet, err := assembler.New().
				AddLayer(ethernet.New(&p.Ethernet)).
				AddLayer(ip.New(&p.IP)).
				AddLayer(tcp.New(p.TCP)).
				Build(p.TCP.CorruptChecksum)
			if err != nil {
				log.Printf("packet %d: Assembler Build error: %v\n", n, err)
				break
			}

			if err := sendAndWait(netCap, packet, time.Duration(p.Delay*float64(time.Second)), flowKey); err != nil {
				log.Printf("packet %d: sendAndWait error: %v\n", n, err)
				break
			}

		} else {
			// --------------------------------------------------
			// Case 2: No TCP layer => IP fragmentation path?
			// --------------------------------------------------
			if p.IP.MessageLength != 0 {
				if probe.Message == nil {
					log.Printf("packet %d: IP fragmentation requested but config.Message is nil\n", n)
					break
				}

				// If we haven't built the application message yet, do so:
				if len(probe.Message.PayloadBytes) == 0 {
					rawPayloadBytes, rawReversedPayloadBytes, buildErr := buildMessages(probe)
					if buildErr != nil {
						log.Printf("packet %d: buildMessages error: %v\n", n, buildErr)
						break
					}
					state, ok := loadTCPState(flowKey)
					if !ok {
						log.Printf("packet %d: no TCP state found for flow %v\n", n, flowKey)
						break
					}
					tcpWrap := &tcp.TCPConfig{
						SrcPort: probe.SrcPort,
						DstPort: probe.DstPort,
						Seq:     state.SeqNum,
						Ack:     state.AckNum,
						Flags:   tcp.TCPFlags{PSH: true, ACK: true},
						Window:  2056,
						Data:    rawPayloadBytes,
					}
					tcpWrapReversedPayload := &tcp.TCPConfig{
						SrcPort: probe.SrcPort,
						DstPort: probe.DstPort,
						Seq:     state.SeqNum,
						Ack:     state.AckNum,
						Flags:   tcp.TCPFlags{PSH: true, ACK: true},
						Window:  2056,
						Data:    rawReversedPayloadBytes,
					}
					rawTCP, wrapErr := tcp.BuildAndSerialize(tcpWrap, p.IP.SrcIP, p.IP.DstIP)
					if wrapErr != nil {
						log.Printf("packet %d: building TCP for IP fragmentation error: %v\n", n, wrapErr)
						break
					}
					rawTCPReversed, wrapErr := tcp.BuildAndSerialize(tcpWrapReversedPayload, p.IP.SrcIP, p.IP.DstIP)
					if wrapErr != nil {
						log.Printf("packet %d: building TCP for IP fragmentation error: %v\n", n, wrapErr)
					}
					probe.Message.PayloadBytes = rawTCP
					probe.Message.ReversePayloadBytes = rawTCPReversed
				}

				messageOffsetBytes := p.IP.MessageOffset
				if messageOffsetBytes%8 != 0 {
					log.Printf("packet %d: message offset for IP fragmentation must be a multiple of 8 bytes\n", n)
					break
				}
				var length int
				if p.IP.MessageLength == -1 {
					length = len(probe.Message.PayloadBytes) - messageOffsetBytes
					if length < 1 {
						log.Printf("packet %d: invalid fragment offset (beyond message size)\n", n)
						break
					}
				} else {
					length = p.IP.MessageLength
				}

				endPos := messageOffsetBytes + length
				if endPos > len(probe.Message.PayloadBytes) {
					log.Printf("packet %d: fragment out of range\n", n)
					break
				}
				fragmentPayload := probe.Message.PayloadBytes[messageOffsetBytes:endPos]
				if p.IP.ReverseDomain {
					fragmentPayload = probe.Message.ReversePayloadBytes[messageOffsetBytes:endPos]
				}

				// Build Ethernet/IP (with the fragment payload)
				packet, err := assembler.New().
					AddLayer(ethernet.New(&p.Ethernet)).
					AddLayer(ip.NewWithPayload(&p.IP, fragmentPayload)).
					Build(false)
				if err != nil {
					log.Printf("packet %d: Assembler Build error: %v\n", n, err)
					break
				}

				if err := sendAndWait(netCap, packet, time.Duration(p.Delay*float64(time.Second)), flowKey); err != nil {
					log.Printf("packet %d: sendAndWait error: %v\n", n, err)
					break
				}

			} else {
				// No TCP and no fragmentation => nothing to send
				log.Printf("packet %d: No TCP layer specified and no IP fragmentation => nothing to send\n", n)
				break
			}
		}
	}
}
