package service

import (
	"bytes"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/censoredplanet/CenDPI/internal/assembler"
	"github.com/censoredplanet/CenDPI/internal/ethernet"
	"github.com/censoredplanet/CenDPI/internal/http"
	"github.com/censoredplanet/CenDPI/internal/ip"
	"github.com/censoredplanet/CenDPI/internal/netcap"
	"github.com/censoredplanet/CenDPI/internal/tcp"
	"github.com/censoredplanet/CenDPI/internal/tls"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"
)

type ServiceConfig struct {
	Iface     string
	PcapPath  string
	BPF       string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   layers.TCPPort
	DstPort   layers.TCPPort
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
	PayloadBytes        []byte           // built with the original domain
	ReversePayloadBytes []byte           // built with the reversed domain
}

type ServicePacket struct {
	Ethernet ethernet.EthernetConfig
	IP       ip.IPConfig    `yaml:"ip"`
	TCP      *tcp.TCPConfig `yaml:"tcp"`
	Delay    float64        `yaml:"delay"` // Per-packet delay in seconds
}

type Target struct {
	TargetIP   string `json:"TargetIP"`
	TargetPort uint16 `json:"TargetPort"`
	SourcePort uint16 `json:"SourcePort"`
	TestDomain string `json:"TestDomain"`
	Protocol   string `json:"Protocol"` // e.g. "http" or "https"
	IsControl  bool   `json:"IsDomain"`
	Label      string `json:"Label"`
}

type FlowKey struct {
	IP1   string
	Port1 layers.TCPPort
	IP2   string
	Port2 layers.TCPPort
}

type tcpState struct {
	SeqNum     uint32
	AckNum     uint32
	InitialSeq uint32
}

var tcpStates = make(map[FlowKey]tcpState)

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

func NormalizeFlowKey(srcIP net.IP, srcPort layers.TCPPort, dstIP net.IP, dstPort layers.TCPPort) FlowKey {
	a := srcIP.To16()
	b := dstIP.To16()

	cmp := bytes.Compare(a, b)
	if cmp == 0 {
		if srcPort < dstPort {
			return FlowKey{IP1: srcIP.String(), Port1: srcPort, IP2: dstIP.String(), Port2: dstPort}
		}
		return FlowKey{IP1: dstIP.String(), Port1: dstPort, IP2: srcIP.String(), Port2: srcPort}
	} else if cmp < 0 {
		return FlowKey{IP1: srcIP.String(), Port1: srcPort, IP2: dstIP.String(), Port2: dstPort}
	} else {
		return FlowKey{IP1: dstIP.String(), Port1: dstPort, IP2: srcIP.String(), Port2: srcPort}
	}
}

func wrapError(err *error, str string, args ...any) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), *err)
		log.Println(*err)
	}
}

func collectPackets(packetCh <-chan netcap.PacketInfo, duration time.Duration, flowKey FlowKey) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	for {
		select {
		case packet := <-packetCh:
			tcpLayer := packet.Data.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				t := tcpLayer.(*layers.TCP)
				states := tcpStates[flowKey]

				// Calculate how much to increment Ack
				ackIncrement := uint32(len(t.Payload))
				// SYN or FIN increments ACK by 1
				if t.SYN || t.FIN {
					ackIncrement++
				}

				// Move seq forward if the remote host ACKs our data
				if states.SeqNum < packet.Ack {
					states.SeqNum = packet.Ack
				}
				// Our new Ack = incoming seq + ackIncrement
				nextAck := packet.Seq + ackIncrement
				if states.AckNum < nextAck {
					states.AckNum = nextAck
				}

				tcpStates[flowKey] = tcpState{
					SeqNum:     states.SeqNum,
					AckNum:     states.AckNum,
					InitialSeq: states.InitialSeq,
				}
			}

		case <-timer.C:
			return
		}
	}
}

func sendAndCollect(netCap *netcap.NetCap, packetCh <-chan netcap.PacketInfo, pkt []byte, delay time.Duration, flowKey FlowKey, port uint16) error {
	if err := netCap.SendPacket(pkt, port); err != nil {
		return err
	}
	if delay > 0 {
		collectPackets(packetCh, delay, flowKey)
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

func Start(netCap *netcap.NetCap, probes []ServiceConfig, srcPort layers.TCPPort, targets []Target, packetCh <-chan netcap.PacketInfo, srcMAC *net.HardwareAddr, dstMAC *net.HardwareAddr) {
	var err error
	defer wrapError(&err, "CenDPI")
skipProbe:
	for _, probe := range probes {
		//loop now all the domains to test for this vp
		var dstIP net.IP
		var dstPort layers.TCPPort
		for _, target := range targets {
			probe.Domain = target.TestDomain
			dstIP = net.ParseIP(target.TargetIP)
			dstPort = layers.TCPPort(target.TargetPort)
			probe.Domain = target.TestDomain
			probe.Protocol = target.Protocol

			probe.IsControl = target.IsControl
			probe.SrcPort, probe.DstPort = srcPort, dstPort
			probe.DstIP = dstIP
			probe.Label = target.Label

			flowKey := NormalizeFlowKey(probe.SrcIP, srcPort, dstIP, dstPort)
			for n, p := range probe.Packets {
				if n == 0 {
					initSeq := rand.Uint32()
					tcpStates[flowKey] = tcpState{
						SeqNum:     initSeq,
						AckNum:     0,
						InitialSeq: initSeq,
					}
				}
				p.IP.SrcIP, p.IP.DstIP = probe.SrcIP, dstIP
				if p.TCP != nil {

				}
				hasTCP := false
				if p.TCP != nil {
					hasTCP = true
					p.TCP.SrcPort, p.TCP.DstPort = probe.SrcPort, probe.DstPort
				}
				if probe.Message.TLS != nil {
					probe.Message.TLS.ClientHelloConfig.SNI = probe.Domain
				}

				if hasTCP {
					state := tcpStates[flowKey]

					// Derive the actual Seq/Ack from state and relative offsets
					p.TCP.Seq, p.TCP.Ack = state.SeqNum, state.AckNum
					curIsq := state.InitialSeq

					if p.TCP.SeqRelativeToExpected != 0 {
						p.TCP.Seq = uint32(int64(p.TCP.Seq) + int64(p.TCP.SeqRelativeToExpected))
					}
					if p.TCP.AckRelativeToExpected != 0 {
						p.TCP.Ack = uint32(int64(p.TCP.Ack) + int64(p.TCP.AckRelativeToExpected))
					}
					if p.TCP.SeqRelativeToInitial != 0 {
						p.TCP.Seq = uint32(int64(curIsq) + int64(p.TCP.SeqRelativeToInitial))
					}
					// If we have a "MessageLength" in the config, it means we want to slice
					// from the overall application message.
					if p.TCP.MessageLength != 0 {
						// We expect no raw data in p.TCP.Data if we plan to slice the message.
						if len(p.TCP.Data) != 0 {
							continue skipProbe
						}
						if probe.Message == nil {
							log.Printf("packet %d: asked for message slicing, but config.Message is nil\n", n)
							continue skipProbe
						}
						// Build the application message if not done yet
						if len(probe.Message.PayloadBytes) == 0 {
							rawPayloadBytes, rawReversedPayloadBytes, buildErr := buildMessages(probe)
							if buildErr != nil {
								log.Printf("packet %d: buildMessages error: %v\n", n, buildErr)
								continue skipProbe
							}
							probe.Message.PayloadBytes = rawPayloadBytes
							probe.Message.ReversePayloadBytes = rawReversedPayloadBytes
						}

						messageOffsetBytes := p.TCP.MessageOffset // in bytes
						var length int
						if p.TCP.MessageLength == -1 {
							// take entire remainder
							length = len(probe.Message.PayloadBytes) - messageOffsetBytes
							if length < 1 {
								log.Printf("packet %d: invalid segment offset (beyond message size)\n", n)
							}
						} else {
							length = p.TCP.MessageLength
						}
						endPos := messageOffsetBytes + length
						if endPos > len(probe.Message.PayloadBytes) {
							log.Printf("packet %d: segment out of range\n", n)
						}
						if p.TCP.ReverseDomain {
							p.TCP.Data = probe.Message.ReversePayloadBytes[messageOffsetBytes:endPos]
						} else {
							p.TCP.Data = probe.Message.PayloadBytes[messageOffsetBytes:endPos]
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
					}

					if err := sendAndCollect(netCap, packetCh, packet, time.Duration(p.Delay*float64(time.Second)), flowKey, uint16(srcPort)); err != nil {
						log.Printf("packet %d: sendAndCollect error: %v\n", n, err)
					}

				} else {
					// --------------------------------------------------
					// Case 2: No TCP layer => IP fragmentation path?
					// --------------------------------------------------
					if p.IP.MessageLength != 0 {
						if probe.Message == nil {
							log.Printf("packet %d: IP fragmentation requested but config.Message is nil\n", n)
							continue skipProbe
						}

						// If we haven't built the application message yet, do so:
						if len(probe.Message.PayloadBytes) == 0 {
							rawPayloadBytes, rawReversedPayloadBytes, buildErr := buildMessages(probe)
							if buildErr != nil {
								log.Printf("packet %d: buildMessages error: %v\n", n, buildErr)
								continue skipProbe
							}
							state, ok := tcpStates[flowKey]
							if !ok {
								log.Printf("packet %d: no TCP state found for IP fragmentation\n", n)
								continue skipProbe
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
						}
						var length int
						if p.IP.MessageLength == -1 {
							length = len(probe.Message.PayloadBytes) - messageOffsetBytes
							if length < 1 {
								log.Printf("packet %d: invalid fragment offset (beyond message size)\n", n)
							}
						} else {
							length = p.IP.MessageLength
						}

						endPos := messageOffsetBytes + length
						if endPos > len(probe.Message.PayloadBytes) {
							log.Printf("packet %d: fragment out of range\n", n)
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
						}

						if err := sendAndCollect(netCap, packetCh, packet, time.Duration(p.Delay*float64(time.Second)), flowKey, uint16(srcPort)); err != nil {
							log.Printf("packet %d: sendAndCollect error: %v\n", n, err)
						}

					} else {
						// No TCP and no fragmentation => nothing to send
						log.Printf("packet %d: No TCP layer specified and no IP fragmentation => nothing to send\n", n)
						continue skipProbe
					}
				}
			}
		}
	}
}
