package service

import (
    "context"
    "fmt"
    "log"
    "math/rand/v2"
    "time"
	"net"
	"bytes"
    "github.com/censoredplanet/CenDPI/internal/assembler"
    "github.com/censoredplanet/CenDPI/internal/ethernet"
    "github.com/censoredplanet/CenDPI/internal/ip"
    "github.com/censoredplanet/CenDPI/internal/netcap"
    "github.com/censoredplanet/CenDPI/internal/netutil"
    "github.com/censoredplanet/CenDPI/internal/tcp"
    "github.com/censoredplanet/CenDPI/internal/http"
    "github.com/censoredplanet/CenDPI/internal/tls"
    "github.com/gopacket/gopacket/layers"
    "github.com/gopacket/gopacket/pcap"
)

type ServiceConfig struct {
    Iface    string
    PcapPath string
    BPF      string
    SrcMAC   string
    DstMAC   string
	SrcIP	 net.IP
	DstIP	 net.IP
	SrcPort  layers.TCPPort
	DstPort  layers.TCPPort
    Packets  []ServicePacket
    Message  *ServiceMessage
    Domain   string
	IsControl bool
    Protocol string
	Label	 string
}

type ServiceMessage struct {
    HTTP     	  		*http.HTTPConfig
    TLS      	  		*tls.TLSConfig
	PayloadBytes     	[]byte // built with the original domain
    ReversePayloadBytes []byte // built with the reversed domain
}

type ServicePacket struct {
    Ethernet ethernet.EthernetConfig
    IP       ip.IPConfig
    TCP      tcp.TCPConfig
    Delay    int           // Per-packet delay in seconds
}

type FlowKey struct {
    IP1   string
    Port1 layers.TCPPort
    IP2   string
    Port2 layers.TCPPort
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

type tcpState struct {
    SeqNum     		uint32
    AckNum     		uint32
    InitialSeq 		uint32
}

var tcpStates = make(map[FlowKey]tcpState)

func wrapError(err *error, str string, args ...any) {
    if *err != nil {
        *err = fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), *err)
        log.Println(*err)
    }
}

func collectPackets(netCap *netcap.NetCap, packetChan chan netcap.PacketInfo, duration time.Duration, flowKey FlowKey) []netcap.PacketInfo {
    var packets []netcap.PacketInfo
    timer := time.NewTimer(duration)
    defer timer.Stop()

    for {
        select {
        case packet := <-packetChan:
            err := netCap.WritePacketToPCAP(packet.Data.Data(), packet.Metadata.Timestamp)
            if err != nil {
                log.Printf("error writing to pcap: %v", err)
            }

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
                    SeqNum:       states.SeqNum,
                    AckNum:       states.AckNum,
                    InitialSeq:   states.InitialSeq,
                }
            }

        case <-timer.C:
            return packets
        }
    }
}

func sendAndCollect(netCap *netcap.NetCap, packetChan chan netcap.PacketInfo, pkt []byte, delay time.Duration, flowKey FlowKey) error {
    if err := netCap.SendPacket(pkt); err != nil {
        return err
    }
    if delay > 0 {
        collectPackets(netCap, packetChan, delay, flowKey)
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
            return nil, fmt.Errorf("error building HTTP request: %v", err)
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
            return nil, fmt.Errorf("error building TLS handshake: %v", err)
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
	//fmt.Printf("Control Domain: %s\n", controlDomain)

   	reverseBytes, err := buildSingleMessage(cfg, reverseDomain)
    if err != nil {
        return nil, nil, fmt.Errorf("building reverse domain message: %w", err)
    }

    return payloadBytes, reverseBytes, nil
}

func Start(config ServiceConfig) (err error) {
    defer wrapError(&err, "CenDPI")

    iface, err := netutil.GetInterfaceMAC(config.Iface)
    if err != nil {
        return err
    }

    netCapConfig := netcap.NetCapConfig{
        Interface:      iface,
        SnapLen:        65536,
        Timeout:        pcap.BlockForever,
        ReadBufferSize: 65536,
        PCAPFile:       config.PcapPath,
        BPF:            config.BPF,
    }

    netCap, err := netcap.New(netCapConfig)
    if err != nil {
        return err
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    packetChan := netCap.StartPacketReceiver(ctx)

	flowKey := NormalizeFlowKey(config.SrcIP, config.SrcPort, config.DstIP, config.DstPort)
    for n, p := range config.Packets {
		if n == 0 {
			initSeq := rand.Uint32()
			tcpStates[flowKey] = tcpState{
				SeqNum:       	initSeq,
				AckNum:       	0,
				InitialSeq:   	initSeq,
			}
		}

        hasTCP := (p.TCP.SrcPort != 0 || p.TCP.DstPort != 0)

        // --------------------------------------------------
        // Case 1: We have a TCP layer in the config
        // --------------------------------------------------
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
                    return fmt.Errorf("Packet %d: cannot specify both p.TCP.Data and p.TCP.MessageLength", n)
                }
                if config.Message == nil {
                    return fmt.Errorf("Packet %d: asked for message slicing, but config.Message is nil", n)
                }
                // Build the application message if not done yet
                if len(config.Message.PayloadBytes) == 0 {
                    rawPayloadBytes, rawReversedPayloadBytes, buildErr := buildMessages(config)
                    if buildErr != nil {
                        return fmt.Errorf("Packet %d: buildMessages error: %v", n, buildErr)
                    }
                    config.Message.PayloadBytes = rawPayloadBytes
					config.Message.ReversePayloadBytes = rawReversedPayloadBytes
                }

                messageOffsetBytes := p.TCP.MessageOffset // in bytes
                var length int
                if p.TCP.MessageLength == -1 {
                    // take entire remainder
                    length = len(config.Message.PayloadBytes) - messageOffsetBytes
                    if length < 1 {
                        return fmt.Errorf("Packet %d: invalid segment offset (beyond message size)", n)
                    }
                } else {
                    length = p.TCP.MessageLength
                }
                endPos := messageOffsetBytes + length
                if endPos > len(config.Message.PayloadBytes) {
                    return fmt.Errorf("Packet %d: segment out of range", n)
                }
				if p.TCP.ReverseDomain{
					p.TCP.Data = config.Message.ReversePayloadBytes[messageOffsetBytes:endPos]
				} else {
					p.TCP.Data = config.Message.PayloadBytes[messageOffsetBytes:endPos]
				}
            }

            // Build the Ethernet/IP/TCP layers
            packet, err := assembler.New().
                AddLayer(ethernet.New(&p.Ethernet)).
                AddLayer(ip.New(&p.IP)).
                AddLayer(tcp.New(&p.TCP)).
                Build(p.TCP.CorruptChecksum)
            if err != nil {
                return fmt.Errorf("Packet %d: Assembler Build error: %v", n, err)
            }

            if err := sendAndCollect(netCap, packetChan, packet, time.Duration(p.Delay)*time.Second, flowKey); err != nil {
                return fmt.Errorf("Packet %d: sendAndCollect error: %v", n, err)
            }

        } else {
            // --------------------------------------------------
            // Case 2: No TCP layer => IP fragmentation path?
            // --------------------------------------------------
            if p.IP.MessageLength != 0 {
                if config.Message == nil {
                    return fmt.Errorf("Packet %d: IP fragmentation requested but config.Message is nil", n)
                }
                // If we haven't built the application message yet, do so:
                if len(config.Message.PayloadBytes) == 0 {
                    rawPayloadBytes, rawReversedPayloadBytes, buildErr := buildMessages(config)
                    if buildErr != nil {
                        return fmt.Errorf("Packet %d: buildMessages error: %v", n, buildErr)
                    }
                    state, ok := tcpStates[flowKey]
                    if !ok {
                        return fmt.Errorf("Packet %d: no TCP state found for IP fragmentation", n)
                    }
                    tcpWrap := &tcp.TCPConfig{
                        SrcPort: config.SrcPort,
                        DstPort: config.DstPort,
                        Seq:     state.SeqNum,
                        Ack:     state.AckNum,
                        PSH:     true,
                        ACK:     true,
                        Window:  2056,
                        Data:    rawPayloadBytes,
                    }
					tcpWrapReversedPayload := &tcp.TCPConfig{
						SrcPort: config.SrcPort,
                        DstPort: config.DstPort,
						Seq:     state.SeqNum,
						Ack:     state.AckNum,
						PSH:     true,
						ACK:     true,
						Window:  2056,
						Data:    rawReversedPayloadBytes,
					}
					rawTCP, wrapErr := tcp.BuildAndSerialize(tcpWrap, p.IP.SrcIP, p.IP.DstIP)
					if wrapErr != nil {
						return fmt.Errorf("Packet %d: building TCP for IP fragmentation error: %v", n, wrapErr)
					}
					rawTCPReversed, wrapErr := tcp.BuildAndSerialize(tcpWrapReversedPayload, p.IP.SrcIP, p.IP.DstIP)
					if wrapErr != nil {
						return fmt.Errorf("Packet %d: building TCP for IP fragmentation error: %v", n, wrapErr)
					}
					config.Message.PayloadBytes = rawTCP
					config.Message.ReversePayloadBytes = rawTCPReversed
                }

                messageOffsetBytes := p.IP.MessageOffset
				if messageOffsetBytes % 8 != 0 {
					return fmt.Errorf("Packet %d: message offset for IP fragmentation must be a multiple of 8 bytes", n)
				}
                var length int
                if p.IP.MessageLength == -1 {
                    length = len(config.Message.PayloadBytes) - messageOffsetBytes
                    if length < 1 {
                        return fmt.Errorf("Packet %d: invalid fragment offset (beyond message size)", n)
                    }
                } else {
                    length = p.IP.MessageLength
                }

                endPos := messageOffsetBytes + length
                if endPos > len(config.Message.PayloadBytes) {
                    return fmt.Errorf("Packet %d: fragment out of range", n)
                }
				fragmentPayload := config.Message.PayloadBytes[messageOffsetBytes:endPos]
				if p.IP.ReverseDomain{
					fragmentPayload = config.Message.ReversePayloadBytes[messageOffsetBytes:endPos]
				}

                // Build Ethernet/IP (with the fragment payload)
                packet, err := assembler.New().
                    AddLayer(ethernet.New(&p.Ethernet)).
                    AddLayer(ip.NewWithPayload(&p.IP, fragmentPayload)).
                    Build(false)
                if err != nil {
                    return fmt.Errorf("Packet %d: Assembler Build error: %v", n, err)
                }

                if err := sendAndCollect(netCap, packetChan, packet, time.Duration(p.Delay)*time.Second, flowKey); err != nil {
                    return fmt.Errorf("Packet %d: sendAndCollect error: %v", n, err)
                }

            } else {
                // No TCP and no fragmentation => nothing to send
                return fmt.Errorf("Packet %d: No TCP layer specified and no IP fragmentation => nothing to send", n)
            }
        }
    }
    return nil
}

