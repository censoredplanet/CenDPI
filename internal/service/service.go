package service

import (
    "context"
    "fmt"
    "log"
    "math/rand/v2"
    "time"

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
    Packets  []ServicePacket
    Message  *ServiceMessage
    Domain   string
    Protocol string
}

type ServiceMessage struct {
    HTTP     *http.HTTPConfig
    TLS      *tls.TLSConfig
    RawBytes []byte // to be built once from buildMessage
}

type ServicePacket struct {
    Ethernet ethernet.EthernetConfig
    IP       ip.IPConfig
    TCP      tcp.TCPConfig
    Delay    int           // Per-packet delay in seconds
}

type tcpState struct {
    SeqNum     		uint32
    AckNum     		uint32
    InitialSeq 		uint32
    TCPSourcePort 	layers.TCPPort
    TCPDestPort  	layers.TCPPort
}

var tcpStates = make(map[string]tcpState)

func wrapError(err *error, str string, args ...any) {
    if *err != nil {
        *err = fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), *err)
        log.Println(*err)
    }
}

func collectPackets(netCap *netcap.NetCap, packetChan chan netcap.PacketInfo, duration time.Duration, dstIP string) []netcap.PacketInfo {
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
                states := tcpStates[dstIP]
                curIsq := states.InitialSeq

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

                tcpStates[dstIP] = tcpState{
                    SeqNum:       states.SeqNum,
                    AckNum:       states.AckNum,
                    InitialSeq:   curIsq,
                    TCPSourcePort: states.TCPSourcePort,
                    TCPDestPort:   states.TCPDestPort,
                }
            }

        case <-timer.C:
            return packets
        }
    }
}

func sendAndCollect(netCap *netcap.NetCap, packetChan chan netcap.PacketInfo, pkt []byte, delay time.Duration, dstIPStr string) error {
    if err := netCap.SendPacket(pkt); err != nil {
        return err
    }
    if delay > 0 {
        collectPackets(netCap, packetChan, delay, dstIPStr)
    }
    return nil
}

func buildMessage(cfg ServiceConfig) ([]byte, error) {
    if cfg.Message == nil {
        return nil, fmt.Errorf("no Message config present")
    }
    switch cfg.Protocol {
    case "http":
		if cfg.Message.HTTP == nil {
			return nil, fmt.Errorf("HTTP config is nil")
		}
        req, err := http.BuildHTTPRequest(cfg.Message.HTTP)
		if err != nil {
			return nil, fmt.Errorf("http.BuildRequest error: %v", err)
		}
        return []byte(req), nil

    case "https":
		if cfg.Message.TLS == nil {
			return nil, fmt.Errorf("TLS config is nil")
		}
        tlsBytes, err := tls.BuildTLS(cfg.Message.TLS)
		if err != nil {
			return nil, fmt.Errorf("tls.BuildTLS error: %v", err)
		}
		return []byte(tlsBytes), nil

    default:
        return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
    }
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

    for n, p := range config.Packets {
        dstIPStr := p.IP.DstIP.String()
        hasTCP := (p.TCP.SrcPort != 0 || p.TCP.DstPort != 0)

        // --------------------------------------------------
        // Case 1: We have a TCP layer in the config
        // --------------------------------------------------
        if hasTCP {
            // Initialize tcpState if not present
            if _, ok := tcpStates[dstIPStr]; !ok {
                initSeq := rand.Uint32()
                tcpStates[dstIPStr] = tcpState{
                    SeqNum:       	initSeq,
                    AckNum:       	0,
                    InitialSeq:   	initSeq,
                    TCPSourcePort: 	p.TCP.SrcPort,
                    TCPDestPort:   	p.TCP.DstPort,
                }
            }
            state := tcpStates[dstIPStr]

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
                if len(config.Message.RawBytes) == 0 {
                    rawApp, buildErr := buildMessage(config)
                    if buildErr != nil {
                        return fmt.Errorf("Packet %d: buildMessage error: %v", n, buildErr)
                    }
                    config.Message.RawBytes = rawApp
                }

                messageOffsetBytes := p.TCP.MessageOffset //* 8 // 8-byte units
                var length int
                if p.TCP.MessageLength == -1 {
                    // take entire remainder
                    length = len(config.Message.RawBytes) - messageOffsetBytes
                    if length < 1 {
                        return fmt.Errorf("Packet %d: invalid segment offset (beyond message size)", n)
                    }
                } else {
                    length = p.TCP.MessageLength
                }
                endPos := messageOffsetBytes + length
                if endPos > len(config.Message.RawBytes) {
                    return fmt.Errorf("Packet %d: segment out of range", n)
                }
                p.TCP.Data = config.Message.RawBytes[messageOffsetBytes:endPos]
            }

            // Build the Ethernet/IP/TCP layers
            packet, err := assembler.New().
                AddLayer(ethernet.New(&p.Ethernet)).
                AddLayer(ip.New(&p.IP)).
                AddLayer(tcp.New(&p.TCP)).
                Build()
            if err != nil {
                return fmt.Errorf("Packet %d: Assembler Build error: %v", n, err)
            }

            if err := sendAndCollect(netCap, packetChan, packet, time.Duration(p.Delay)*time.Second, dstIPStr); err != nil {
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
                if len(config.Message.RawBytes) == 0 {
                    rawApp, buildErr := buildMessage(config)
                    if buildErr != nil {
                        return fmt.Errorf("Packet %d: buildMessage error: %v", n, buildErr)
                    }
                    state, ok := tcpStates[dstIPStr]
                    if !ok {
                        fmt.Println("No TCP state found for IP fragmentation")
                    }
                    tcpWrap := &tcp.TCPConfig{
                        SrcPort: state.TCPSourcePort,
                        DstPort: state.TCPDestPort,
                        Seq:     state.SeqNum,
                        Ack:     state.AckNum,
                        PSH:     true,
                        ACK:     true,
                        Window:  2056,
                        Data:    rawApp,
                    }
                    rawTCP, wrapErr := tcp.BuildAndSerialize(tcpWrap, p.IP.SrcIP, p.IP.DstIP)
                    if wrapErr != nil {
                        return fmt.Errorf("Packet %d: building TCP for IP fragmentation error: %v", n, wrapErr)
                    }
                    config.Message.RawBytes = rawTCP
                }

                messageOffsetBytes := p.IP.MessageOffset * 8
                var length int
                if p.IP.MessageLength == -1 {
                    length = len(config.Message.RawBytes) - messageOffsetBytes
                    if length < 1 {
                        return fmt.Errorf("Packet %d: invalid fragment offset (beyond message size)", n)
                    }
                } else {
                    length = p.IP.MessageLength
                }

                endPos := messageOffsetBytes + length
                if endPos > len(config.Message.RawBytes) {
                    return fmt.Errorf("Packet %d: fragment out of range", n)
                }
                fragmentPayload := config.Message.RawBytes[messageOffsetBytes:endPos]

                // Build Ethernet/IP (with the fragment payload)
                packet, err := assembler.New().
                    AddLayer(ethernet.New(&p.Ethernet)).
                    AddLayer(ip.NewWithPayload(&p.IP, fragmentPayload)).
                    Build()
                if err != nil {
                    return fmt.Errorf("Packet %d: Assembler Build error: %v", n, err)
                }

                if err := sendAndCollect(netCap, packetChan, packet, time.Duration(p.Delay)*time.Second, dstIPStr); err != nil {
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

