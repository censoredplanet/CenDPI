package service

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"encoding/hex"
	"time"

	"github.com/censoredplanet/CenDPI/internal/assembler"
	"github.com/censoredplanet/CenDPI/internal/ethernet"
	"github.com/censoredplanet/CenDPI/internal/ip"
	"github.com/censoredplanet/CenDPI/internal/netcap"
	"github.com/censoredplanet/CenDPI/internal/netutil"
	"github.com/censoredplanet/CenDPI/internal/tcp"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type ServiceConfig struct {
    Iface    string
    PcapPath string
    BPF      string
    Delay    int
    Packets  []ServicePacket
    Message  *ServiceMessage
}

type ServiceMessage struct {
    DataHex string          // If the message is just raw hex data
    TCP     *tcp.TCPConfig  // If the message is a TCP-based packet
}

type ServicePacket struct {
	Ethernet ethernet.EthernetConfig
	IP       ip.IPConfig
	TCP      tcp.TCPConfig
}

type tcpState struct {
	SeqNum, AckNum uint32
}

func wrapError(err *error, str string, args ...any) {
	if *err != nil {
		*err = fmt.Errorf("%s: %w", fmt.Sprintf(str, args...), *err)
		log.Println(*err)
	}
}

var tcpStates = make(map[string]tcpState)

func collectPackets(netCap *netcap.NetCap, packetChan chan netcap.PacketInfo, duration time.Duration, ip string) []netcap.PacketInfo {
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
				states := tcpStates[ip]
				if states.SeqNum < packet.Seq {
					states.SeqNum = packet.Seq
				}
				if states.AckNum < packet.Ack {
					states.AckNum = packet.Ack
				}

				tcpStates[ip] = tcpState{
					SeqNum: states.SeqNum,
					AckNum: states.AckNum,
				}
			}
		case <-timer.C:
			return packets
		}
	}
}

func sendAndCollect(netCap *netcap.NetCap, packetChan chan netcap.PacketInfo, pkt []byte, delay time.Duration, dstIPStr string) error {
	err := netCap.SendPacket(pkt)
	if err != nil {
		return err
	}
	collectPackets(netCap, packetChan, delay, dstIPStr)
	return nil
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
	delayDuration := time.Duration(config.Delay) * time.Second

	for n, p := range config.Packets {

		dstIPStr := p.IP.DstIP.String()
		hasTCP := (p.TCP.SrcPort != 0 || p.TCP.DstPort != 0)

		if hasTCP {
			if n == 0 {
				p.TCP.Seq = rand.Uint32()
				tcpStates[dstIPStr] = tcpState{
					SeqNum: p.TCP.Seq,
					AckNum: 0,
				}
			} else {
				state := tcpStates[dstIPStr]
				if (!p.TCP.PSH && p.TCP.ACK) || (p.TCP.FIN && p.TCP.ACK) {
					p.TCP.Seq, p.TCP.Ack = state.SeqNum, state.AckNum+1
				} else {
					p.TCP.Seq, p.TCP.Ack = state.SeqNum, state.AckNum
				}
				tcpStates[dstIPStr] = tcpState{
					SeqNum: p.TCP.Seq,
					AckNum: p.TCP.Ack,
				}
			}
			packet, err := assembler.New().
				AddLayer(ethernet.New(&p.Ethernet)).
				AddLayer(ip.New(&p.IP)).
				AddLayer(tcp.New(&p.TCP)).
				Build()
			if err != nil {
				return err
			}

			if err := sendAndCollect(netCap, packetChan, packet, delayDuration, dstIPStr); err != nil {
				return err
			}

		} else {
			// No TCP layer specified in config
			if p.IP.FragmentLength > 0 && config.Message != nil {
				// IP Fragmentation
				if config.Message.DataHex == "" {
					if config.Message.TCP != nil {
						// Construct DataHex from Message.TCP
						state := tcpStates[dstIPStr]
						msgTCP := *config.Message.TCP
						// Assume that the payload of the IP fragmentation always have a push/ack flag
						msgTCP.Seq = state.SeqNum
						msgTCP.Ack = state.AckNum
						tcpBytes, err := tcp.BuildAndSerialize(&msgTCP, p.IP.SrcIP, p.IP.DstIP)
						if err != nil {
							return err
						}
						config.Message.DataHex = hex.EncodeToString(tcpBytes)

					} else {
						return fmt.Errorf("No message data available to fragment")
					}
				}

				msgBytes, err := hex.DecodeString(config.Message.DataHex)
				if err != nil {
					return err
				}

				fragOffsetBytes := p.IP.FragmentOffset * 8 // Frag Offset is in 8-byte units
				endPos := fragOffsetBytes + p.IP.FragmentLength
				if endPos > len(msgBytes) {
					return fmt.Errorf("Fragment out of range")
				}
				fragmentPayload := msgBytes[fragOffsetBytes:endPos]
				packet, err := assembler.New().
					AddLayer(ethernet.New(&p.Ethernet)).
					AddLayer(ip.NewWithPayload(&p.IP, fragmentPayload)).
					Build()
				if err != nil {
					return err
				}

				if err := sendAndCollect(netCap, packetChan, packet, delayDuration, dstIPStr); err != nil {
					return err
				}

			} else {
				// No TCP, no fragmentation
				packet, err := assembler.New().
					AddLayer(ethernet.New(&p.Ethernet)).
					AddLayer(ip.New(&p.IP)).
					Build()
				if err != nil {
					return err
				}
				if err := sendAndCollect(netCap, packetChan, packet, delayDuration, dstIPStr); err != nil {
					return err
				}
			}
		}
	}
	return nil
}