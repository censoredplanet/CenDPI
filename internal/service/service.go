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
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type ServiceConfig struct {
	Iface    string
	PcapPath string
	BPF      string
	Delay    int
	Packets  []ServicePacket
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
		if n == 0 {
			p.TCP.Seq = rand.Uint32()
			tcpStates[p.IP.DstIP.String()] = tcpState{
				SeqNum: p.TCP.Seq,
				AckNum: 0,
			}
		} else {
			state := tcpStates[p.IP.DstIP.String()]
			if !p.TCP.PSH && p.TCP.ACK || p.TCP.FIN && p.TCP.ACK {
				p.TCP.Seq, p.TCP.Ack = state.SeqNum, state.AckNum+1
			} else {
				p.TCP.Seq, p.TCP.Ack = state.SeqNum, state.AckNum
			}
			tcpStates[p.IP.DstIP.String()] = tcpState{
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
		err = netCap.SendPacket(packet)
		if err != nil {
			return err
		}
		collectPackets(netCap, packetChan, time.Duration(config.Delay)*time.Second, p.IP.DstIP.String())
	}
	return nil
}
