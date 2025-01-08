package netcap

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

type NetCapConfig struct {
	Interface      *net.Interface
	SnapLen        int32
	Timeout        time.Duration
	BPF            string
	ReadBufferSize int
	PCAPFile       string
}

type NetCap struct {
	Handle      *pcap.Handle
	pcapWriters map[uint16]*pcapgo.Writer
	pcapFiles   []*os.File
	Config      NetCapConfig
}

func New(config NetCapConfig) (*NetCap, error) {
	handle, err := pcap.OpenLive(
		config.Interface.Name,
		config.SnapLen,
		true,
		config.Timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	if config.BPF != "" {
		if err := handle.SetBPFFilter(config.BPF); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	return &NetCap{
		Handle:      handle,
		Config:      config,
		pcapWriters: make(map[uint16]*pcapgo.Writer),
		pcapFiles:   []*os.File{},
	}, nil
}

func (n *NetCap) ChangeFilter(filter string) {
	if err := n.Handle.SetBPFFilter(filter); err != nil {
		log.Println("failed to set filter")
		n.Handle.Close()
	}
}

func (n *NetCap) WritePacketToPCAP(writer *pcapgo.Writer, packet []byte, captureTime time.Time) error {
	err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     captureTime,
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet)
	if err != nil {
		return fmt.Errorf("failed to write packet to pcap: %w", err)
	}
	return nil
}

func (n *NetCap) SendPacket(packet []byte, port uint16) error {
	// Write packet to pcap file before sending
	if err := n.WritePacketToPCAP(n.pcapWriters[port], packet, time.Now()); err != nil {
		return err
	}
	if err := n.Handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}
	return nil
}

type PacketInfo struct {
	Data     gopacket.Packet
	Metadata *gopacket.PacketMetadata
	Seq      uint32
	Ack      uint32
	Port     uint16
}

func (n *NetCap) StartPacketReceiver(ctx context.Context, chMap map[uint16]chan PacketInfo, saveCh chan<- PacketInfo) {
	go func() {
		packetSource := gopacket.NewPacketSource(n.Handle, n.Handle.LinkType())
		for {
			select {
			case <-ctx.Done():
				return

			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					if err == io.EOF || err == pcap.NextErrorTimeoutExpired {
						continue
					}
					log.Println("Error reading packet:", err)
					continue
				}

				tcp := packet.TransportLayer().(*layers.TCP)
				port := uint16(tcp.DstPort)

				packetInfo := PacketInfo{
					Data:     packet,
					Metadata: packet.Metadata(),
					Seq:      tcp.Seq,
					Ack:      tcp.Ack,
					Port:     port,
				}
				if ch, ok := chMap[port]; ok {
					select {
					case ch <- packetInfo:
					default:
						log.Printf("Channel for port %d is full", port)
					}
				}
				saveCh <- packetInfo
			}
		}
	}()
}

func BuildTCPResponseFilter(srcIP, dstIP net.IP, srcPort, dstPort int) string {
	return fmt.Sprintf(
		"tcp and src host %s and src port %d and dst host %s and dst port %d",
		dstIP.String(), dstPort, srcIP.String(), srcPort,
	)
}

func (n *NetCap) SetupPCAPWriters(portToIP map[uint16]string, path string) error {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	for port, ip := range portToIP {
		fileName := filepath.Join(path, fmt.Sprintf("%s.pcap", strings.ReplaceAll(ip, ".", "-")))
		f, err := os.Create(fileName)
		if err != nil {
			return err
		}
		w := pcapgo.NewWriter(f)
		err = w.WriteFileHeader(uint32(n.Config.SnapLen), n.Handle.LinkType())
		if err != nil {
			f.Close()
			return fmt.Errorf("failed to write pcap header for %s: %w", fileName, err)
		}
		n.pcapWriters[port] = w
		n.pcapFiles = append(n.pcapFiles, f)
	}

	return nil

}

func (n *NetCap) SavePackets(ctx context.Context, ch <-chan PacketInfo) {
	go func() {
		for {
			select {
			case packet := <-ch:
				writer := n.pcapWriters[packet.Port]
				n.WritePacketToPCAP(writer, packet.Data.Data(), packet.Metadata.Timestamp)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (n *NetCap) Close() {
	for _, f := range n.pcapFiles {
		f.Close()
	}
	n.Handle.Close()
}
