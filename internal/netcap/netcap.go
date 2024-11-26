package netcap

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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
	Handle     *pcap.Handle
	pcapWriter *pcapgo.Writer
	pcapFile   *os.File
	Config     NetCapConfig
}

func New(config NetCapConfig) (*NetCap, error) {
	handle, err := pcap.OpenLive(
		config.Interface.Name,
		config.SnapLen,
		true,
		config.Timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %v", err)
	}

	if config.BPF != "" {
		if err := handle.SetBPFFilter(config.BPF); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	f, err := os.Create(config.PCAPFile)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to create pcap file: %v", err)
	}

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(uint32(config.SnapLen), handle.LinkType())
	if err != nil {
		f.Close()
		handle.Close()
		return nil, fmt.Errorf("failed to write pcap header: %v", err)
	}

	return &NetCap{
		Handle:     handle,
		Config:     config,
		pcapWriter: w,
		pcapFile:   f,
	}, nil
}

func (n *NetCap) ChangeFilter(filter string) {
	if err := n.Handle.SetBPFFilter(filter); err != nil {
		log.Println("failed to set filter")
		n.Handle.Close()
	}
}

func (n *NetCap) Close() error {
	if n.Handle != nil {
		n.Handle.Close()
	}
	if n.pcapFile != nil {
		n.pcapFile.Close()
	}
	return nil
}

func (n *NetCap) WritePacketToPCAP(packet []byte, captureTime time.Time) error {
	err := n.pcapWriter.WritePacket(gopacket.CaptureInfo{
		Timestamp:     captureTime,
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet)
	if err != nil {
		return fmt.Errorf("failed to write packet to pcap: %v", err)
	}
	return nil
}

func (n *NetCap) SendPacket(packet []byte) error {
	// Write packet to pcap file before sending
	if err := n.WritePacketToPCAP(packet, time.Now()); err != nil {
		return err
	}

	// For debugging only
	// p := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)

	//
	// if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	// 	tcp, _ := tcpLayer.(*layers.TCP)
	// 	log.Printf("About to send packet - Seq: %d, Ack: %d, SYN: %t, ACK: %t",
	// 		tcp.Seq, tcp.Ack, tcp.SYN, tcp.ACK)
	// }

	if err := n.Handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}
	return nil
}

func (n *NetCap) ReceivePacket(ctx context.Context) ([]byte, uint32, uint32, error) {
	packetSource := gopacket.NewPacketSource(n.Handle, n.Handle.LinkType())
	//packetSource.NoCopy = true // Optimize memory usage if no packet access is needed

	for {
		select {
		case <-ctx.Done():
			return nil, 0, 0, ctx.Err()

		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				if err == io.EOF || err == pcap.NextErrorTimeoutExpired {
					continue
				}
				log.Println("Error reading packet:", err)
				continue
			}

			err = n.WritePacketToPCAP(packet.Data(), packet.Metadata().Timestamp)
			if err != nil {
				return nil, 0, 0, fmt.Errorf("error writing to pcap: %v", err)
			}

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if ok {

					if tcp.SYN && tcp.ACK {
						log.Printf("SYN-ACK received - Sequence: %d, Acknowledgment: %d",
							tcp.Seq, tcp.Ack)
						return packet.Data(), tcp.Seq, tcp.Ack, nil
					}
					if tcp.PSH && tcp.ACK {
						log.Printf("PSH-ACK received - Sequence: %d, Acknowledgment: %d",
							tcp.Seq, tcp.Ack)
						return packet.Data(), tcp.Seq, tcp.Ack, nil
					}
					if tcp.FIN && tcp.ACK {
						log.Printf("ACK received - Sequence: %d, Acknowledgment: %d",
							tcp.Seq, tcp.Ack)
						return packet.Data(), tcp.Seq + uint32(len(tcp.Payload)), tcp.Ack, nil
					}
					if tcp.ACK {
						log.Printf("ACK received - Sequence: %d, Acknowledgment: %d",
							tcp.Seq, tcp.Ack)
						return packet.Data(), tcp.Seq + uint32(len(tcp.Payload)), tcp.Ack, nil
					}
				}
			}
		}
	}
}

type PacketInfo struct {
	Data     gopacket.Packet
	Metadata *gopacket.PacketMetadata
	Seq      uint32
	Ack      uint32
}

func (n *NetCap) StartPacketReceiver(ctx context.Context) chan PacketInfo {
	packetChan := make(chan PacketInfo)

	go func() {
		defer close(packetChan)
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

				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, ok := tcpLayer.(*layers.TCP)
					if ok {
						packetChan <- PacketInfo{
							Data:     packet,
							Metadata: packet.Metadata(),
							Seq:      tcp.Ack,
							Ack:      tcp.Seq,
						}
					}
				}
			}
		}
	}()

	return packetChan
}

func BuildTCPResponseFilter(srcIP, dstIP net.IP, srcPort, dstPort int) string {
	return fmt.Sprintf(
		"tcp and src host %s and src port %d and dst host %s and dst port %d",
		dstIP.String(), dstPort, srcIP.String(), srcPort,
	)
}
