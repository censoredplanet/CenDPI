package netcap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/censoredplanet/CenDPI/internal/http"
	"github.com/censoredplanet/CenDPI/internal/ip"
	"github.com/censoredplanet/CenDPI/internal/tcp"
	"github.com/censoredplanet/CenDPI/internal/tls"

	// cenTls "github.com/censoredplanet/CenDPI/internal/tls"
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
	SavePcap       bool
	ResultCh       chan Result
}

type NetCap struct {
	Handle      *pcap.Handle
	PcapWriters map[FlowKey]*pcapgo.Writer
	pcapFiles   []*os.File
	Config      NetCapConfig
}

type NetCapPcapInfo struct {
	TargetIP   net.IP
	TargetPort layers.TCPPort
	IsControl  bool
	ProbeName  string
}

type FlowKey struct {
	IP1   string
	Port1 layers.TCPPort
	IP2   string
	Port2 layers.TCPPort
}

type PacketInfo struct {
	Data     gopacket.Packet
	Metadata *gopacket.PacketMetadata
	Seq      uint32
	Ack      uint32
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  layers.TCPPort
	DstPort  layers.TCPPort
}

// All the meta data belonging to the target, basically all in the Service Config (ips, port, domain, control, label, Sequence of packets received, for each packet received - all the packets ip, tcp & tcp payload. Try parsing http and tls as well if possible
// 	http - response code
// 	Tls - content type or record type, we basically want to know if the package is a server hello

type Result struct {
	Probe         string           `json:"Probe"`
	Domain        string           `json:"Domain"`
	Control       bool             `json:"Control"`
	Packets       []ResultPacket   `json:"Packets"`
	HTTPResponses []http.Response  `json:"HTTPResponses"`
	ServerHello   *tls.ServerHello `json:"ServerHello"`
}

type ResultPacket struct {
	SequenceNumber int           `json:"SequenceNum"`
	IP             ip.IPConfig   `json:"IP"`
	TCP            tcp.TCPConfig `json:"TCP"`
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
		PcapWriters: make(map[FlowKey]*pcapgo.Writer),
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

func (n *NetCap) SendPacket(packet []byte, flowKey FlowKey) error {
	if n.Config.SavePcap {
		if _, ok := n.PcapWriters[flowKey]; !ok {
			log.Fatalf("FlowKey %v does not exist in the map", flowKey)
		}
		// Write packet to pcap file before sending
		if err := n.WritePacketToPCAP(n.PcapWriters[flowKey], packet, time.Now()); err != nil {
			return err
		}
	}
	if err := n.Handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}
	return nil
}

func (n *NetCap) StartPacketReceiver(ctx context.Context, chMap map[FlowKey]chan PacketInfo) {
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

				// Make sure this packet actually has a TCP layer
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					continue
				}
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					continue
				}

				netLayer := packet.NetworkLayer()
				if netLayer == nil {
					continue
				}

				var srcIP, dstIP net.IP
				switch nl := netLayer.(type) {
				case *layers.IPv4:
					srcIP = nl.SrcIP
					dstIP = nl.DstIP
				default:
					// Maybe IPv6; skip
					continue
				}

				packetInfo := PacketInfo{
					Data:     packet,
					Metadata: packet.Metadata(),
					Seq:      tcp.Seq,
					Ack:      tcp.Ack,
					SrcIP:    srcIP,
					DstIP:    dstIP,
					SrcPort:  tcp.SrcPort,
					DstPort:  tcp.DstPort,
				}
				flowkey := NormalizeFlowKey(srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
				if ch, ok := chMap[flowkey]; ok {
					select {
					case ch <- packetInfo:
					default:
						log.Println("Channel for the flow SrcIP:", srcIP, "DstIP:", dstIP, "SrcPort:", tcp.SrcPort, "DstPort:", tcp.DstPort, "is full")
					}
				}
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

func (n *NetCap) SetupPCAPWriters(flowKeyToPcap map[FlowKey]NetCapPcapInfo, path string) error {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	// for each flowkey, create a pcap file. The path should be [path passed in]/[dstIP]:[dstPort]/ProbeName_[test/control (depending on the value of NetCapPcapInfo.IsControl)].pcap
	for flowKey, pcapInfo := range flowKeyToPcap {

		// Subdirectory named "dstIP:dstPort"
		subdir := fmt.Sprintf("%s:%d", pcapInfo.TargetIP.String(), pcapInfo.TargetPort)
		subdirFullPath := filepath.Join(path, subdir)

		if err := os.MkdirAll(subdirFullPath, 0755); err != nil {
			return fmt.Errorf("failed to create subdir %s: %w", subdirFullPath, err)
		}

		// filename: e.g. "0_0_standard_request_test.pcap" or "0_0_standard_request_control.pcap"
		testOrControl := "control"
		if !pcapInfo.IsControl {
			testOrControl = "test"
		}
		fileName := fmt.Sprintf("%s_%s.pcap", pcapInfo.ProbeName, testOrControl)
		fullFilePath := filepath.Join(subdirFullPath, fileName)

		// Create the file
		f, err := os.Create(fullFilePath)
		if err != nil {
			return fmt.Errorf("failed to create pcap file %s: %w", fullFilePath, err)
		}

		w := pcapgo.NewWriter(f)
		err = w.WriteFileHeader(uint32(n.Config.SnapLen), n.Handle.LinkType())
		if err != nil {
			f.Close()
			return fmt.Errorf("failed to write pcap header for %s: %w", fullFilePath, err)
		}
		n.PcapWriters[flowKey] = w
		n.pcapFiles = append(n.pcapFiles, f)
	}
	return nil
}

func (n *NetCap) ParseResults(packet gopacket.Packet) ResultPacket {
	var result ResultPacket
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		result.IP = ip.ParseIPv4Layer(ip4Layer.(*layers.IPv4))
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		result.TCP = tcp.ParseTCPLayer(tcpLayer.(*layers.TCP))
	}

	return result
}

func (n *NetCap) SaveResults(ctx context.Context, filePath string, pktChan chan Result) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	encoder.SetEscapeHTML(false)

	for {
		select {
		case results := <-pktChan:
			for sequence := range results.Packets {
				results.Packets[sequence].SequenceNumber = sequence + 1
			}
			if err := encoder.Encode(results); err != nil {
				log.Println("Error when writing json results")
			}
		case <-ctx.Done():
			return nil
		}

	}
}

func (n *NetCap) Close() {
	for _, f := range n.pcapFiles {
		f.Close()
	}
	n.Handle.Close()
}
