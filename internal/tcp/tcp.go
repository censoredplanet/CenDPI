package tcp

import (
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/censoredplanet/CenDPI/internal/network"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/ipv4"
)

type CenTCP struct {
	Handle       *pcap.Handle
	Iface        string
	PcapPath     string
	SrcIp        net.IP
	DstIp        net.IP
	SrcPort      layers.TCPPort
	DstPort      layers.TCPPort
	SeqNum       uint32
	ServerSeqNum uint32
}

// InitiateHandshake performs the TCP three-way handshake.
func (ct *CenTCP) InitiateHandshake(pcapPath string) error {
	handle, err := pcap.OpenLive(ct.Iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap.OpenLive: %v", err)
	}
	defer handle.Close()

	w, fileHandle := network.SetupPcapFile(pcapPath)
	defer fileHandle.Close()

	conn, err := net.ListenPacket("ip4:tcp", ct.SrcIp.String())
	if err != nil {
		return fmt.Errorf("net.ListenPacket: %v", err)
	}
	defer conn.Close()

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		return fmt.Errorf("ipv4.NewRawConn: %v", err)
	}

	ipHeader, payload, err := ct.buildSYNPacketAndIPHeader()
	if err != nil {
		return fmt.Errorf("ct.buildSYNPacketAndIPHeader: %v", err)
	}

	err = network.SendPacket(w, ipHeader, payload, rawConn)
	if err != nil {
		return fmt.Errorf("network.SendPacket: %v", err)
	}

	err = ct.captureSYNACK(handle, w)
	if err != nil {
		return fmt.Errorf("ct.captureSYNACK: %v", err)
	}

	ackIPHeader, ackPayload, err := ct.buildACKPacketAndIPHeader()
	if err != nil {
		return fmt.Errorf("ct.buildACKPacketAndIPHeader: %v", err)
	}
	err = network.SendPacket(w, ackIPHeader, ackPayload, rawConn)
	if err != nil {
		return fmt.Errorf("network.SendPacket: %v", err)
	}

	return nil
}

func (ct *CenTCP) captureSYNACK(handle *pcap.Handle, w *pcapgo.Writer) error {
	filter := fmt.Sprintf("tcp and src host %s and src port %d and dst host %s and dst port %d",
		ct.DstIp.String(), ct.DstPort, ct.SrcIp.String(), ct.SrcPort)
	err := handle.SetBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case packet := <-packetSource.Packets():
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SYN && tcp.ACK && tcp.Ack == ct.SeqNum+1 {
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer == nil {
						return fmt.Errorf("no IPv4 layer found")
					}
					ip, _ := ipLayer.(*layers.IPv4)
					buffer := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: false,
					}
					if err := gopacket.SerializeLayers(buffer, opts, ip, tcp); err != nil {
						return fmt.Errorf("error serializing layers: %v", err)
					}
					serializedPacket := buffer.Bytes()

					err := w.WritePacket(gopacket.CaptureInfo{
						Timestamp:      packet.Metadata().Timestamp,
						CaptureLength:  len(serializedPacket),
						Length:         len(serializedPacket),
						InterfaceIndex: 0,
					}, serializedPacket)
					if err != nil {
						return fmt.Errorf("error writing received SYN-ACK packet to pcap file: %v", err)
					}
					ct.ServerSeqNum = tcp.Seq
					return nil
				}
			}
		case <-time.After(5 * time.Second):
			return fmt.Errorf("timeout waiting for SYN-ACK")
		}
	}
}

func (ct *CenTCP) buildSYNPacketAndIPHeader() (*ipv4.Header, []byte, error) {
	ct.SeqNum = rand.Uint32()
	tcpLayer := &layers.TCP{
		SrcPort: ct.SrcPort,
		DstPort: ct.DstPort,
		Seq:     ct.SeqNum,
		SYN:     true,
		Window:  64240,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xb4}, // MSS 1460
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x07}, // Window scale shift count of 7
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
		},
	}

	err := tcpLayer.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP:    ct.SrcIp,
		DstIP:    ct.DstIp,
		Protocol: layers.IPProtocolTCP,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error setting network layer for checksum: %v", err)
	}

	tcpBuffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = tcpLayer.SerializeTo(tcpBuffer, options)
	if err != nil {
		return nil, nil, fmt.Errorf("error serializing TCP layer: %v", err)
	}

	tcpPayload := tcpBuffer.Bytes()

	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TOS:      0,
		TotalLen: ipv4.HeaderLen + len(tcpPayload),
		ID:       int(rand.Uint32() & 0xffff), // IP ID field is 16 bits
		FragOff:  0,
		TTL:      64,
		Protocol: int(layers.IPProtocolTCP),
		Src:      ct.SrcIp,
		Dst:      ct.DstIp,
	}

	return ipHeader, tcpPayload, nil
}

func (ct *CenTCP) buildACKPacketAndIPHeader() (*ipv4.Header, []byte, error) {
	tcpLayer := &layers.TCP{
		SrcPort: ct.SrcPort,
		DstPort: ct.DstPort,
		Seq:     ct.SeqNum + 1,
		Ack:     ct.ServerSeqNum + 1,
		ACK:     true,
		Window:  14600,
	}

	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TOS:      0,
		TotalLen: 0,
		ID:       int(rand.Uint32()),
		FragOff:  0,
		TTL:      64,
		Protocol: int(layers.IPProtocolTCP),
		Src:      ct.SrcIp,
		Dst:      ct.DstIp,
	}

	err := tcpLayer.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP:    ct.SrcIp,
		DstIP:    ct.DstIp,
		Protocol: layers.IPProtocolTCP,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error setting network layer for checksum: %v", err)
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = tcpLayer.SerializeTo(buffer, options)
	if err != nil {
		return nil, nil, fmt.Errorf("error serializing TCP layer: %v", err)
	}

	payload := buffer.Bytes()
	ipHeader.TotalLen = ipv4.HeaderLen + len(payload)

	return ipHeader, payload, nil
}
