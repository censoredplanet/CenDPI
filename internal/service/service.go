package service

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/censoredplanet/CenDPI/internal/arp"
	"github.com/censoredplanet/CenDPI/internal/assembler"
	"github.com/censoredplanet/CenDPI/internal/ethernet"
	"github.com/censoredplanet/CenDPI/internal/ip"
	"github.com/censoredplanet/CenDPI/internal/netcap"
	"github.com/censoredplanet/CenDPI/internal/netutil"
	"github.com/censoredplanet/CenDPI/internal/tcp"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const (
	TCPMode = "TCP"
)

type ModeConfig struct {
	IfaceName, PcapOutput, GatewayIPFlag, GatewayMACFlag *string
	Mode                                                 string
	SrcPort, DstPort                                     *int
	SrcIP, DstIP                                         net.IP
}

func ValidMode(status string) bool {
	switch status {
	case TCPMode:
		return true
	default:
		return false
	}
}

func Start(c ModeConfig) {
	iface, err := netutil.GetInterfaceMAC(*c.IfaceName)
	if err != nil {
		log.Fatal(err)
	}

	netCapConfig := netcap.NetCapConfig{
		Interface:      iface,
		SnapLen:        65536,
		Timeout:        pcap.BlockForever,
		ReadBufferSize: 65536,
		PCAPFile:       *c.PcapOutput,
	}

	netCap, err := netcap.New(netCapConfig)
	if err != nil {
		log.Fatalf("Failed to create netcap: %v", err)
	}

	var gatewayMAC net.HardwareAddr

	if *c.GatewayMACFlag == "" {
		if *c.GatewayIPFlag == "" {
			log.Fatalln("If no gateway MAC address has been specified, the gateway IP address is needed")
		} else {
			gatewayMAC = arpMode(c, iface, netCap)
		}
	}

	switch c.Mode {
	case TCPMode:
		if err := tcpMode(netCap, c, gatewayMAC); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("Unsupported mode: %s", c.Mode)
	}
}

func arpMode(c ModeConfig, iface *net.Interface, netCap *netcap.NetCap) net.HardwareAddr {
	gatewayIP := net.ParseIP(*c.GatewayIPFlag).To4()
	if c.DstIP == nil {
		log.Fatalf("Invalid gateway IP address: %s", *c.GatewayIPFlag)
	}
	gatewayResolver, err := arp.NewGatewayResolver(iface, c.SrcIP, gatewayIP, netCap.Handle)
	if err != nil {
		log.Fatalf("arp.NewARPResolver: %v", err)
	}
	gatewayMAC, err := gatewayResolver.ResolveGatewayMAC()
	if err != nil {
		log.Fatalf("gatewayResolver.ResolveGatewayMAC: %v", err)
	}
	return gatewayMAC
}

func tcpMode(netCap *netcap.NetCap, c ModeConfig, gatewayMAC net.HardwareAddr) error {
	defer netCap.Close()
	netCap.ChangeFilter(netcap.BuildTCPResponseFilter(
		c.SrcIP,
		c.DstIP,
		*c.SrcPort,
		*c.DstPort,
	))

	ethernetConfig := &ethernet.EthernetConfig{
		SrcMAC: netCap.Config.Interface.HardwareAddr,
		DstMAC: gatewayMAC,
	}

	ipConfig := &ip.IPConfig{
		SrcIP: c.SrcIP,
		DstIP: c.DstIP,
	}

	tcpConfig := &tcp.TCPConfig{
		SrcPort: layers.TCPPort(*c.SrcPort),
		DstPort: layers.TCPPort(*c.DstPort),
		PType:   tcp.PacketSYN,
	}

	// Crafting SYN Packet
	packet, err := assembler.New().AddLayer(ethernet.New(ethernetConfig)).
		AddLayer(ip.New(ipConfig)).
		AddLayer(tcp.New(tcpConfig)).
		Build()
	if err != nil {
		log.Fatal(err)
		return err
	}

	// Sending SYN
	err = netCap.SendPacket(packet)
	if err != nil {
		log.Println("sendpacket ", err)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Receiving SYN-ACK
	_, seq, ack, err := netCap.ReceivePacket(ctx)
	if err != nil {
		log.Println("ReceivePacket ", err)
		return err
	}

	// Crafing ACK
	tcpConfig.PType = tcp.PacketACK
	tcpConfig.Seq = ack
	tcpConfig.Ack = seq
	packet, err = assembler.New().
		AddLayer(ethernet.New(ethernetConfig)).
		AddLayer(ip.New(ipConfig)).
		AddLayer(tcp.New(tcpConfig)).
		Build()

	// Sending ACK
	err = netCap.SendPacket(packet)
	if err != nil {
		log.Println("sendpacket ", err)
		return err
	}

	netCap.Close()
	return nil
}
