package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net"
	"os"
	"strings"

	"github.com/censoredplanet/CenDPI/internal/service"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Iface    string   `yaml:"interface"`
	PcapPath string   `yaml:"pcapPath"`
	BPF      string   `yaml:"bpf"`
	Delay    int      `yaml:"delay"`
	Packets  []Packet `yaml:"packets"`
}

type Packet struct {
	Ethernet EthernetYaml `yaml:"ethernet"`
	IP       IPYaml       `yaml:"ip"`
	TCP      TCPYaml      `yaml:"tcp"`
}

type EthernetYaml struct {
	SrcMAC string `yaml:"srcMac"`
	DstMAC string `yaml:"dstMac"`
}

type IPYaml struct {
	SrcIP string `yaml:"srcIp"`
	DstIP string `yaml:"dstIp"`
	TOS   uint8  `yaml:"tos"`
	TTL   uint8  `yaml:"ttl"`
}

type TCPFlags struct {
	SYN bool `yaml:"syn"`
	ACK bool `yaml:"ack"`
	PSH bool `yaml:"psh"`
	FIN bool `yaml:"fin"`
	RST bool `yaml:"rst"`
	URG bool `yaml:"urg"`
	ECE bool `yaml:"ece"`
}

type TCPYaml struct {
	SrcPort uint16   `yaml:"srcPort"`
	DstPort uint16   `yaml:"dstPort"`
	Window  uint16   `yaml:"window"`
	Flags   TCPFlags `yaml:"flags"`
	Data    string   `yaml:"data,omitempty"` // Base64 encoded
}

func parseConfig(data []byte) *service.ServiceConfig {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil
	}

	serviceConfig := service.ServiceConfig{
		Iface:    config.Iface,
		PcapPath: config.PcapPath,
		BPF:      config.BPF,
		Delay:    config.Delay,
	}

	packets := []service.ServicePacket{}
	for _, c := range config.Packets {
		p := service.ServicePacket{}
		srcMAC, err := net.ParseMAC(c.Ethernet.SrcMAC)
		if err != nil {
			log.Fatal(err)
		}
		dstMAC, err := net.ParseMAC(c.Ethernet.DstMAC)
		if err != nil {
			log.Fatal(err)
		}
		p.Ethernet.SrcMAC, p.Ethernet.DstMAC = srcMAC, dstMAC
		p.IP.SrcIP, p.IP.DstIP = net.ParseIP(c.IP.SrcIP), net.ParseIP(c.IP.DstIP)
		p.IP.TOS, p.IP.TTL = c.IP.TOS, c.IP.TTL

		p.TCP.SrcPort, p.TCP.DstPort = layers.TCPPort(c.TCP.SrcPort), layers.TCPPort(c.TCP.DstPort)
		p.TCP.Window = c.TCP.Window
		p.TCP.SYN, p.TCP.ACK, p.TCP.PSH, p.TCP.FIN = c.TCP.Flags.SYN, c.TCP.Flags.ACK, c.TCP.Flags.PSH, c.TCP.Flags.FIN
		p.TCP.RST, p.TCP.URG, p.TCP.ECE = c.TCP.Flags.RST, c.TCP.Flags.URG, c.TCP.Flags.ECE
		if c.TCP.Data != "" {
			p.TCP.Data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(c.TCP.Data))
			if err != nil {
				log.Fatal(err)
			}
		}

		packets = append(packets, p)
	}
	serviceConfig.Packets = packets
	return &serviceConfig
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	configFile := flag.String("config", "", "Path to the YAML configuration file")
	flag.Parse()

	ymlData, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	config := parseConfig(ymlData)
	if err != nil {
		log.Fatal(err)
	}

	service.Start(*config)
}
