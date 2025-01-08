package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/censoredplanet/CenDPI/internal/netcap"
	"github.com/censoredplanet/CenDPI/internal/netutil"
	"github.com/censoredplanet/CenDPI/internal/portoracle"
	"github.com/censoredplanet/CenDPI/internal/service"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

type GlobalMeasurementConfig struct {
	Interface   string           `yaml:"interface"`
	ResultsPath string           `yaml:"resultsPath"`
	SourceMAC   net.HardwareAddr `yaml:"-"`
	GatewayMAC  net.HardwareAddr `yaml:"-"`
	SourceIP    net.IP           `yaml:"-"`
	Probelist   []string         `yaml:"probelist"`
}

func (c *GlobalMeasurementConfig) UnmarshalYAML(node *yaml.Node) error {
	type base GlobalMeasurementConfig
	raw := struct {
		base   `yaml:",inline"`
		SrcIP  string `yaml:"sourceIP"`
		SrcMAC string `yaml:"sourceMAC"`
		DstMAC string `yaml:"gatewayMAC"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	*c = GlobalMeasurementConfig(raw.base)

	if raw.SrcIP != "" && raw.SrcMAC != "" && raw.DstMAC != "" {
		c.SourceIP = net.ParseIP(raw.SrcIP)
		srcMAC, err := net.ParseMAC(raw.SrcMAC)
		if err != nil {
			log.Fatalf("invalid sourceMAC specified in the measurement yaml file: %v", err)
		}
		c.SourceMAC = srcMAC
		dstMAC, err := net.ParseMAC(raw.DstMAC)
		if err != nil {
			log.Fatalf("invalid gatewayMAC specified in the measurement yaml file: %v", err)
		}
		c.GatewayMAC = dstMAC
	} else {
		log.Fatal("the measurement yaml file needs to specify the sourceMAC, gatewayMAC and sourceIP")
	}

	return nil
}

func parseGlobalMeasurementConfig(path string) (*GlobalMeasurementConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg GlobalMeasurementConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func parseTargetsJSONL(path string) (map[string][]service.Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	targets := make(map[string][]service.Target)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			// skip empty lines or comment lines
			continue
		}
		var tgt service.Target
		if err := json.Unmarshal([]byte(line), &tgt); err != nil {
			return nil, fmt.Errorf("json decode error on line: %s\n%v", line, err)
		}
		targets[tgt.TargetIP] = append(targets[tgt.TargetIP], tgt)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func parseProbeConfigYAML(path string, cfg *GlobalMeasurementConfig) (service.ServiceConfig, error) {
	ymlData, err := os.ReadFile(path)
	if err != nil {
		return service.ServiceConfig{}, err
	}

	var config service.ServiceConfig
	if err := yaml.Unmarshal(ymlData, &config); err != nil {
		return service.ServiceConfig{}, err
	}
	for i := range config.Packets {
		config.Packets[i].Ethernet.SrcMAC = cfg.SourceMAC
		config.Packets[i].Ethernet.DstMAC = cfg.GatewayMAC
	}
	config.Iface = cfg.Interface
	config.PcapPath = cfg.ResultsPath
	return config, nil
}

func closePorts(ports []net.Listener) {
	for _, p := range ports {
		p.Close()
	}
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	measurementConfigPath := flag.String("config", "", "Path to global measurement.config YAML")
	targetConfigPath := flag.String("target", "", "Path to target.jsonl (line-delimited JSON)")

	flag.Parse()
	if *measurementConfigPath == "" || *targetConfigPath == "" {
		log.Fatal("Usage: cendpi -measurement measurement.config -target target.jsonl")
	}

	globalCfg, err := parseGlobalMeasurementConfig(*measurementConfigPath)
	if err != nil {
		log.Fatalf("Error parsing measurement config: %v\n", err)
	}

	targets, err := parseTargetsJSONL(*targetConfigPath)
	if err != nil {
		log.Fatalf("Error parsing targets file: %v\n", err)
	}

	// build probe template
	var probeTemplates []service.ServiceConfig
probe:
	for _, probeFile := range globalCfg.Probelist {
		probeCfg, err := parseProbeConfigYAML(probeFile, globalCfg)
		if err != nil {
			log.Printf("Skipping probe %s: %v\n", probeFile, err)
			continue
		}
		// Check for edge case where no tcp and no fragmentation
		for _, packet := range probeCfg.Packets {
			if packet.TCP == nil && !packet.IP.FragmentationEnabled {
				log.Fatal("Probe Invalid: no tcp packet and no fragmentation defined within the yaml file, Skipping")
				continue probe
			}
		}
		probeCfg.SrcIP = globalCfg.SourceIP
		probeTemplates = append(probeTemplates, probeCfg)
	}

	// get sequential ports to build port range based BPF
	ports, err := portoracle.ReservePortRanges(len(targets))
	if err != nil {
		log.Fatal(err)
	}
	defer closePorts(ports)
	// channel lookup map
	chMap := make(map[uint16]chan netcap.PacketInfo)
	// port to ip lookup map
	portToIP := make(map[uint16]string)
	var ips []string
	for ip := range targets {
		ips = append(ips, ip)
	}
	for i, port := range ports {
		p := uint16(port.Addr().(*net.TCPAddr).Port)
		portToIP[p] = ips[i]
		ch := make(chan netcap.PacketInfo, 10)
		chMap[p] = ch
	}

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())

	iface, err := netutil.GetInterfaceMAC(globalCfg.Interface)
	if err != nil {
		log.Fatal(err)
	}

	netCapConfig := netcap.NetCapConfig{
		Interface:      iface,
		SnapLen:        65536,
		Timeout:        pcap.BlockForever,
		ReadBufferSize: 65536,
		BPF:            portoracle.BuildPortRangeBPF(ports),
	}
	netCap, err := netcap.New(netCapConfig)
	if err != nil {
		log.Fatal(err)
	}

	err = netCap.SetupPCAPWriters(portToIP, globalCfg.ResultsPath)
	if err != nil {
		log.Fatal(err)
	}

	saveCh := make(chan netcap.PacketInfo, 100)

	netCap.StartPacketReceiver(ctx, chMap, saveCh)
	netCap.SavePackets(ctx, saveCh)
	defer netCap.Close()

	for port, ip := range portToIP {
		// get a copy of the probe templates
		var probes []service.ServiceConfig
		jsonData, err := json.Marshal(probeTemplates)
		if err != nil {
			log.Fatal(err)
		}
		json.Unmarshal(jsonData, &probes)

		srcPort := layers.TCPPort(port)
		log.Printf("target: %s, source port: %s", ip, srcPort.String())

		wg.Add(1)
		go func() {
			defer wg.Done()
			service.Start(netCap, probes, srcPort, targets[ip], chMap[port], &globalCfg.SourceMAC, &globalCfg.GatewayMAC)
		}()
	}

	wg.Wait()
	cancel()
	log.Println("All measurements done.")
}
