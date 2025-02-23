package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/censoredplanet/CenDPI/internal/netcap"
	"github.com/censoredplanet/CenDPI/internal/netutil"
	"github.com/censoredplanet/CenDPI/internal/service"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

type GlobalMeasurementConfig struct {
	Interface       string           `yaml:"interface"`
	ResultsPath     string           `yaml:"resultsPath"`
	SourceMAC       net.HardwareAddr `yaml:"-"`
	GatewayMAC      net.HardwareAddr `yaml:"-"`
	SourceIP        net.IP           `yaml:"-"`
	DestinationIP   net.IP           `yaml:"-"`
	StartSourcePort uint16           `yaml:"startSourcePort"`
	ProbeDir        string           `yaml:"probedir"`
}

func (c *GlobalMeasurementConfig) UnmarshalYAML(node *yaml.Node) error {
	type base GlobalMeasurementConfig
	raw := struct {
		base   `yaml:",inline"`
		SrcIP  string `yaml:"sourceIP"`
		DstIP  string `yaml:"destinationIP"`
		SrcMAC string `yaml:"sourceMAC"`
		DstMAC string `yaml:"gatewayMAC"`
	}{}

	if err := node.Decode(&raw); err != nil {
		return err
	}

	*c = GlobalMeasurementConfig(raw.base)

	if raw.SrcIP != "" && raw.SrcMAC != "" && raw.DstMAC != "" && raw.DstIP != "" {
		c.SourceIP = net.ParseIP(raw.SrcIP)
		c.DestinationIP = net.ParseIP(raw.DstIP)
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

func parseProbeConfigYAML(path string, cfg *GlobalMeasurementConfig) (service.ServiceConfig, error) {
	ymlData, err := os.ReadFile(path)
	if err != nil {
		return service.ServiceConfig{}, err
	}

	var config service.ServiceConfig
	if err := yaml.Unmarshal(ymlData, &config); err != nil {
		return service.ServiceConfig{}, err
	}

	// Use the base filename (strips directories and .yml/.yaml extension)
	filename := filepath.Base(path)
	nameOnly := strings.TrimSuffix(filename, filepath.Ext(filename))
	config.Name = nameOnly

	// check if nameOnly can be converted to uint16 and convert if so otherwise error out
	if _, err := fmt.Sscanf(nameOnly, "%d", &config.Number); err != nil {
		return service.ServiceConfig{}, fmt.Errorf("invalid probe name: %s", nameOnly)
	}

	for i := range config.Packets {
		config.Packets[i].Ethernet.SrcMAC = cfg.SourceMAC
		config.Packets[i].Ethernet.DstMAC = cfg.GatewayMAC
	}
	config.Iface = cfg.Interface
	config.PcapPath = cfg.ResultsPath
	return config, nil
}

func copyServiceConfig(original service.ServiceConfig) (service.ServiceConfig, error) {
	data, err := json.Marshal(original)
	if err != nil {
		return service.ServiceConfig{}, fmt.Errorf("marshal error: %w", err)
	}
	var copy service.ServiceConfig
	if err := json.Unmarshal(data, &copy); err != nil {
		return service.ServiceConfig{}, fmt.Errorf("unmarshal error: %w", err)
	}
	return copy, nil
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	measurementConfigPath := flag.String("config", "", "Path to global measurement.config YAML")
	curProtocol := flag.String("protocol", "", "Protocol to use for the server")

	flag.Parse()
	if *measurementConfigPath == "" {
		log.Fatal("Usage: cendpi -measurement measurement.config ")
	}

	globalCfg, err := parseGlobalMeasurementConfig(*measurementConfigPath)
	if err != nil {
		log.Fatalf("Error parsing measurement config: %v\n", err)
	}

	// Read all probe files from the specified directory
	if globalCfg.ProbeDir == "" {
		log.Fatal("Probe directory not specified in the measurement config")
	}
	probeFiles, err := filepath.Glob(filepath.Join(globalCfg.ProbeDir, "*.yml"))
	if err != nil {
		log.Fatalf("Error reading probe directory: %v", err)
	}

	// build probe template
	var probeTemplates []service.ServiceConfig
	for _, probeFile := range probeFiles {
		probeCfg, err := parseProbeConfigYAML(probeFile, globalCfg)
		if err != nil {
			log.Printf("Skipping probe %s: %v\n", probeFile, err)
			continue
		}
		// Check for edge case where no tcp and no fragmentation
		for _, packet := range probeCfg.Packets {
			if packet.TCP == nil && !packet.IP.FragmentationEnabled {
				log.Fatal("Probe Invalid: no tcp packet and no fragmentation defined within the yaml file.")
			}
		}
		probeCfg.SrcIP = globalCfg.SourceIP
		probeCfg.DstIP = globalCfg.DestinationIP

		if probeCfg.Protocol != "both" && probeCfg.Protocol != *curProtocol {
			continue
		}

		probeCfg.SrcPort = layers.TCPPort(globalCfg.StartSourcePort + probeCfg.Number)
		if *curProtocol == "http" {
			probeCfg.DstPort = layers.TCPPort(80)
			probeCfg.Protocol = "http"
		} else if *curProtocol == "https" {
			probeCfg.DstPort = layers.TCPPort(443)
			probeCfg.Protocol = "https"
		} else {
			log.Fatalf("Invalid protocol: %s", *curProtocol)
		}

		testCfg, err := copyServiceConfig(probeCfg)
		if err != nil {
			log.Fatalf("Failed copying config for test: %v", err)
		}
		testCfg.IsControl = false
		probeTemplates = append(probeTemplates, testCfg)
	}

	iface, err := netutil.GetInterfaceMAC(globalCfg.Interface)
	if err != nil {
		log.Fatal(err)
	}

	netCapConfig := netcap.NetCapConfig{
		Interface:      iface,
		SnapLen:        65536,
		Timeout:        pcap.BlockForever,
		ReadBufferSize: 65536,
	}
	netCap, err := netcap.New(netCapConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer netCap.Close()

	// pcap info lookup map
	var flowKeyToPcap map[netcap.FlowKey]netcap.NetCapPcapInfo
	flowKeyToPcap = make(map[netcap.FlowKey]netcap.NetCapPcapInfo, len(probeTemplates))

	// channel lookup map, each TCP connection has its own channel
	chMap := make(map[netcap.FlowKey]chan netcap.PacketInfo)

	// pre-populate the channel map
	for _, probe := range probeTemplates {

		flowKey := netcap.NormalizeFlowKey(probe.SrcIP, probe.SrcPort, probe.DstIP, probe.DstPort)
		if _, ok := chMap[flowKey]; ok {
			log.Fatalf("Duplicate flowKey: %v", flowKey)
		}
		chMap[flowKey] = make(chan netcap.PacketInfo, 100)

		pcapInfo := netcap.NetCapPcapInfo{
			TargetIP:   probe.DstIP,
			TargetPort: probe.DstPort,
			IsControl:  probe.IsControl,
			ProbeName:  probe.Name,
		}
		flowKeyToPcap[flowKey] = pcapInfo
	}
	log.Println("Channel map populated with num of channels:", len(chMap))

	err = netCap.SetupPCAPWriters(flowKeyToPcap, globalCfg.ResultsPath)
	if err != nil {
		log.Fatal(err)
	}

	var roundWG sync.WaitGroup

	for _, probe := range probeTemplates {

		roundWG.Add(1)
		probeCopy, err := copyServiceConfig(probe)
		if err != nil {
			log.Fatalf("Failed copying config for targets: %v", err)
		}
		go func(c service.ServiceConfig) {
			defer roundWG.Done()
			flowKey := netcap.NormalizeFlowKey(c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)
			if _, ok := chMap[flowKey]; !ok {
				log.Fatalf("FlowKey not found in chMap: %v", flowKey)
			}
			service.StartSingleMeasurement(netCap, c, chMap[flowKey])
		}(probeCopy)
	}
	roundWG.Wait()
	log.Println("All measurements done.")
}
