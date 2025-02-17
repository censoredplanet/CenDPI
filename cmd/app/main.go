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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/censoredplanet/CenDPI/internal/netcap"
	"github.com/censoredplanet/CenDPI/internal/netutil"
	"github.com/censoredplanet/CenDPI/internal/portoracle"
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
	StartSourcePort uint16           `yaml:"startSourcePort"`
	Probelist       []string         `yaml:"probelist"`
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

	if c.StartSourcePort < portoracle.MINPORT || c.StartSourcePort > portoracle.MAXPORT {
		c.StartSourcePort = portoracle.MINPORT
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

func parseTargetsJSONL(path string) ([]service.Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []service.Target
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
		targets = append(targets, tgt)
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

	// Use the base filename (strips directories and .yml/.yaml extension)
	filename := filepath.Base(path)
	nameOnly := strings.TrimSuffix(filename, filepath.Ext(filename))
	config.Name = nameOnly

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

func drainChannels(chMap map[netcap.FlowKey]chan netcap.PacketInfo) {
	for _, ch := range chMap {
		for {
			select {
			case <-ch:
			default:
				goto NEXT
			}
		}
	NEXT:
	}
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	measurementConfigPath := flag.String("config", "", "Path to global measurement.config YAML")
	targetConfigPath := flag.String("target", "", "Path to target.jsonl (line-delimited JSON)")
	savePcap := flag.Bool("pcap", false, "Saves the probes additionally within pcap files")
	resultsPath := flag.String("resultPath", "results.json", "Path to JSON results file")
	rounds := flag.Int("rounds", 1, "Number of rounds to run for each probe-target measurement")

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
	for _, probeFile := range globalCfg.Probelist {
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

		controlCfg, err := copyServiceConfig(probeCfg)
		if err != nil {
			log.Fatalf("Failed copying config for control: %v", err)
		}
		testCfg, err := copyServiceConfig(probeCfg)
		if err != nil {
			log.Fatalf("Failed copying config for test: %v", err)
		}

		controlCfg.IsControl = true
		testCfg.IsControl = false

		probeTemplates = append(probeTemplates, controlCfg)
		probeTemplates = append(probeTemplates, testCfg)
	}

	// get sequential ports
	ports, err := portoracle.ReservePortRanges(len(probeTemplates), globalCfg.StartSourcePort)
	if err != nil {
		log.Fatal(err)
	}
	defer closePorts(ports)

	// assign each probe a unique source port
	for i, port := range ports {
		p := uint16(port.Addr().(*net.TCPAddr).Port)
		probeTemplates[i].SrcPort = layers.TCPPort(p)
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
		BPF:            portoracle.BuildPortRangeBPF(ports),
	}
	netCap, err := netcap.New(netCapConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer netCap.Close()
	netCap.Config.SavePcap = *savePcap

	// pcap info lookup map
	var flowKeyToPcap map[netcap.FlowKey]netcap.NetCapPcapInfo
	if netCap.Config.SavePcap {
		flowKeyToPcap = make(map[netcap.FlowKey]netcap.NetCapPcapInfo, len(probeTemplates)*len(targets))
	}

	// channel lookup map, each TCP connection has its own channel
	chMap := make(map[netcap.FlowKey]chan netcap.PacketInfo)

	// pre-populate the channel map
	for _, probe := range probeTemplates {
		for _, tgt := range targets {
			if probe.Protocol != "both" && probe.Protocol != tgt.Protocol {
				continue
			}
			dstIP := net.ParseIP(tgt.TargetIP)
			dstPort := layers.TCPPort(tgt.TargetPort)
			flowKey := netcap.NormalizeFlowKey(probe.SrcIP, probe.SrcPort, dstIP, dstPort)

			// ensure no duplicate flowKey
			if _, ok := chMap[flowKey]; ok {
				log.Fatalf("Duplicate flowKey: %v", flowKey)
			}
			chMap[flowKey] = make(chan netcap.PacketInfo, 100)

			if netCap.Config.SavePcap {
				pcapInfo := netcap.NetCapPcapInfo{
					TargetIP:   dstIP,
					TargetPort: dstPort,
					IsControl:  probe.IsControl,
					ProbeName:  probe.Name,
				}
				flowKeyToPcap[flowKey] = pcapInfo
			}
		}
	}
	log.Println("Channel map populated with num of channels:", len(chMap))
	ctx, cancel := context.WithCancel(context.Background())

	if netCap.Config.SavePcap {
		err = netCap.SetupPCAPWriters(flowKeyToPcap, globalCfg.ResultsPath)
		if err != nil {
			log.Fatal(err)
		}
	}
	netCap.StartPacketReceiver(ctx, chMap)
	resultsCh := make(chan netcap.Result, 1000)
	go netCap.SaveResults(ctx, *resultsPath, resultsCh)

	for i := 0; i < *rounds; i++ {
		for _, probe := range probeTemplates {
			mode := "test"
			if probe.IsControl {
				mode = "control"
			}
			log.Printf("=== Starting Probe Round: %s (%s) ===", probe.Name, mode)

			// Run all targets in *this* probe concurrently.
			// Then wait for them before moving on to the next probe.
			var roundWG sync.WaitGroup
			for _, tgt := range targets {
				if probe.Protocol != "both" && probe.Protocol != tgt.Protocol {
					continue
				}
				roundWG.Add(1)
				probeCopy, err := copyServiceConfig(probe)
				if err != nil {
					log.Fatalf("Failed copying config for targets: %v", err)
				}
				go func(c service.ServiceConfig, t service.Target) {
					defer roundWG.Done()
					flowKey := netcap.NormalizeFlowKey(c.SrcIP, c.SrcPort, net.ParseIP(t.TargetIP), layers.TCPPort(t.TargetPort))
					if _, ok := chMap[flowKey]; !ok {
						log.Fatalf("FlowKey not found in chMap: %v", flowKey)
					}
					resultsCh <- service.StartSingleMeasurement(netCap, c, t, chMap[flowKey])

				}(probeCopy, tgt)
			}

			// Wait for all targets in this probe to finish
			roundWG.Wait()
			// 3 seconds wait between control and test of the same probe
			time.Sleep(3 * time.Second)
			if !probe.IsControl {
				// longer wait between consecutive probes
				time.Sleep(30 * time.Second)
			}
			drainChannels(chMap)
			time.Sleep(3 * time.Second)
		}
	}
	cancel()
	log.Println("All measurements done.")
}
