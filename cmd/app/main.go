package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/censoredplanet/CenDPI/internal/portoracle"
	"github.com/censoredplanet/CenDPI/internal/service"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"
)

type GlobalMeasurementConfig struct {
	Interface  string           `yaml:"interface"`
	PcapPath   string           `yaml:"pcapPath"`
	SourceMAC  net.HardwareAddr `yaml:"-"`
	GatewayMAC net.HardwareAddr `yaml:"-"`
	SourceIP   net.IP           `yaml:"-"`
	Probelist  []string         `yaml:"probelist"`
}

type Target struct {
	TargetIP      string `json:"TargetIP"`
	TargetPort    uint16 `json:"TargetPort"`
	SourcePort    uint16 `json:"SourcePort"`
	TestDomain    string `json:"TestDomain"`
	Protocol      string `json:"Protocol"` // e.g. "http" or "https"
	ControlDomain string `json:"ControlDomain"`
	Label         string `json:"Label"`
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
			log.Fatalf("invalid sourceMAC specified in the measurement yaml file: %w", err)
		}
		c.SourceMAC = srcMAC
		dstMAC, err := net.ParseMAC(raw.DstMAC)
		if err != nil {
			log.Fatalf("invalid gatewayMAC specified in the measurement yaml file: %w", err)
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

func parseTargetsJSONL(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []Target
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			// skip empty lines or comment lines
			continue
		}
		var tgt Target
		if err := json.Unmarshal([]byte(line), &tgt); err != nil {
			return nil, fmt.Errorf("json decode error on line: %s\n%v", line, err)
		}
		results = append(results, tgt)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func parseProbeConfigYAML(path string, cfg *GlobalMeasurementConfig) (*service.ServiceConfig, error) {
	ymlData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config service.ServiceConfig
	if err := yaml.Unmarshal(ymlData, &config); err != nil {
		return nil, err
	}
	for i := range config.Packets {
		config.Packets[i].Ethernet.SrcMAC = cfg.SourceMAC
		config.Packets[i].Ethernet.DstMAC = cfg.GatewayMAC
	}
	config.Iface = cfg.Interface
	config.PcapPath = cfg.PcapPath
	return &config, nil
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

	sourcePortOracle := portoracle.New(39152, 65535)

	// todo: add concurrency
	for _, probeFile := range globalCfg.Probelist {
		for _, tgt := range targets {
			log.Printf("Measuring target %s:%d (domain=%s) with probe '%s'\n",
				tgt.TargetIP, tgt.TargetPort, tgt.TestDomain, probeFile)

			probeCfg, err := parseProbeConfigYAML(probeFile, globalCfg)
			if err != nil {
				log.Printf("Skipping probe %s: %v\n", probeFile, err)
				continue
			}

			probeCfg.Domain = tgt.TestDomain
			if probeCfg.Message != nil && probeCfg.Message.HTTP != nil {
				probeCfg.Message.HTTP.Domain = tgt.TestDomain
			}

			controlProbeCfg, err := parseProbeConfigYAML(probeFile, globalCfg)
			if err != nil {
				log.Printf("Skipping probe %s: %v\n", probeFile, err)
				continue
			}

			controlProbeCfg.Domain = tgt.ControlDomain
			controlProbeCfg.IsControl = true
			if controlProbeCfg.Message != nil && probeCfg.Message.HTTP != nil {
				controlProbeCfg.Message.HTTP.Domain = tgt.ControlDomain
			}

			probeCfg.SrcPort = layers.TCPPort(sourcePortOracle.NextPort())
			controlProbeCfg.SrcPort = layers.TCPPort(sourcePortOracle.NextPort())
			probeCfg.DstPort = layers.TCPPort(tgt.TargetPort)
			controlProbeCfg.DstPort = layers.TCPPort(tgt.TargetPort)
			probeCfg.BPF = "tcp and src host " + tgt.TargetIP
			controlProbeCfg.BPF = "tcp and src host " + tgt.TargetIP
			probeCfg.SrcIP, controlProbeCfg.SrcIP = globalCfg.SourceIP, globalCfg.SourceIP
			probeCfg.DstIP, controlProbeCfg.DstIP = net.ParseIP(tgt.TargetIP), net.ParseIP(tgt.TargetIP)
			probeCfg.Label, controlProbeCfg.Label = tgt.Label, tgt.Label

			err = service.Start(*controlProbeCfg)
			if err != nil {
				log.Fatalf("Error starting control measurement: %v\n", err)
			}

			err = service.Start(*probeCfg)
			if err != nil {
				log.Fatalf("Error starting test measurement: %v\n", err)
			}
		}
	}

	log.Println("All measurements done.")
}
