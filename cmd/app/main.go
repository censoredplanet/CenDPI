package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"

	"github.com/censoredplanet/CenDPI/internal/service"
)

func main() {
	if os.Geteuid() != 0 {
		log.Println("This program must be run as root! (sudo)")
		return
	}
	ifaceName := flag.String("iface", "", "Network interface name to use")
	srcIPStr := flag.String("srcip", "", "Source IP address (required)")
	dstIPStr := flag.String("dstip", "", "Destination IP address (required)")
	gatewayIPFlag := flag.String("gatewayip", "", "Gateway IP address (optional)")
	gatewayMACFlag := flag.String("gatewaymac", "", "Gateway MAC address (optional)")
	srcPortFlag := flag.Int("srcport", 59152, "Source ephemeral port (49152–65535 for MacOS & 32768–60999 Linux kernel)")
	dstPortFlag := flag.Int("dstport", 80, "Destination port")
	mode := flag.String("mode", "tcp", "Connection to establish")
	pcapOutput := flag.String("pcapoutput", "output.pcap", "Optional: File path to save the pcap capture output")

	flag.Parse()

	if *ifaceName == "" {
		log.Fatalf("Error: -iface must be specified")
	}

	srcIP := net.ParseIP(*srcIPStr).To4()
	if srcIP == nil {
		log.Fatalf("Invalid source IP address: %s", *srcIPStr)
	}

	dstIP := net.ParseIP(*dstIPStr).To4()
	if dstIP == nil {
		log.Fatalf("Invalid destination IP address: %s", *dstIPStr)
	}

	if *srcPortFlag < 32768 || *srcPortFlag > 65535 {
		log.Fatalf("Error: -srcport value needs to be between 32768 and 65535")
	}

	if *dstPortFlag != 80 && *dstPortFlag != 443 {
		log.Fatalf("Error: -dstport value needs to be either 80 or 443")
	}

	if !service.ValidMode(strings.ToUpper(*mode)) {
		log.Fatalf("Error: invalid -mode value")
	}

	service.Start(service.ModeConfig{
		IfaceName:      ifaceName,
		Mode:           strings.ToUpper(*mode),
		PcapOutput:     pcapOutput,
		GatewayIPFlag:  gatewayIPFlag,
		GatewayMACFlag: gatewayMACFlag,
		SrcPort:        srcPortFlag,
		DstPort:        dstPortFlag,
		SrcIP:          srcIP,
		DstIP:          dstIP,
	})
}
