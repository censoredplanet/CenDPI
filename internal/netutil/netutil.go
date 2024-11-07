package netutil

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func GetInterfaceMAC(interfaceName string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %v", err)
	}
	return iface, nil
}

func SetupPcapFile(fileName string) (*pcapgo.Writer, *os.File) {
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(65535, layers.LinkTypeIPv4)
	if err != nil {
		log.Fatal(err)
	}

	return w, f
}
