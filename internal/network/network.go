package network

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/ipv4"
)

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

func SendPacket(w *pcapgo.Writer, ipHeader *ipv4.Header, payload []byte, rawConn *ipv4.RawConn) error {
	ipHeaderBytes, err := ipHeader.Marshal()
	if err != nil {
		return fmt.Errorf("error serializing IP header: %v", err)
	}

	packet := append(ipHeaderBytes, payload...)

	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(packet),
		Length:         len(packet),
		InterfaceIndex: 0,
	}
	err = w.WritePacket(ci, packet)
	if err != nil {
		return fmt.Errorf("error writing sent packet to pcap file: %v", err)
	}

	err = rawConn.WriteTo(ipHeader, payload, nil)
	if err != nil {
		return fmt.Errorf("error sending packet via rawConn: %v", err)
	}

	return nil
}
