package assembler

import (
	"fmt"

	"github.com/gopacket/gopacket"
	golayer "github.com/gopacket/gopacket/layers"
	"github.com/censoredplanet/CenDPI/internal/ip"
)

type Layer interface {
	Build() (gopacket.SerializableLayer, error)
}

type Assembler struct {
	layers []Layer
}

func New() *Assembler {
	return &Assembler{
		layers: make([]Layer, 0),
	}
}

func (a *Assembler) AddLayer(layer Layer) *Assembler {
	a.layers = append(a.layers, layer)
	return a
}


func (a *Assembler) Build(corruptTCPChecksum bool) ([]byte, error) {

	var ipLayer *golayer.IPv4
	var ipAndBelow  []gopacket.SerializableLayer
	var tcpAndAbove []gopacket.SerializableLayer
	var rawIPPayload  []byte

	for _, layer := range a.layers {
		l, err := layer.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build layer: %w", err)
		}

		// Check if this is an IPv4 layer
		if ip4, ok := l.(*golayer.IPv4); ok {
			ipLayer = ip4
			ipAndBelow = append(ipAndBelow, ipLayer)

			// If the original layer is of type *ip.IPLayer, we can get its config
			if ipLay, ok := layer.(*ip.IPLayer); ok {
				cfg := ipLay.Config()
				if len(cfg.RawPayload) > 0 {
					// We have raw IP payload to append later
					rawIPPayload = cfg.RawPayload
				}
			}
		} else if tcpLayer, ok := l.(*golayer.TCP); ok && ipLayer != nil { // Check if this is a TCP layer
			tcpAndAbove = append(tcpAndAbove, tcpLayer)
			if len(tcpLayer.Payload) > 0 {
				tcpAndAbove = append(tcpAndAbove, gopacket.Payload(tcpLayer.Payload))
			}
			tcpLayer.SetNetworkLayerForChecksum(ipLayer)

			// Since we found a TCP layer, rawPayload of the IP layer should not be added directly,
			// because now we have a proper upper layer (TCP).
			// TODO: add proper error handling if rawPayload from the IP layer is not nil and TCP layer is found.
			rawIPPayload = nil
		} else {
			// ethernet
			ipAndBelow = append(ipAndBelow, l)
		}
	}

	if len(tcpAndAbove) > 0 && ipLayer != nil {
		tcpAndAboveBuf := gopacket.NewSerializeBuffer()
		tcpAndAboveOpts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: !corruptTCPChecksum, // we may want to corrupt TCP checksum
		}
		err := gopacket.SerializeLayers(tcpAndAboveBuf, tcpAndAboveOpts, tcpAndAbove...)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize TCP and above layers: %w", err)
		}
		rawIPPayload = tcpAndAboveBuf.Bytes()
	}

	if rawIPPayload != nil {
		ipAndBelow = append(ipAndBelow, gopacket.Payload(rawIPPayload))
	}

	ipAndBelowBuf := gopacket.NewSerializeBuffer()
	ipAndBelowOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true, // we always want IP checksum to be correct
	}
	err := gopacket.SerializeLayers(ipAndBelowBuf, ipAndBelowOpts, ipAndBelow...)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize IP and below layers: %w", err)
	}

	return ipAndBelowBuf.Bytes(), nil
}