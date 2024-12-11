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

func (a *Assembler) Build() ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var layersList []gopacket.SerializableLayer
	var ipLayer *golayer.IPv4
	var rawPayload []byte

	for _, layer := range a.layers {
		l, err := layer.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build layer: %w", err)
		}

		// Check if this is an IPv4 layer
		if ip4, ok := l.(*golayer.IPv4); ok {
			ipLayer = ip4
			layersList = append(layersList, ipLayer)

			// If the original layer is of type *ip.IPLayer, we can get its config
			if ipLay, ok := layer.(*ip.IPLayer); ok {
				cfg := ipLay.Config()
				if len(cfg.RawPayload) > 0 {
					// We have raw IP payload to append later
					rawPayload = cfg.RawPayload
				}
			}
		} else if tcpLayer, ok := l.(*golayer.TCP); ok && ipLayer != nil { // Check if this is a TCP layer
			// We have a TCP layer after IP
			layersList = append(layersList, tcpLayer)
			if len(tcpLayer.Payload) > 0 {
				layersList = append(layersList, gopacket.Payload(tcpLayer.Payload))
			}
			tcpLayer.SetNetworkLayerForChecksum(ipLayer)

			// Since we found a TCP layer, rawPayload of the IP layer should not be added directly,
			// because now we have a proper upper layer (TCP).
			// TODO: add proper error handling if rawPayload from the IP layer is not nil and TCP layer is found.
			rawPayload = nil
		} else {
			// Non-TCP, Non-IP layers
			layersList = append(layersList, l)
		}
	}

	// After processing all layers, if rawPayload is still present,
	// Append it as a payload layer.
	if rawPayload != nil {
		layersList = append(layersList, gopacket.Payload(rawPayload))
	}

	err := gopacket.SerializeLayers(buf, opts, layersList...)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize layers: %w", err)
	}

	return buf.Bytes(), nil
}