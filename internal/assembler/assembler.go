package assembler

import (
	"fmt"

	"github.com/gopacket/gopacket"
	golayer "github.com/gopacket/gopacket/layers"
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

	var layers []gopacket.SerializableLayer
	var ipLayer *golayer.IPv4
	for _, layer := range a.layers {
		l, err := layer.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build layer: %w", err)
		}

		if ip, ok := l.(*golayer.IPv4); ok {
			ipLayer = ip
		}

		if tcp, ok := l.(*golayer.TCP); ok && ipLayer != nil {
			tcp.SetNetworkLayerForChecksum(ipLayer)
		}

		layers = append(layers, l)
	}

	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize layers: %w", err)
	}

	return buf.Bytes(), nil
}
