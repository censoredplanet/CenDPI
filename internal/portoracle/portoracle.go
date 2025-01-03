package portoracle

import (
	"log"
	"math/rand"
)

type PortOracle struct {
	ports []uint16
	pos   int
}

func New(minPort, maxPort uint16) *PortOracle {
	if minPort > maxPort {
		log.Fatal("minPort cannot be greater than maxPort")
	}
	total := maxPort - minPort + 1
	portSlice := make([]uint16, total)

	for i := range portSlice {
		portSlice[i] = uint16(minPort + uint16(i))
	}

	shufflePorts(portSlice)

	return &PortOracle{
		ports: portSlice,
		pos:   0,
	}
}

func (o *PortOracle) NextPort() uint16 {
	if o.pos >= len(o.ports) {
		o.pos = 0
	}
	p := o.ports[o.pos]
	o.pos++
	return p
}

func shufflePorts(ports []uint16) {
	for i := len(ports) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		ports[i], ports[j] = ports[j], ports[i]
	}
}
