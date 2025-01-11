package portoracle

import (
	"fmt"
	"log"
	"math/rand"
	"net"
)

const (
	MINPORT uint16 = 39152
	MAXPORT uint16 = 65535
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

func ReservePortRanges(numOfPorts int, startSourcePort uint16) (ports []net.Listener, err error) {
	for min := startSourcePort; len(ports) < numOfPorts && min <= MAXPORT; min++ {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", min))
		if err != nil {
			log.Printf("Port %d is in use\n", min)
			continue
		}
		ports = append(ports, ln)
	}
	if numOfPorts != len(ports) {
		return nil, fmt.Errorf("not enough ports available, missing %d port(s)", numOfPorts-len(ports))
	}
	return ports, nil
}

func BuildPortRangeBPF(ports []net.Listener) string {
	var previousPort, port, lastWrittenPort int
	bpf := ""
	if len(ports) == 1 {
		return fmt.Sprintf("tcp dst port %d", ports[0].Addr().(*net.TCPAddr).Port)
	}
	for i, p := range ports {
		port = p.Addr().(*net.TCPAddr).Port
		if i == 0 {
			lastWrittenPort = port
			previousPort = port
			continue
		}
		isLastIteration := i == len(ports)-1
		if previousPort+1 != port || isLastIteration {
			if isLastIteration && previousPort+1 == port {
				previousPort = port
			}
			if lastWrittenPort == previousPort {
				if bpf == "" {
					bpf = fmt.Sprintf("tcp dst port %d", lastWrittenPort)
				} else {
					bpf += fmt.Sprintf(" or tcp dst port %d", lastWrittenPort)
				}
			} else {
				if bpf == "" {
					bpf = fmt.Sprintf("tcp dst portrange %d-%d", lastWrittenPort, previousPort)
				} else {
					bpf += fmt.Sprintf(" or tcp dst portrange %d-%d", lastWrittenPort, previousPort)
				}
			}

			if isLastIteration && port != previousPort {
				bpf += fmt.Sprintf(" or tcp dst port %d", port)
			}
			lastWrittenPort = port
		}
		previousPort = port
	}
	return bpf
}
