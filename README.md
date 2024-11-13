# CenDPI

## Requirements

- Go 1.23.2
- Root privileges (due to the need for raw socket access)
- Docker (optional, but recommended to bypass the OS TCP stack)

## Usage

### Flags

- `-iface`: **Required** — Specifies the network interface to use (e.g., `eth0`).
- `-srcip`: **Required** — Source IP address for the TCP handshake.
- `-dstip`: **Required** — Destination IP address for the TCP handshake.
- `-gatewayip`: *Optional* — Gateway IP address.
- `-gatewaymac`: *Optional* — Gateway MAC address.
- `-srcport`: Optional — Source ephemeral port (default: `59152`). Must be in the range `32768–65535` for Linux or `49152–65535` for macOS.
- `-dstport`: Optional — Destination port (default: `80`). Only ports `80` (HTTP) and `443` (HTTPS) are allowed.kpfctl -s rules
- `-mode`: Optional — Connection to establish (default: `tcp`).
- `-pcapoutput`: Optional — File path to save the pcap capture (default: `output.pcap`).

**Note**: **One of `gatewayip` or `gatewaymac` must be provided.** 


## Building the Program

### Locally

To build the program, run the following command in the project directory:

```bash
go build -o cendpi cmd/app/main.go
```

This will create an executable called `cendpi`.

### Building a Docker container (recommended)

When running directly on the host machine, the OS TCP stack may drop the ACK packet crafted by the raw sockets. To bypass this restriction, you can use Docker with the appropriate settings.

To build the Docker image:

```bash
docker build -t cendpi:latest .
```

### Example Usage

#### Running directly on the host machine

To run the program on your host machine (with root privileges):

```bash
sudo ./cendpi -iface eth0 -srcip x.x.x.x -dstip x.x.x.x -srcport 49153 -dstport 80 -pcapoutput output.pcap
```

##### macOS host machine

To run directly on macOS, you can configure the firewall settings with `pfctl` to drop outgoing RST packets sent by the OS. You need to edit the `\etc\pf.conf` file (*remember to back up original configuration*), and add the following:

```
block drop out proto tcp flags R/R
```

Some helpful commands:
```
sudo pfctl -e   # enable pf

sudo pfctl -f /etc/pf.conf  # load filter rules

sudo pfctl -s all   # show all rules

sudo pfctl -d   # disable pf
```




#### Running using Docker (recommended)

First you will need to find the IP address range the container will be using. 
Therefore run:

```bash
 docker run --rm --network=host --entrypoint ip cendpi:latest addr  
```
And look for the `eth0` entry to find the ip address of the container. 
Use that address as the source ip address for the execution:

```bash
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network=host \
-v $(pwd)/results:/app/results \
cendpi:latest -iface eth0 -srcip x.x.x.x -dstip x.x.x.x -srcport 49153 -dstport 80 -pcapoutput /app/results/output.pcap
```

This will run the program within a Docker container, bypassing the OS TCP stack, and store the pcap output in the `results` folder on your execution path.

