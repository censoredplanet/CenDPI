# CenDPI

## Requirements

- Go 1.23.2
- Root privileges (due to the need for raw socket access)

## Usage

### Flags

- `-config`: **Required** — Path to the YAML configuration file.

### Example Configuration - TCP Connection to Google


This example demonstrates a complete TCP connection with an HTTP request to Google. The configuration includes four packets that establish the connection, send a request, and gracefully close the connection.

---

```yaml
# yaml-language-server: $schema=./cendpi-schema.json

# Global settings
interface: en0                     # Network interface to use
pcapPath: results.pcap             # Where to save the packet capture
bpf: tcp and src host 142.251.40.195 and src port 80   # Capture filter for Google's responses
delay: 1                           # Wait 1 second for responses

packets:
  # Packet 1: TCP SYN
  - ethernet:
      srcMac: aa:bb:cc:dd:ee:ff    # Source MAC (your interface)
      dstMac: ff:ee:dd:cc:bb:aa    # Destination MAC (gateway)
    ip:
      srcIp: 192.168.178.2         # Source IP (your IP)
      dstIp: 142.251.40.195        # Destination IP (Google)
      tos: 0                       # Type of Service
      ttl: 64                      # Time to Live
    tcp:
      srcPort: 42344               # Source port (ephemeral)
      dstPort: 80                  # Destination port (HTTP)
      window: 65535                # TCP window size
      flags:
        syn: true                  # SYN flag for connection initiation

  # Packet 2: TCP ACK (for SYN-ACK)
  - ethernet: {...}                # Same MAC addresses as above
    ip: {...}                      # Same IP configuration
    tcp:
      srcPort: 42344 
      dstPort: 80
      window: 65535
      flags:
        ack: true                  # ACK flag to acknowledge SYN-ACK

  # Packet 3: HTTP GET Request
  - ethernet: {...}                # Same MAC addresses
    ip: {...}                      # Same IP configuration
    tcp:
      srcPort: 42344
      dstPort: 80
      window: 65535
      flags:
        psh: true                  # PSH flag to push data
        ack: true                  # ACK flag for previous packet
      data: R0VUIC8gSFRUUC8xLjEKSG9zdDogZ29vZ2xlLmNvbQpDb25uZWN0aW9uOiBjbG9zZQoK
            # Base64 encoded HTTP GET request:
            # GET / HTTP/1.1
            # Host: google.com
            # Connection: close
            #
            #

  # Packet 4: TCP FIN-ACK
  - ethernet: {...}                # Same MAC addresses
    ip: {...}                      # Same IP configuration
    tcp:
      srcPort: 42344
      dstPort: 80
      window: 65535
      flags:
        ack: true                  # ACK flag for received data
        fin: true                  # FIN flag to close connection

```
## Building the Program

### Locally

To build the program, run the following command in the project directory:

```bash
go build -o cendpi cmd/app/main.go
```

This will create an executable called `cendpi`.

### Example Usage

#### Running directly on the host machine

To run the program on your host machine (with root privileges):

```bash
sudo ./cendpi -config config.yml
```

#### macOS host machine

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


