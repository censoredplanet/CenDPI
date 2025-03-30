# CenDPI

## Requirements

- Go 1.23.2
- Root privileges (due to the need for raw socket access)

## Usage

### Flags

- `-config`: **Required** — Path to the global configuration file (e.g., measurement_http.yml).
- `-target`: **Required** — Path to the target configuration file (e.g., targets.jsonl).
- `-resultPath`: **Required** — Path to the result file (e.g., result.jsonl).
- `-rounds`: **optional** — Send each probe N times.
- `-concurrency`: **optional** — Number of concurrent measurements.

## Building the Program

### Locally

To build the program, run the following command in the project directory:

```bash
go build -o cendpi cmd/app/main.go
```

This will create an executable called `cendpi`.

### Example Usage

#### Drop outgoing RSTs (required)

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

#### Turn off segmentation offloading (optional)

```bash
sudo ethtool -K <interface> gro off gso off tso off
```

#### Running directly on the host machine

To run the program on your host machine (with root privileges):

```bash
sudo ./cendpi -config measurement_https.yml -target targets.jsonl -resultPath result.jsonl -rounds 3 -concurrency 1000
```

