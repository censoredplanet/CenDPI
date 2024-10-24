FROM golang:1.23.2

RUN apt-get update && apt-get install -y libpcap-dev iproute2

WORKDIR /app

RUN mkdir /app/results

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -o cendpi cmd/app/main.go

# Expose the required capabilities (NET_RAW and NET_ADMIN) for packet capture and raw socket access
RUN setcap cap_net_raw,cap_net_admin=eip /app/cendpi

ENTRYPOINT ["/app/cendpi"]
