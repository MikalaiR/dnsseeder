FROM golang:1.11-alpine as builder
ENV CGO_ENABLED 0

RUN apk add --no-cache git
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o dnsseeder *.go

FROM scratch
WORKDIR /app
COPY --from=builder /build/dnsseeder .
ENTRYPOINT ["./dnsseeder", "-netfile", "configs/bitcoin.yml", "-listen", ":53"]
