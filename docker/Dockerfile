# ── Стадия 1: сборка Go-бинарника ────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

# libpcap-dev нужен для github.com/google/gopacket/pcap
RUN apk add --no-cache libpcap-dev gcc musl-dev

WORKDIR /build

# Кешируем зависимости отдельным слоем
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходники коллектора
COPY collector/ collector/

RUN CGO_ENABLED=1 GOOS=linux go build \
        -ldflags="-s -w" \
        -o /build/collector \
        ./collector/...

# ── Стадия 2: минимальный runtime-образ ──────────────────────────────────────
FROM alpine:3.18

# libpcap нужен в runtime (динамическая линковка)
RUN apk add --no-cache libpcap ca-certificates

WORKDIR /app

COPY --from=builder /build/collector ./collector

# Директории для данных (монтируются через PVC в Kubernetes)
RUN mkdir -p /data/samples /data/output

ENV PCAP_DIR=/data/samples \
    OUTPUT_DIR=/data/output \
    ARROW_SERVER_PORT=8815 \
    NATS_URL=nats://nats:4222

EXPOSE 8815

ENTRYPOINT ["./collector"]
# Режим по умолчанию: Arrow HTTP сервер
CMD ["--serve-arrow"]
