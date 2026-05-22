package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

const natsSubjectPackets = "pcap.packets"

// NATSProducer оборачивает NATS-соединение и публикует PacketRecord.
type NATSProducer struct {
	nc *nats.Conn
}

func newNATSProducer(url string) (*NATSProducer, error) {
	nc, err := nats.Connect(
		url,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(5),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Printf("[NATS] отключение: %v", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Printf("[NATS] переподключение к %s", nc.ConnectedUrl())
		}),
	)
	if err != nil {
		return nil, err
	}
	log.Printf("[NATS] подключён к %s", nc.ConnectedUrl())
	return &NATSProducer{nc: nc}, nil
}

func (p *NATSProducer) publish(rec PacketRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return p.nc.Publish(natsSubjectPackets, data)
}

func (p *NATSProducer) close() {
	if err := p.nc.Drain(); err != nil {
		log.Printf("[NATS] ошибка drain: %v", err)
	}
	log.Println("[NATS] соединение закрыто")
}

// RunNATSProducer читает PCAP-файлы и публикует каждый пакет в NATS.
func RunNATSProducer(pcapDir string) {
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL // nats://localhost:4222
	}

	producer, err := newNATSProducer(natsURL)
	if err != nil {
		log.Fatalf("[NATS] ошибка подключения: %v", err)
	}
	defer producer.close()

	files, err := filepath.Glob(filepath.Join(pcapDir, "*.pcap"))
	if err != nil || len(files) == 0 {
		log.Fatal("[NATS] нет .pcap файлов в директории")
	}
	log.Printf("[NATS] публикация %d файлов в subject '%s'", len(files), natsSubjectPackets)

	ch := make(chan PacketRecord, 1000)
	var wg sync.WaitGroup

	for _, f := range files {
		wg.Add(1)
		go parsePCAP(f, ch, &wg)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	published := 0
	errors := 0
	for rec := range ch {
		if err := producer.publish(rec); err != nil {
			log.Printf("[NATS] ошибка публикации: %v", err)
			errors++
		} else {
			published++
		}
	}

	log.Printf("[NATS] опубликовано: %d пакетов, ошибок: %d", published, errors)
}
