package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
)

type PacketRecord struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     int       `json:"src_port"`
	DstPort     int       `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	PacketSize  int       `json:"packet_size"`
	TTL         int       `json:"ttl"`
	Flags       string    `json:"flags"`
	PayloadSize int       `json:"payload_size"`
	WindowID    string    `json:"window_id"`
}

func parsePCAP(path string, ch chan<- PacketRecord, wg *sync.WaitGroup) {
	defer wg.Done()
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		log.Printf("[COLLECTOR] ошибка открытия %s: %v", path, err)
		return
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		rec := extractRecord(packet)
		ch <- rec
	}
	log.Printf("[COLLECTOR] обработан файл: %s", path)
}

func extractRecord(packet gopacket.Packet) PacketRecord {
	rec := PacketRecord{
		ID:         uuid.New().String(),
		Timestamp:  packet.Metadata().Timestamp,
		PacketSize: packet.Metadata().Length,
		WindowID:   packet.Metadata().Timestamp.Truncate(60 * time.Second).Format(time.RFC3339),
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		rec.SrcIP = ip.SrcIP.String()
		rec.DstIP = ip.DstIP.String()
		rec.TTL = int(ip.TTL)
		rec.Protocol = ip.Protocol.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		rec.SrcPort = int(tcp.SrcPort)
		rec.DstPort = int(tcp.DstPort)
		rec.Protocol = "TCP"
		rec.PayloadSize = len(tcp.Payload)
		flags := ""
		if tcp.SYN {
			flags += "SYN "
		}
		if tcp.ACK {
			flags += "ACK "
		}
		if tcp.FIN {
			flags += "FIN "
		}
		if tcp.RST {
			flags += "RST "
		}
		rec.Flags = strings.TrimSpace(flags)
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		rec.SrcPort = int(udp.SrcPort)
		rec.DstPort = int(udp.DstPort)
		rec.Protocol = "UDP"
		rec.PayloadSize = len(udp.Payload)
	}

	return rec
}

func writeWorker(ch <-chan PacketRecord, outputDir string, done chan struct{}) {
	const batchSize = 100
	const flushInterval = 5 * time.Second

	batch := make([]PacketRecord, 0, batchSize)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		filename := filepath.Join(outputDir,
			fmt.Sprintf("packets_%s.ndjson", time.Now().Format("20060102_150405")))
		f, err := os.Create(filename)
		if err != nil {
			log.Printf("[WRITER] ошибка создания файла: %v", err)
			return
		}
		enc := json.NewEncoder(f)
		for _, rec := range batch {
			enc.Encode(rec)
		}
		f.Close()
		log.Printf("[WRITER] записано %d пакетов в %s", len(batch), filename)
		batch = batch[:0]
	}

	for {
		select {
		case rec, ok := <-ch:
			if !ok {
				flush()
				close(done)
				return
			}
			batch = append(batch, rec)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func writeWindowWorker(ch <-chan WindowAgg, outputDir string, done chan struct{}) {
	filename := filepath.Join(outputDir,
		fmt.Sprintf("windows_%s.ndjson", time.Now().Format("20060102_150405")))
	f, err := os.Create(filename)
	if err != nil {
		log.Printf("[WINDOW-WRITER] ошибка создания файла: %v", err)
		close(done)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	count := 0
	for agg := range ch {
		enc.Encode(agg)
		count++
	}
	log.Printf("[WINDOW-WRITER] записано %d окон в %s", count, filename)
	close(done)
}

func main() {
	windowed := flag.Bool("windowed", false, "запустить оконную агрегацию вместо записи сырых пакетов")
	serveArrow := flag.Bool("serve-arrow", false, "запустить Arrow HTTP сервер")
	natsMode := flag.Bool("nats", false, "публиковать пакеты в NATS (требует запущенного NATS-сервера)")
	etcdMode := flag.Bool("etcd", false, "включить etcd-координацию для распределения шардов между инстансами")
	etcdEndpoints := flag.String("etcd-endpoints", "localhost:2379", "адреса etcd через запятую")
	flag.Parse()

	pcapDir := os.Getenv("PCAP_DIR")
	if pcapDir == "" {
		pcapDir = "./data/samples"
	}
	outputDir := os.Getenv("OUTPUT_DIR")
	if outputDir == "" {
		outputDir = "./data/output"
	}
	arrowPort := os.Getenv("ARROW_SERVER_PORT")
	if arrowPort == "" {
		arrowPort = "8815"
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("[COLLECTOR] не удалось создать директорию %s: %v", outputDir, err)
	}

	files, err := filepath.Glob(filepath.Join(pcapDir, "*.pcap"))
	if err != nil {
		log.Fatalf("[COLLECTOR] ошибка поиска файлов: %v", err)
	}
	if len(files) == 0 {
		log.Fatal("[COLLECTOR] нет .pcap файлов в директории")
	}
	log.Printf("[COLLECTOR] найдено %d PCAP-файлов", len(files))

	// Etcd-координация: регистрируем инстанс и получаем назначенный шард файлов.
	if *etcdMode {
		endpoints := strings.Split(*etcdEndpoints, ",")
		coord, coordErr := NewEtcdCoordinator(endpoints)
		if coordErr != nil {
			log.Printf("[ETCD] не удалось подключиться (%v) — обрабатываю все файлы", coordErr)
		} else {
			defer coord.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if regErr := coord.Register(ctx); regErr != nil {
				log.Printf("[ETCD] ошибка регистрации (%v) — обрабатываю все файлы", regErr)
			} else {
				shardCtx, shardCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shardCancel()
				if shard, shardErr := coord.GetShard(shardCtx, files); shardErr == nil {
					files = shard
				}
			}
		}
	}

	ch := make(chan PacketRecord, 1000)
	done := make(chan struct{})
	var wg sync.WaitGroup

	if *natsMode {
		RunNATSProducer(pcapDir)
		return
	}

	if *serveArrow {
		// Сначала собираем все пакеты, потом запускаем сервер
		var allPackets []PacketRecord
		var mu sync.Mutex

		go func() {
			for rec := range ch {
				mu.Lock()
				allPackets = append(allPackets, rec)
				mu.Unlock()
			}
			close(done)
		}()

		for _, f := range files {
			wg.Add(1)
			go parsePCAP(f, ch, &wg)
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			wg.Wait()
			close(ch)
		}()

		select {
		case <-sig:
			log.Println("[COLLECTOR] получен сигнал завершения")
			<-done // ждём, пока потребитель вычитает ch и закроет done
		case <-done:
		}

		log.Printf("[COLLECTOR] собрано %d пакетов, запускаю Arrow-сервер", len(allPackets))
		ServeArrow(allPackets, arrowPort)
		return
	}

	if *windowed {
		windowCh := make(chan WindowAgg, 100)
		windowDone := make(chan struct{})

		go func() {
			TumblingWindowProcessor(ch, windowCh, 60*time.Second)
		}()
		go writeWindowWorker(windowCh, outputDir, windowDone)

		for _, f := range files {
			wg.Add(1)
			go parsePCAP(f, ch, &wg)
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			wg.Wait()
			close(ch)
		}()

		select {
		case <-sig:
			log.Println("[COLLECTOR] получен сигнал завершения, дожидаюсь записи буфера...")
			<-windowDone // ждём, пока горутина закроет ch и окна запишутся
		case <-windowDone:
		}
		log.Println("[COLLECTOR] оконная агрегация завершена корректно")
		return
	}

	go writeWorker(ch, outputDir, done)

	for _, f := range files {
		wg.Add(1)
		go parsePCAP(f, ch, &wg)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		wg.Wait()
		close(ch)
	}()

	select {
	case <-sig:
		log.Println("[COLLECTOR] получен сигнал завершения, дожидаюсь записи буфера...")
		<-done // ждём, пока writeWorker вычитает буфер и закроет done
	case <-done:
	}
	log.Println("[COLLECTOR] завершено корректно")
}
