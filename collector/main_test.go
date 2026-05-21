package main

import (
	"testing"
	"time"
)

func TestAggregateWindow(t *testing.T) {
	packets := []PacketRecord{
		{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", Protocol: "TCP",
			PacketSize: 100, PayloadSize: 80, Flags: "SYN",
			Timestamp: time.Now()},
		{SrcIP: "1.1.1.1", DstIP: "3.3.3.3", Protocol: "UDP",
			PacketSize: 200, PayloadSize: 180,
			Timestamp: time.Now()},
	}
	start := time.Now().Truncate(time.Minute)
	end := start.Add(time.Minute)
	agg := aggregateWindow(packets, start, end)

	if agg.TotalPackets != 2 {
		t.Errorf("ожидалось 2, получено %d", agg.TotalPackets)
	}
	if agg.TotalBytes != 300 {
		t.Errorf("ожидалось 300, получено %d", agg.TotalBytes)
	}
	if agg.UniqueSrcIPs != 1 {
		t.Errorf("ожидался 1 уникальный src IP, получено %d", agg.UniqueSrcIPs)
	}
	if agg.TCPSynCount != 1 {
		t.Errorf("ожидался 1 SYN, получено %d", agg.TCPSynCount)
	}
	if agg.AvgPacketSize != 150.0 {
		t.Errorf("ожидалось avg=150, получено %f", agg.AvgPacketSize)
	}
}

func TestAggregateWindowEmpty(t *testing.T) {
	start := time.Now().Truncate(time.Minute)
	end := start.Add(time.Minute)
	agg := aggregateWindow([]PacketRecord{}, start, end)

	if agg.TotalPackets != 0 {
		t.Errorf("ожидалось 0 пакетов, получено %d", agg.TotalPackets)
	}
	if agg.MinPacketSize != 0 {
		t.Errorf("MinPacketSize для пустого окна должен быть 0, получено %d", agg.MinPacketSize)
	}
}

func TestTumblingWindowGroups(t *testing.T) {
	t1 := time.Date(2024, 1, 1, 10, 0, 30, 0, time.UTC)
	t2 := time.Date(2024, 1, 1, 10, 1, 30, 0, time.UTC)
	packets := []PacketRecord{
		{ID: "1", Timestamp: t1, PacketSize: 100, Protocol: "TCP", SrcIP: "1.1.1.1"},
		{ID: "2", Timestamp: t1, PacketSize: 200, Protocol: "UDP", SrcIP: "2.2.2.2"},
		{ID: "3", Timestamp: t2, PacketSize: 300, Protocol: "TCP", SrcIP: "3.3.3.3"},
	}

	in := make(chan PacketRecord, 10)
	out := make(chan WindowAgg, 10)

	for _, p := range packets {
		in <- p
	}
	close(in)

	TumblingWindowProcessor(in, out, time.Minute)

	windows := []WindowAgg{}
	for w := range out {
		windows = append(windows, w)
	}

	if len(windows) != 2 {
		t.Errorf("ожидалось 2 окна, получено %d", len(windows))
	}

	totalPackets := 0
	for _, w := range windows {
		totalPackets += w.TotalPackets
	}
	if totalPackets != 3 {
		t.Errorf("суммарно должно быть 3 пакета, получено %d", totalPackets)
	}
}

func TestExtractRecordDefaults(t *testing.T) {
	// Проверяем, что WindowID правильно усекается до минуты
	rec := PacketRecord{
		Timestamp: time.Date(2024, 1, 15, 10, 23, 41, 0, time.UTC),
		WindowID:  time.Date(2024, 1, 15, 10, 23, 41, 0, time.UTC).Truncate(60 * time.Second).Format(time.RFC3339),
	}

	expected := "2024-01-15T10:23:00Z"
	if rec.WindowID != expected {
		t.Errorf("ожидалось WindowID=%s, получено %s", expected, rec.WindowID)
	}
}
