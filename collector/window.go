package main

import (
	"strings"
	"time"
)

type WindowAgg struct {
	WindowStart    time.Time      `json:"window_start"`
	WindowEnd      time.Time      `json:"window_end"`
	TotalPackets   int            `json:"total_packets"`
	TotalBytes     int            `json:"total_bytes"`
	UniqueSrcIPs   int            `json:"unique_src_ips"`
	UniqueDstIPs   int            `json:"unique_dst_ips"`
	ProtocolCounts map[string]int `json:"protocol_counts"`
	TopSrcIP       string         `json:"top_src_ip"`
	TopDstPort     int            `json:"top_dst_port"`
	AvgPacketSize  float64        `json:"avg_packet_size"`
	MaxPacketSize  int            `json:"max_packet_size"`
	MinPacketSize  int            `json:"min_packet_size"`
	TCPSynCount    int            `json:"tcp_syn_count"`
	TCPFinCount    int            `json:"tcp_fin_count"`
	TCPRstCount    int            `json:"tcp_rst_count"`
}

func aggregateWindow(packets []PacketRecord, start, end time.Time) WindowAgg {
	agg := WindowAgg{
		WindowStart:    start,
		WindowEnd:      end,
		ProtocolCounts: map[string]int{},
		MinPacketSize:  int(^uint(0) >> 1),
	}

	srcIPCount := map[string]int{}
	dstIPSet := map[string]bool{}
	dstPortCount := map[int]int{}

	for _, p := range packets {
		agg.TotalPackets++
		agg.TotalBytes += p.PacketSize
		agg.ProtocolCounts[p.Protocol]++
		srcIPCount[p.SrcIP]++
		dstIPSet[p.DstIP] = true
		dstPortCount[p.DstPort]++

		if p.PacketSize > agg.MaxPacketSize {
			agg.MaxPacketSize = p.PacketSize
		}
		if p.PacketSize < agg.MinPacketSize {
			agg.MinPacketSize = p.PacketSize
		}

		if strings.Contains(p.Flags, "SYN") {
			agg.TCPSynCount++
		}
		if strings.Contains(p.Flags, "FIN") {
			agg.TCPFinCount++
		}
		if strings.Contains(p.Flags, "RST") {
			agg.TCPRstCount++
		}
	}

	if agg.TotalPackets > 0 {
		agg.AvgPacketSize = float64(agg.TotalBytes) / float64(agg.TotalPackets)
	} else {
		agg.MinPacketSize = 0
	}
	agg.UniqueSrcIPs = len(srcIPCount)
	agg.UniqueDstIPs = len(dstIPSet)

	maxCount := 0
	for ip, c := range srcIPCount {
		if c > maxCount {
			maxCount = c
			agg.TopSrcIP = ip
		}
	}
	maxCount = 0
	for port, c := range dstPortCount {
		if c > maxCount {
			maxCount = c
			agg.TopDstPort = port
		}
	}

	return agg
}

func TumblingWindowProcessor(in <-chan PacketRecord, out chan<- WindowAgg, windowSize time.Duration) {
	windows := map[string][]PacketRecord{}

	for rec := range in {
		windowKey := rec.Timestamp.Truncate(windowSize).Format(time.RFC3339)
		windows[windowKey] = append(windows[windowKey], rec)
	}

	for keyStr, packets := range windows {
		start, _ := time.Parse(time.RFC3339, keyStr)
		end := start.Add(windowSize)
		agg := aggregateWindow(packets, start, end)
		out <- agg
	}
	close(out)
}
