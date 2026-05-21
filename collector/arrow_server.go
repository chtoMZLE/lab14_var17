package main

import (
	"log"
	"net/http"

	"github.com/apache/arrow/go/v14/arrow"
	"github.com/apache/arrow/go/v14/arrow/array"
	"github.com/apache/arrow/go/v14/arrow/ipc"
	"github.com/apache/arrow/go/v14/arrow/memory"
)

func buildArrowBatch(packets []PacketRecord) arrow.Record {
	pool := memory.NewGoAllocator()

	schema := arrow.NewSchema([]arrow.Field{
		{Name: "id", Type: arrow.BinaryTypes.String},
		{Name: "timestamp", Type: arrow.FixedWidthTypes.Timestamp_us},
		{Name: "src_ip", Type: arrow.BinaryTypes.String},
		{Name: "dst_ip", Type: arrow.BinaryTypes.String},
		{Name: "src_port", Type: arrow.PrimitiveTypes.Int32},
		{Name: "dst_port", Type: arrow.PrimitiveTypes.Int32},
		{Name: "protocol", Type: arrow.BinaryTypes.String},
		{Name: "packet_size", Type: arrow.PrimitiveTypes.Int32},
		{Name: "payload_size", Type: arrow.PrimitiveTypes.Int32},
		{Name: "ttl", Type: arrow.PrimitiveTypes.Int32},
		{Name: "flags", Type: arrow.BinaryTypes.String},
	}, nil)

	b := array.NewRecordBuilder(pool, schema)
	defer b.Release()

	for _, p := range packets {
		b.Field(0).(*array.StringBuilder).Append(p.ID)
		b.Field(1).(*array.TimestampBuilder).Append(arrow.Timestamp(p.Timestamp.UnixMicro()))
		b.Field(2).(*array.StringBuilder).Append(p.SrcIP)
		b.Field(3).(*array.StringBuilder).Append(p.DstIP)
		b.Field(4).(*array.Int32Builder).Append(int32(p.SrcPort))
		b.Field(5).(*array.Int32Builder).Append(int32(p.DstPort))
		b.Field(6).(*array.StringBuilder).Append(p.Protocol)
		b.Field(7).(*array.Int32Builder).Append(int32(p.PacketSize))
		b.Field(8).(*array.Int32Builder).Append(int32(p.PayloadSize))
		b.Field(9).(*array.Int32Builder).Append(int32(p.TTL))
		b.Field(10).(*array.StringBuilder).Append(p.Flags)
	}

	return b.NewRecord()
}

func ServeArrow(packets []PacketRecord, port string) {
	http.HandleFunc("/packets", func(w http.ResponseWriter, r *http.Request) {
		batch := buildArrowBatch(packets)
		defer batch.Release()

		w.Header().Set("Content-Type", "application/vnd.apache.arrow.stream")
		writer := ipc.NewWriter(w, ipc.WithSchema(batch.Schema()))
		defer writer.Close()
		writer.Write(batch)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("[ARROW-SERVER] слушаю на порту %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
