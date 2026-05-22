"""
Задание 7 (повышенный уровень): Python NATS-консьюмер со скользящим окном.

Получает пакеты от Go-продюсера через NATS, агрегирует их в скользящем окне
(по умолчанию 5 минут) и каждые 10 секунд печатает статистику.

Запуск:
    # Терминал 1 — запустить NATS:
    docker run -p 4222:4222 nats:2.10-alpine
    # или: docker compose -f docker/docker-compose.yml up nats

    # Терминал 2 — запустить Go-продюсер:
    go run collector/main.go collector/window.go \\
       collector/arrow_server.go collector/nats_producer.go --nats

    # Терминал 3 — запустить этот консьюмер:
    python analyzer/nats_consumer.py
"""

import asyncio
import json
import os
import time
from collections import defaultdict, deque

from dotenv import load_dotenv

load_dotenv()

NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
SUBJECT = "pcap.packets"
WINDOW_SECONDS = int(os.getenv("WINDOW_SIZE_SECONDS", "300"))  # 5 минут
STATS_INTERVAL = 10  # секунды между выводом статистики


def _compute_window_stats(window: deque) -> dict:
    """Агрегирует содержимое скользящего окна."""
    if not window:
        return {}

    proto_counts: dict = defaultdict(int)
    total_bytes = 0
    unique_src: set = set()
    unique_dst_ports: set = set()
    syn_count = fin_count = rst_count = 0

    for rec in window:
        proto_counts[rec.get("protocol", "UNKNOWN")] += 1
        total_bytes += rec.get("packet_size", 0)
        if rec.get("src_ip"):
            unique_src.add(rec["src_ip"])
        if rec.get("dst_port"):
            unique_dst_ports.add(rec["dst_port"])
        flags = rec.get("flags", "")
        if "SYN" in flags:
            syn_count += 1
        if "FIN" in flags:
            fin_count += 1
        if "RST" in flags:
            rst_count += 1

    return {
        "packets": len(window),
        "bytes": total_bytes,
        "unique_src_ips": len(unique_src),
        "unique_dst_ports": len(unique_dst_ports),
        "protocols": dict(proto_counts),
        "tcp_syn": syn_count,
        "tcp_fin": fin_count,
        "tcp_rst": rst_count,
    }


async def run_consumer() -> None:
    import nats as nats_lib

    nc = await nats_lib.connect(
        NATS_URL,
        name="pcap-sliding-window-consumer",
        reconnected_cb=lambda nc: print(f"[CONSUMER] переподключён к {nc.connected_url}"),
        disconnected_cb=lambda: print("[CONSUMER] отключение от NATS"),
        error_cb=lambda e: print(f"[CONSUMER] ошибка NATS: {e}"),
    )
    print(f"[CONSUMER] подключён к {NATS_URL}")
    print(f"[CONSUMER] скользящее окно: {WINDOW_SECONDS}с | интервал вывода: {STATS_INTERVAL}с")

    window: deque = deque()
    total_received = 0

    async def on_message(msg) -> None:
        nonlocal total_received
        try:
            rec = json.loads(msg.data.decode())
            rec["_recv_at"] = time.monotonic()
            window.append(rec)
            total_received += 1
        except json.JSONDecodeError as e:
            print(f"[CONSUMER] невалидный JSON: {e}")

    sub = await nc.subscribe(SUBJECT, cb=on_message)
    print(f"[CONSUMER] подписан на '{SUBJECT}', ожидание пакетов...")

    try:
        while True:
            await asyncio.sleep(STATS_INTERVAL)

            # Выселяем устаревшие записи из окна
            now = time.monotonic()
            cutoff = now - WINDOW_SECONDS
            evicted = 0
            while window and window[0]["_recv_at"] < cutoff:
                window.popleft()
                evicted += 1

            stats = _compute_window_stats(window)
            if not stats:
                print(f"[CONSUMER] {time.strftime('%H:%M:%S')} — окно пусто "
                      f"(всего получено: {total_received})")
                continue

            print(
                f"\n{'='*55}\n"
                f"  Скользящее окно {WINDOW_SECONDS}с — {time.strftime('%H:%M:%S')}\n"
                f"{'='*55}\n"
                f"  Пакетов в окне:           {stats['packets']}\n"
                f"  Всего получено:           {total_received}\n"
                f"  Байт в окне:              {stats['bytes']:,}\n"
                f"  Уникальных IP-источников: {stats['unique_src_ips']}\n"
                f"  Уникальных dst-портов:    {stats['unique_dst_ports']}\n"
                f"  Протоколы:                {stats['protocols']}\n"
                f"  TCP SYN/FIN/RST:          {stats['tcp_syn']}/{stats['tcp_fin']}/{stats['tcp_rst']}\n"
                f"  Выселено из окна:         {evicted}"
            )

            # Предупреждение о возможном сканировании
            rst = stats["tcp_rst"]
            syn = stats["tcp_syn"]
            if rst > 0 and syn > 0 and rst > syn * 0.15:
                print(f"  ⚠ ВНИМАНИЕ: RST/SYN = {rst/syn:.1%} — возможное сканирование портов!")

    except asyncio.CancelledError:
        pass
    finally:
        await sub.unsubscribe()
        await nc.drain()
        print(f"\n[CONSUMER] завершение. Всего получено пакетов: {total_received}")


if __name__ == "__main__":
    try:
        asyncio.run(run_consumer())
    except KeyboardInterrupt:
        print("\n[CONSUMER] прерван пользователем")
