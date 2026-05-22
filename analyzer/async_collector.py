"""
Задание 6 (повышенный уровень): Python asyncio/aiohttp сборщик PCAP.

Реализует параллельный разбор PCAP-файлов через asyncio + ProcessPoolExecutor
(аналог горутин в Go). Используется для сравнения производительности с
Go-сборщиком (см. benchmark.py).
"""

import asyncio
import json
import os
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PCAP_DIR = os.getenv("PCAP_DIR", "./data/samples")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./data/output")


# ── синхронный парсер (запускается в subprocess-пуле) ────────────────────────

def _parse_pcap_sync(path: str) -> list:
    """Разбирает один PCAP-файл с помощью scapy (синхронно, в пуле)."""
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP, ICMP

    try:
        packets = rdpcap(path)
    except Exception as e:
        print(f"[ASYNC-COLLECTOR] ошибка чтения {path}: {e}")
        return []

    records = []
    for pkt in packets:
        rec = {
            "id": str(uuid.uuid4()),
            "timestamp": str(pkt.time),
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "UNKNOWN",
            "packet_size": len(pkt),
            "ttl": 0,
            "flags": "",
            "payload_size": 0,
            "window_id": "",
        }

        if IP in pkt:
            rec["src_ip"] = pkt[IP].src
            rec["dst_ip"] = pkt[IP].dst
            rec["ttl"] = int(pkt[IP].ttl)
            rec["protocol"] = str(pkt[IP].proto)
            # window_id: усечение до минуты
            ts = int(float(pkt.time))
            rec["window_id"] = time.strftime("%Y-%m-%dT%H:%M:00Z", time.gmtime(ts - ts % 60))

        if TCP in pkt:
            rec["src_port"] = int(pkt[TCP].sport)
            rec["dst_port"] = int(pkt[TCP].dport)
            rec["protocol"] = "TCP"
            rec["payload_size"] = len(bytes(pkt[TCP].payload))
            flags = pkt[TCP].sprintf("%TCP.flags%")
            rec["flags"] = flags

        elif UDP in pkt:
            rec["src_port"] = int(pkt[UDP].sport)
            rec["dst_port"] = int(pkt[UDP].dport)
            rec["protocol"] = "UDP"
            rec["payload_size"] = len(bytes(pkt[UDP].payload))

        elif ICMP in pkt:
            rec["protocol"] = "ICMP"

        records.append(rec)
    return records


# ── asyncio-обёртка ───────────────────────────────────────────────────────────

async def _parse_pcap_async(path: str, executor: ProcessPoolExecutor) -> list:
    """Запускает синхронный парсер в пуле процессов (неблокирующий вызов)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, _parse_pcap_sync, path)


async def collect_all_async(pcap_dir: str = PCAP_DIR) -> tuple:
    """
    Параллельно обрабатывает все .pcap файлы через asyncio.gather().
    Возвращает (список записей, время выполнения в секундах).
    """
    files = list(Path(pcap_dir).glob("*.pcap"))
    if not files:
        raise FileNotFoundError(f"Нет PCAP-файлов в {pcap_dir}")

    print(f"[ASYNC-COLLECTOR] найдено {len(files)} файлов, запуск параллельного разбора...")
    t0 = time.perf_counter()

    # ProcessPoolExecutor позволяет обойти GIL — каждый файл в своём процессе
    with ProcessPoolExecutor(max_workers=max(len(files), 1)) as executor:
        tasks = [_parse_pcap_async(str(f), executor) for f in files]
        results = await asyncio.gather(*tasks)

    all_records = [rec for batch in results for rec in batch]
    elapsed = time.perf_counter() - t0

    print(
        f"[ASYNC-COLLECTOR] {len(files)} файлов → {len(all_records)} пакетов "
        f"за {elapsed:.3f}с ({len(all_records)/elapsed:.0f} pkt/s)"
    )
    return all_records, elapsed


def save_results(records: list, output_dir: str = OUTPUT_DIR) -> str:
    """Сохраняет результаты в NDJSON (аналогично Go-сборщику)."""
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(output_dir, f"async_packets_{int(time.time())}.ndjson")
    with open(filename, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    size_kb = os.path.getsize(filename) / 1024
    print(f"[ASYNC-COLLECTOR] сохранено {len(records)} записей в {filename} ({size_kb:.1f} KB)")
    return filename


if __name__ == "__main__":
    records, _ = asyncio.run(collect_all_async())
    save_results(records)
