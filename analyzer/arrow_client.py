import pyarrow as pa
import pyarrow.ipc as ipc
import polars as pl
import requests
import io
import json
import os
import time
from dotenv import load_dotenv

load_dotenv()

ARROW_PORT = os.getenv("ARROW_SERVER_PORT", "8815")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./data/output")


def fetch_arrow_data(port: str = ARROW_PORT) -> pl.DataFrame:
    """Получает данные от Go Arrow-сервера и возвращает Polars DataFrame."""
    t0 = time.perf_counter()

    url = f"http://localhost:{port}/packets"
    resp = requests.get(url, stream=True)
    resp.raise_for_status()

    reader = ipc.open_stream(pa.py_buffer(resp.content))
    table = reader.read_all()
    df = pl.from_arrow(table)

    elapsed = time.perf_counter() - t0
    print(f"[ARROW-CLIENT] получено {len(df)} пакетов за {elapsed:.3f}с")
    print(f"[ARROW-CLIENT] размер данных: {len(resp.content)} байт")
    return df


def compare_performance():
    """Сравнение: Arrow vs JSON файлы по скорости загрузки."""
    # Тест 1: Arrow
    t0 = time.perf_counter()
    df_arrow = fetch_arrow_data()
    arrow_time = time.perf_counter() - t0

    # Тест 2: JSON файлы
    t0 = time.perf_counter()
    records = []
    for f in os.listdir(OUTPUT_DIR):
        if f.endswith(".ndjson"):
            with open(os.path.join(OUTPUT_DIR, f), encoding="utf-8") as fp:
                for line in fp:
                    records.append(json.loads(line))
    df_json = pl.DataFrame(records) if records else pl.DataFrame()
    json_time = time.perf_counter() - t0

    print(f"\n=== Сравнение производительности ===")
    print(f"Arrow IPC: {arrow_time:.3f}с  ({len(df_arrow)} записей)")
    print(f"JSON файлы: {json_time:.3f}с ({len(df_json)} записей)")
    if arrow_time > 0:
        print(f"Ускорение Arrow: {json_time / arrow_time:.1f}x")

    return {
        "arrow_seconds": arrow_time,
        "json_seconds": json_time,
        "speedup": json_time / arrow_time if arrow_time > 0 else 0,
    }


if __name__ == "__main__":
    df = fetch_arrow_data()
    print(df.head())
    compare_performance()
