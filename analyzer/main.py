import polars as pl
import duckdb
import json
import os
import time
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./data/output")


# -----------------------------------------
# Задание 4: Импорт данных (Polars)
# -----------------------------------------
def load_data() -> pl.DataFrame:
    """Загружает все NDJSON файлы из output/ в Polars DataFrame."""
    files = list(Path(OUTPUT_DIR).glob("packets_*.ndjson"))
    if not files:
        raise FileNotFoundError(f"Нет NDJSON-файлов в {OUTPUT_DIR}")

    dfs = []
    for f in files:
        records = [json.loads(line) for line in open(f, encoding="utf-8")]
        dfs.append(pl.DataFrame(records))

    df = pl.concat(dfs)
    print(f"\n=== Задание 4: Загрузка данных ===")
    print(f"Строк: {len(df)}, Колонок: {len(df.columns)}")
    print(f"Типы данных:\n{df.dtypes}")
    print(f"\nПервые 5 строк:\n{df.head()}")
    return df


# -----------------------------------------
# Задание 5: Очистка и валидация
# -----------------------------------------
def clean_data(df: pl.DataFrame) -> pl.DataFrame:
    """Очистка: дубликаты, пропуски, типы."""
    print(f"\n=== Задание 5: Очистка данных ===")
    print(f"До очистки: {len(df)} строк")

    df = df.unique(subset=["id"])
    print(f"После удаления дубликатов: {len(df)} строк")

    df = df.with_columns([
        pl.col("timestamp").str.to_datetime(format="%+"),
        pl.col("src_port").cast(pl.Int32),
        pl.col("dst_port").cast(pl.Int32),
        pl.col("packet_size").cast(pl.Int32),
        pl.col("payload_size").cast(pl.Int32),
        pl.col("ttl").cast(pl.Int32),
    ])

    before = len(df)
    df = df.filter(pl.col("src_ip") != "0.0.0.0")
    print(f"Удалено пакетов с src_ip=0.0.0.0: {before - len(df)}")

    df = df.with_columns(
        pl.col("protocol").fill_null("UNKNOWN"),
        pl.col("flags").fill_null(""),
    )

    print(f"После очистки: {len(df)} строк")
    print(f"Пропуски:\n{df.null_count()}")
    return df


# -----------------------------------------
# Задание 6: Агрегационный анализ
# -----------------------------------------
def aggregate_analysis(df: pl.DataFrame):
    """Агрегация по протоколу, порту, IP."""
    print(f"\n=== Задание 6: Агрегационный анализ ===")

    by_protocol = df.group_by("protocol").agg([
        pl.len().alias("packet_count"),
        pl.col("packet_size").sum().alias("total_bytes"),
        pl.col("packet_size").mean().alias("avg_size"),
        pl.col("packet_size").min().alias("min_size"),
        pl.col("packet_size").max().alias("max_size"),
    ]).sort("packet_count", descending=True)
    print(f"\nПо протоколу:\n{by_protocol}")

    by_port = df.group_by("dst_port").agg([
        pl.len().alias("packet_count"),
        pl.col("packet_size").sum().alias("total_bytes"),
        pl.col("src_ip").n_unique().alias("unique_src_ips"),
    ]).sort("packet_count", descending=True).head(10)
    print(f"\nТоп-10 портов назначения:\n{by_port}")

    by_src_ip = df.group_by("src_ip").agg([
        pl.len().alias("packet_count"),
        pl.col("packet_size").sum().alias("total_bytes"),
        pl.col("dst_ip").n_unique().alias("unique_dst"),
        pl.col("dst_port").n_unique().alias("unique_ports"),
    ]).sort("packet_count", descending=True).head(10)
    print(f"\nТоп-10 источников:\n{by_src_ip}")

    tcp_df = df.filter(pl.col("protocol") == "TCP")
    if len(tcp_df) > 0:
        syn_count = tcp_df.filter(pl.col("flags").str.contains("SYN")).height
        rst_count = tcp_df.filter(pl.col("flags").str.contains("RST")).height
        fin_count = tcp_df.filter(pl.col("flags").str.contains("FIN")).height
        print(f"\nTCP флаги: SYN={syn_count}, RST={rst_count}, FIN={fin_count}")
        if rst_count > syn_count * 0.1:
            print("ВНИМАНИЕ: Высокий RST — возможное сканирование портов!")

    return by_protocol, by_port, by_src_ip


# -----------------------------------------
# Задание 7: Сохранение в Parquet
# -----------------------------------------
def save_parquet(df: pl.DataFrame):
    path = f"{OUTPUT_DIR}/packets.parquet"
    df.write_parquet(path)
    size_mb = os.path.getsize(path) / (1024 * 1024)
    print(f"\n=== Задание 7: Parquet ===")
    print(f"Сохранено в {path} ({size_mb:.2f} MB)")
    return path


# -----------------------------------------
# Задание 8: DuckDB анализ
# -----------------------------------------
def duckdb_analysis(parquet_path: str):
    print(f"\n=== Задание 8: DuckDB анализ ===")
    conn = duckdb.connect()

    t0 = time.perf_counter()
    result = conn.execute(f"""
        SELECT
            protocol,
            COUNT(*) as packet_count,
            SUM(packet_size) as total_bytes,
            AVG(packet_size) as avg_size,
            PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY packet_size) as median_size,
            COUNT(DISTINCT src_ip) as unique_src_ips
        FROM '{parquet_path}'
        WHERE src_ip != '0.0.0.0'
        GROUP BY protocol
        ORDER BY packet_count DESC
    """).fetchdf()
    duckdb_time = time.perf_counter() - t0
    print(f"DuckDB выполнен за {duckdb_time:.4f}с:")
    print(result)

    suspicious = conn.execute(f"""
        SELECT
            src_ip,
            COUNT(DISTINCT dst_port) as scanned_ports,
            COUNT(*) as total_packets,
            SUM(CASE WHEN flags LIKE '%RST%' THEN 1 ELSE 0 END) as rst_count
        FROM '{parquet_path}'
        GROUP BY src_ip
        HAVING COUNT(DISTINCT dst_port) > 5
        ORDER BY scanned_ports DESC
        LIMIT 10
    """).fetchdf()
    print(f"\nПодозрительные IP (сканирование портов):\n{suspicious}")

    timeline = conn.execute(f"""
        SELECT
            DATE_TRUNC('minute', CAST(timestamp AS TIMESTAMP)) as minute,
            COUNT(*) as packets,
            SUM(packet_size) as bytes
        FROM '{parquet_path}'
        GROUP BY 1
        ORDER BY 1
    """).fetchdf()
    print(f"\nТрафик по минутам (первые 5):\n{timeline.head()}")

    return result, suspicious, timeline


if __name__ == "__main__":
    df = load_data()
    df = clean_data(df)
    by_protocol, by_port, by_src_ip = aggregate_analysis(df)
    parquet_path = save_parquet(df)
    duckdb_analysis(parquet_path)
    print("\nАнализ завершён. Запустите visualize.py для графиков.")
