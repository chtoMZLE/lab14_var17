import polars as pl
import duckdb
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
import os

OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./data/output")
PARQUET = f"{OUTPUT_DIR}/packets.parquet"


def plot_protocol_distribution():
    """График 1: Распределение пакетов по протоколам (pie + bar)."""
    conn = duckdb.connect()
    df = conn.execute(f"""
        SELECT protocol, COUNT(*) as count, SUM(packet_size) as total_bytes
        FROM '{PARQUET}'
        GROUP BY protocol
        ORDER BY count DESC
    """).fetchdf()

    fig = make_subplots(rows=1, cols=2,
        subplot_titles=["Пакеты по протоколу", "Байты по протоколу"],
        specs=[[{"type": "pie"}, {"type": "bar"}]])

    fig.add_trace(go.Pie(labels=df["protocol"], values=df["count"], name="пакеты"), row=1, col=1)
    fig.add_trace(go.Bar(x=df["protocol"], y=df["total_bytes"], name="байты"), row=1, col=2)

    fig.update_layout(title="Распределение трафика по протоколам", height=400)
    fig.write_html(f"{OUTPUT_DIR}/chart_protocols.html")
    fig.write_image(f"{OUTPUT_DIR}/chart_protocols.png")
    print(f"График 1 сохранён: chart_protocols.png")


def plot_traffic_timeline():
    """График 2: Временной ряд трафика (пакеты в минуту)."""
    conn = duckdb.connect()
    df = conn.execute(f"""
        SELECT
            DATE_TRUNC('minute', CAST(timestamp AS TIMESTAMP)) as minute,
            COUNT(*) as packets,
            SUM(packet_size) as bytes,
            protocol
        FROM '{PARQUET}'
        GROUP BY 1, 4
        ORDER BY 1
    """).fetchdf()

    fig = px.area(df, x="minute", y="packets", color="protocol",
        title="Трафик по времени (пакеты в минуту)",
        labels={"minute": "Время", "packets": "Пакеты", "protocol": "Протокол"})
    fig.write_html(f"{OUTPUT_DIR}/chart_timeline.html")
    fig.write_image(f"{OUTPUT_DIR}/chart_timeline.png")
    print(f"График 2 сохранён: chart_timeline.png")


def plot_top_ips_heatmap():
    """График 3: Тепловая карта src_ip → dst_port (аномалии)."""
    conn = duckdb.connect()
    df = conn.execute(f"""
        SELECT src_ip, dst_port, COUNT(*) as count
        FROM '{PARQUET}'
        WHERE protocol = 'TCP'
        GROUP BY src_ip, dst_port
        HAVING COUNT(*) > 2
        ORDER BY count DESC
        LIMIT 200
    """).fetchdf()

    if df.empty:
        print("График 3 пропущен: нет TCP-данных для тепловой карты")
        return

    pivot = df.pivot_table(index="src_ip", columns="dst_port", values="count", fill_value=0)
    fig, ax = plt.subplots(figsize=(14, 8))
    im = ax.imshow(pivot.values, aspect="auto", cmap="YlOrRd")
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns, rotation=90)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)
    plt.colorbar(im, ax=ax, label="Количество пакетов")
    ax.set_title("Тепловая карта: IP-источник → Порт назначения (TCP)")
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/chart_heatmap.png", dpi=150)
    plt.close()
    print(f"График 3 сохранён: chart_heatmap.png")


def plot_packet_size_distribution():
    """График 4: Гистограмма размеров пакетов по протоколам."""
    conn = duckdb.connect()
    df = conn.execute(f"""
        SELECT protocol, packet_size FROM '{PARQUET}'
        WHERE protocol IN ('TCP', 'UDP', 'ICMP')
    """).fetchdf()

    fig = px.histogram(df, x="packet_size", color="protocol",
        nbins=50, barmode="overlay",
        title="Распределение размеров пакетов",
        labels={"packet_size": "Размер пакета (байт)", "count": "Количество"},
        opacity=0.7)
    fig.write_html(f"{OUTPUT_DIR}/chart_sizes.html")
    fig.write_image(f"{OUTPUT_DIR}/chart_sizes.png")
    print(f"График 4 сохранён: chart_sizes.png")


if __name__ == "__main__":
    plot_protocol_distribution()
    plot_traffic_timeline()
    plot_top_ips_heatmap()
    plot_packet_size_distribution()
    print(f"\nВсе графики сохранены в {OUTPUT_DIR}/")
