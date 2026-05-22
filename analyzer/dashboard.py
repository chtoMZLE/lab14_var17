import streamlit as st
import polars as pl
import duckdb
import plotly.express as px
import plotly.graph_objects as go
import os
import re
import time
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PARQUET = os.getenv("OUTPUT_DIR", "./data/output") + "/packets.parquet"

st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
st.title("Анализ сетевого трафика — Вариант 17")

if not os.path.exists(PARQUET):
    st.error(f"Файл {PARQUET} не найден. Сначала запустите Go-сборщик и analyzer/main.py")
    st.stop()

conn = duckdb.connect()

# Метрики
st.subheader("Общая статистика")
col1, col2, col3, col4 = st.columns(4)

stats = conn.execute(f"""
    SELECT COUNT(*) as total, SUM(packet_size) as bytes,
           COUNT(DISTINCT src_ip) as src_ips, COUNT(DISTINCT dst_port) as ports
    FROM '{PARQUET}'
""").fetchone()

col1.metric("Всего пакетов", f"{stats[0]:,}")
col2.metric("Всего байт", f"{stats[1]/1024/1024:.1f} MB")
col3.metric("Уникальных IP", stats[2])
col4.metric("Уникальных портов", stats[3])

# Фильтры
st.sidebar.header("Фильтры")
protocols = conn.execute(f"SELECT DISTINCT protocol FROM '{PARQUET}'").fetchdf()["protocol"].tolist()
selected_protocols = st.sidebar.multiselect("Протоколы", protocols, default=protocols)

port_filter = st.sidebar.text_input("Порт назначения (пусто = все)", "")
ip_filter = st.sidebar.text_input("IP-адрес источника (пусто = все)", "")

proto_list = ", ".join(f"'{p}'" for p in selected_protocols) if selected_protocols else "''"
where_clauses = [f"protocol IN ({proto_list})"]
if port_filter.isdigit():
    where_clauses.append(f"dst_port = {int(port_filter)}")
# Разрешаем только символы допустимые в IP-адресе — защита от SQL-инъекции
ip_safe = re.sub(r"[^0-9a-fA-F.:]", "", ip_filter)
if ip_safe:
    where_clauses.append(f"src_ip LIKE '%{ip_safe}%'")
where = " AND ".join(where_clauses)

# Графики
col_a, col_b = st.columns(2)

with col_a:
    st.subheader("Протоколы")
    df_proto = conn.execute(f"""
        SELECT protocol, COUNT(*) as count FROM '{PARQUET}'
        WHERE {where} GROUP BY protocol ORDER BY count DESC
    """).fetchdf()
    fig = px.pie(df_proto, names="protocol", values="count")
    st.plotly_chart(fig, use_container_width=True)

with col_b:
    st.subheader("Топ-10 портов назначения")
    df_ports = conn.execute(f"""
        SELECT dst_port, COUNT(*) as count FROM '{PARQUET}'
        WHERE {where} GROUP BY dst_port ORDER BY count DESC LIMIT 10
    """).fetchdf()
    fig2 = px.bar(df_ports, x="dst_port", y="count", text="count")
    st.plotly_chart(fig2, use_container_width=True)

# Временной ряд
st.subheader("Трафик по времени")
df_time = conn.execute(f"""
    SELECT DATE_TRUNC('minute', CAST(timestamp AS TIMESTAMP)) as t,
           COUNT(*) as packets, protocol
    FROM '{PARQUET}'
    WHERE {where} GROUP BY 1, 2 ORDER BY 1
""").fetchdf()
fig3 = px.area(df_time, x="t", y="packets", color="protocol")
st.plotly_chart(fig3, use_container_width=True)

# Подозрительные IP
st.subheader("Подозрительная активность")
df_sus = conn.execute(f"""
    SELECT src_ip, COUNT(DISTINCT dst_port) as scanned_ports,
           COUNT(*) as total_packets,
           SUM(CASE WHEN flags LIKE '%RST%' THEN 1 ELSE 0 END) as rst_packets
    FROM '{PARQUET}'
    WHERE {where}
    GROUP BY src_ip HAVING COUNT(DISTINCT dst_port) > 3
    ORDER BY scanned_ports DESC LIMIT 20
""").fetchdf()
st.dataframe(df_sus, use_container_width=True)

# Автообновление
if st.sidebar.checkbox("Автообновление (5с)", value=False):
    time.sleep(5)
    st.rerun()

st.caption(f"Данные: {PARQUET} | Обновлено: {time.strftime('%H:%M:%S')}")
