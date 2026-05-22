# Лабораторная работа №14, Вариант 17 (повышенная сложность)
- Студент: Тараканова Мария 
- Группа: 221131
## Анализ сетевого трафика — конвейер Go + Python

**Предметная область:** анализ сетевого трафика из PCAP-файлов / tcpdump  
**Уровень сложности:** повышенный (вариант 17, задания 1–8)

---

## Архитектура конвейера

```
PCAP-файлы
    │
    ├─► [Go сборщик] ──► NDJSON ──► [Python Polars] ──► Parquet ──► [DuckDB] ──► [Визуализация]
    │        │                              │
    │        ├─► Tumbling window (60с)      └─► [Rust валидатор] (PyO3)
    │        │       └──► windows_*.ndjson
    │        │
    │        ├─► Arrow IPC HTTP (/packets) ──► [Python Arrow-клиент]
    │        │                                        └──► сравнение Arrow vs JSON
    │        │
    │        └─► NATS ("pcap.packets") ──► [Python скользящее окно 5 мин]
    │
    └─► [Python asyncio] ──► benchmark vs Go
                                    └──► benchmark.png / benchmark_report.json

[Streamlit дашборд] ──► Parquet (DuckDB-запросы в реальном времени)
```

---

## Структура проекта

```
lab14-var17/
├── collector/
│   ├── main.go                # PCAP-парсер: горутины, флаги, graceful shutdown
│   ├── window.go              # Tumbling window агрегация (60с)
│   ├── arrow_server.go        # Arrow IPC HTTP сервер (GET /packets, GET /health)
│   ├── nats_producer.go       # NATS-продюсер (публикует в "pcap.packets")
│   ├── etcd_coordinator.go    # etcd: lease, регистрация инстансов, шардирование файлов
│   └── main_test.go           # Юнит-тесты (4 теста, все PASS)
├── analyzer/
│   ├── main.py              # Polars + DuckDB анализ (задания базового уровня)
│   ├── arrow_client.py      # Arrow IPC клиент + сравнение скорости Arrow vs JSON
│   ├── validate_integration.py  # Интеграция Rust-валидатора (PyO3 / Python fallback)
│   ├── async_collector.py   # Python asyncio PCAP-сборщик (ProcessPoolExecutor)
│   ├── benchmark.py         # Бенчмарк Go vs Python asyncio
│   ├── nats_consumer.py     # NATS-консьюмер со скользящим окном 5 мин
│   ├── visualize.py         # 4 графика (Plotly + matplotlib)
│   └── dashboard.py         # Streamlit веб-дашборд
├── validator/
│   ├── Cargo.toml           # Rust crate (pyo3 = "0.20")
│   ├── pyproject.toml       # maturin build config
│   └── src/lib.rs           # validate_packet / validate_batch / version
├── docker/
│   ├── Dockerfile           # Multi-stage: golang:1.21-alpine → alpine:3.18
│   ├── docker-compose.yml   # NATS + collector сервисы
│   └── kubernetes/
│       ├── namespace.yaml   # namespace: lab14
│       ├── deployment.yaml  # Deployment pcap-collector (liveness/readiness пробы)
│       ├── service.yaml     # ClusterIP :8815
│       └── hpa.yaml         # HPA 1–5 реплик (CPU>60%, RAM>70%)
├── data/
│   ├── samples/             # PCAP-файлы и generate_test_pcap.py
│   └── output/              # NDJSON, Parquet, PNG/HTML графики, бенчмарк
├── go.mod                   # Go-зависимости (gopacket, arrow/v14, nats.go, uuid, etcd/client/v3)
├── requirements.txt         # Python-зависимости
└── .env                     # NATS_URL, PCAP_DIR, OUTPUT_DIR, ARROW_SERVER_PORT
```

---

## Быстрый старт

### 1. Зависимости

```bash
go mod tidy
pip install -r requirements.txt
```

### 2. Генерация тестовых PCAP-данных

```bash
python data/samples/generate_test_pcap.py
# → data/samples/test_traffic.pcap (500 пакетов, random.seed=42)
```

### 3. Go-сборщик → NDJSON

```bash
go run ./collector/...
# → data/output/packets_*.ndjson
```

### 4. Оконная агрегация (tumbling window 60с)

```bash
go run ./collector/... --windowed
# → data/output/windows_*.ndjson
```

### 5. Python-анализ (Polars + DuckDB + Parquet)

```bash
python analyzer/main.py
# Задания 4–8: загрузка → очистка → агрегация → Parquet → DuckDB
```

### 6. Rust-валидатор (задание 4)

```bash
# Сборка Rust-модуля (требует Rust toolchain: https://rustup.rs)
cd validator
pip install maturin
maturin develop --release
cd ..

# Проверка
python analyzer/validate_integration.py
```

> Если Rust не установлен — модуль автоматически переключается на Python-fallback
> с идентичной логикой проверок.

### 7. Apache Arrow HTTP сервер + клиент (задание 3)

```bash
# Терминал 1 — запустить сервер
go run ./collector/... --serve-arrow

# Терминал 2 — получить данные и сравнить производительность
curl http://localhost:8815/health        # → OK
python analyzer/arrow_client.py         # → Arrow vs JSON сравнение
```

### 8. Распределённый сборщик с etcd-координацией (задание 1)

```bash
# Терминал 1 — запустить etcd
docker run -p 2379:2379 -p 2380:2380 quay.io/coreos/etcd:v3.5.11 \
  etcd --advertise-client-urls http://0.0.0.0:2379 \
       --listen-client-urls http://0.0.0.0:2379

# Терминал 2 — инстанс сборщика A (получит шард файлов)
go run ./collector/... --etcd --etcd-endpoints localhost:2379

# Терминал 3 — инстанс сборщика B (получит другой шард)
go run ./collector/... --etcd --etcd-endpoints localhost:2379
# Каждый инстанс регистрируется в etcd, получает lease и
# обрабатывает только назначенные ему файлы (shard = i % N == myIndex)
```

### 9. NATS-стриминг + скользящее окно (задание 7)

```bash
# Терминал 1 — NATS broker
docker run -p 4222:4222 nats:2.10-alpine
# или: docker compose -f docker/docker-compose.yml up nats

# Терминал 2 — Go продюсер
go run ./collector/... --nats

# Терминал 3 — Python консьюмер (скользящее окно 5 мин)
python analyzer/nats_consumer.py
```

### 10. Бенчмарк Go vs Python asyncio (задание 6)

```bash
python analyzer/benchmark.py
# → data/output/benchmark.png
# → data/output/benchmark_report.json
```

### 11. Визуализация (задание 9)

```bash
python analyzer/visualize.py
# → data/output/chart_protocols.png  (pie + bar)
# → data/output/chart_timeline.png   (area chart)
# → data/output/chart_heatmap.png    (тепловая карта IP → порт)
# → data/output/chart_sizes.png      (гистограмма размеров)
```

### 12. Streamlit дашборд (задание 8)

```bash
streamlit run analyzer/dashboard.py
# Открыть: http://localhost:8501
```

### 13. Kubernetes (задание 5)

```bash
# Собрать Docker-образ
docker build -f docker/Dockerfile -t pcap-collector:latest .

# Развернуть в minikube/k3s
kubectl apply -f docker/kubernetes/namespace.yaml
kubectl apply -f docker/kubernetes/deployment.yaml
kubectl apply -f docker/kubernetes/service.yaml
kubectl apply -f docker/kubernetes/hpa.yaml

# Проверить статус
kubectl -n lab14 get pods
kubectl -n lab14 get hpa
```

### 14. Docker Compose (etcd + NATS + collector)

```bash
docker compose -f docker/docker-compose.yml up
# Поднимает: etcd (координатор шардов) + NATS (стриминг) + collector (Arrow HTTP)
```

### 15. Тесты

```bash
go test ./collector/... -v
# PASS: TestAggregateWindow
# PASS: TestAggregateWindowEmpty
# PASS: TestTumblingWindowGroups
# PASS: TestExtractRecordDefaults
```

---

## Реализованные задания

### Задания базового уровня (1–9 из методички)

| № | Файл | Описание |
|---|------|----------|
| 1 | collector/main.go | Go-сборщик: горутины + буферизованные каналы |
| 2 | collector/main.go | Буферизация (100 записей / 5с flush) |
| 3 | collector/main.go | Graceful shutdown (SIGINT/SIGTERM) |
| 4 | analyzer/main.py | Импорт NDJSON в Polars DataFrame |
| 5 | analyzer/main.py | Очистка: дубликаты, типы, фильтр 0.0.0.0 |
| 6 | analyzer/main.py | Агрегация по протоколу, порту, src IP |
| 7 | analyzer/main.py | Сохранение в Parquet |
| 8 | analyzer/main.py | DuckDB SQL + сравнение с Polars по времени |
| 9 | analyzer/visualize.py | 4 графика: pie/bar, timeline, heatmap, histogram |

### Задания повышенного уровня (вариант 17)

| № | Файл(ы) | Описание |
|---|---------|----------|
| 1 | collector/main.go, collector/etcd_coordinator.go | Распределённый PCAP-парсер: горутины + WaitGroup + etcd-координация (lease, регистрация инстансов, распределение шардов файлов) |
| 2 | collector/window.go | Tumbling window агрегация (60с окна, 15 метрик) |
| 3 | collector/arrow_server.go, analyzer/arrow_client.py | Apache Arrow IPC HTTP: Go-сервер отдаёт RecordBatch, Python-клиент читает в Polars; сравнение Arrow vs JSON |
| 4 | validator/src/lib.rs, analyzer/validate_integration.py | Rust-библиотека валидации пакетов через PyO3; проверка IP, портов (0–65535), TTL (0–255), размера пакета |
| 5 | docker/Dockerfile, docker/kubernetes/ | Docker multi-stage сборка; Kubernetes Deployment + Service + HPA (CPU>60%, RAM>70%, 1–5 реплик) |
| 6 | analyzer/async_collector.py, analyzer/benchmark.py | Python asyncio + ProcessPoolExecutor PCAP-сборщик; бенчмарк Go vs Python (время, pkt/s, RAM), Plotly-график |
| 7 | collector/nats_producer.go, analyzer/nats_consumer.py | Go-продюсер публикует пакеты в NATS; Python asyncio-консьюмер со скользящим окном 5 мин, детекция сканирования портов |
| 8 | analyzer/dashboard.py | Streamlit веб-дашборд: 4 метрики, фильтры протокол/порт/IP, pie/bar/area графики, таблица подозрительных IP, автообновление |

---

## Флаги Go-сборщика

```
--windowed               Tumbling window агрегация → windows_*.ndjson
--serve-arrow            Arrow IPC HTTP сервер на :8815
--nats                   Публикация пакетов в NATS (subject: pcap.packets)
--etcd                   Включить etcd-координацию шардов
--etcd-endpoints string  Адреса etcd через запятую (по умолчанию: env ETCD_ENDPOINTS или localhost:2379)
```

---

## Переменные окружения (.env)

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `NATS_URL` | `nats://localhost:4222` | Адрес NATS-брокера |
| `PCAP_DIR` | `./data/samples` | Директория с PCAP-файлами |
| `OUTPUT_DIR` | `./data/output` | Директория для результатов |
| `WINDOW_SIZE_SECONDS` | `300` | Размер скользящего окна (Python консьюмер) |
| `ARROW_SERVER_PORT` | `8815` | Порт Arrow HTTP сервера |
| `ETCD_ENDPOINTS` | `localhost:2379` | Адреса etcd (используется флагом `--etcd`) |

---

## Примечания по платформам

| Платформа | Требование |
|-----------|-----------|
| Windows | [Npcap](https://npcap.com/) для gopacket/pcap |
| Linux | `apt-get install libpcap-dev` |
| Rust | [rustup.rs](https://rustup.rs) + `pip install maturin` для задания 4 |
| Kubernetes | [minikube](https://minikube.sigs.k8s.io/) или k3s для задания 5 |

Без прав на захват трафика: `python data/samples/generate_test_pcap.py`  
Реальный захват: `tcpdump -w data/samples/live.pcap -i eth0 -c 10000`
