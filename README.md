# Лабораторная работа №14, Вариант 17
## Анализ сетевого трафика — конвейер Go + Python

### Архитектура конвейера

```
PCAP-файлы → [Go сборщик] → NDJSON/Arrow → [Python Polars] → Parquet → [DuckDB] → [Визуализация]
                   ↓
           Оконная агрегация
           (tumbling window 60с)
                   ↓
           [Apache Arrow HTTP]
                   ↓
           [Python Arrow-клиент]
                   ↓
           [Streamlit дашборд]
```

### Структура проекта

```
lab14-var17/
├── collector/
│   ├── main.go              # Сборщик/парсер PCAP (горутины, graceful shutdown)
│   ├── window.go            # Tumbling window агрегация (60с окна)
│   ├── arrow_server.go      # Arrow IPC HTTP сервер
│   └── main_test.go         # Юнит-тесты
├── analyzer/
│   ├── main.py              # Polars + DuckDB анализ (задания 4–8)
│   ├── arrow_client.py      # Arrow клиент + сравнение производительности
│   ├── visualize.py         # 4 графика (Plotly + matplotlib)
│   └── dashboard.py         # Streamlit дашборд
├── data/
│   ├── samples/             # PCAP-файлы и генератор
│   └── output/              # NDJSON, Parquet, PNG, HTML
├── go.mod
├── requirements.txt
└── .env
```

### Запуск

#### 1. Установить зависимости

```bash
go mod tidy
pip install -r requirements.txt
```

#### 2. Сгенерировать тестовые данные

```bash
python data/samples/generate_test_pcap.py
```

#### 3. Запустить сборщик (режим файлов → NDJSON)

```bash
go run collector/main.go collector/window.go collector/arrow_server.go
```

#### 4. Запустить сборщик с оконной агрегацией

```bash
go run collector/main.go collector/window.go collector/arrow_server.go --windowed
```

#### 5. Запустить анализ

```bash
python analyzer/main.py
python analyzer/visualize.py
```

#### 6. Arrow HTTP сервер + клиент

```bash
# Терминал 1
go run collector/main.go collector/window.go collector/arrow_server.go --serve-arrow

# Терминал 2
curl http://localhost:8815/health
python analyzer/arrow_client.py
```

#### 7. Streamlit дашборд

```bash
streamlit run analyzer/dashboard.py
# Открыть: http://localhost:8501
```

#### 8. Запуск тестов

```bash
go test ./collector/... -v
```

### Реализованные задания

| Задание | Уровень | Файл | Описание |
|---------|---------|------|----------|
| 1 | Повышенный | collector/main.go | Параллельный парсер PCAP через горутины |
| 2 | Повышенный | collector/window.go | Tumbling window агрегация (60с) |
| 3 | Повышенный | collector/arrow_server.go | Apache Arrow IPC HTTP сервер |
| 4 | Базовый | analyzer/main.py | Импорт NDJSON в Polars |
| 5 | Базовый | analyzer/main.py | Очистка данных и валидация |
| 6 | Базовый | analyzer/main.py | Агрегационный анализ |
| 7 | Базовый | analyzer/main.py | Сохранение в Parquet |
| 8 | Повышенный | analyzer/main.py + dashboard.py | DuckDB анализ + Streamlit дашборд |
| 9 | Базовый | analyzer/visualize.py | 4 интерактивных графика |

### Примечания

- Для Windows требуется [Npcap](https://npcap.com/) для работы с PCAP
- Для Linux: `apt-get install libpcap-dev`
- Без прав на захват трафика использовать `generate_test_pcap.py`
- Для реального трафика: `tcpdump -w output.pcap -i eth0 -c 10000`
