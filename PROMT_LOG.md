# PROMPT_LOG.md — Лог сессии ИИ-агента
## Лабораторная работа №14, Вариант 17 — Анализ сетевого трафика

**Инструмент:** Claude Code (agentic режим)  
**ОС:** Windows 11 + WSL  
**Итоговых коммитов:** 5

---

## Стартовый промпт

```
Следуй плану из workplan.md, создай гит репозиторий, делай коммиты
```

---

## Общая структура сессии

```
Фаза 0: Структура проекта, git init          ✅ без проблем
Фаза 1–3: Go-сборщик, окна, Arrow            ✅ без проблем
Фаза 4–6: Python анализ, графики, дашборд    ✅ без проблем
Фаза 7: Тесты и README                       ✅ все 4 теста прошли
Код ревью + исправление замечаний            ✅ 8 из 8 замечаний исправлены
```

Всего выполнено ~40 инструментальных вызовов:
`Bash` — команды, `Write` — создание файлов, `Edit` — правки, `Read` — чтение.

---

## Фаза 0 — Инициализация проекта

### Промпт агента (из WORKPLAN.md)
```
Создать файловую структуру и установить все зависимости.
mkdir -p collector analyzer data/samples data/output docker
go mod init lab14-var17
Критерий: go mod tidy и pip install завершаются без ошибок.
```

### ❌ Ошибка 1 — Опечатка в имени файла workplan

**Симптом:**
```
Read c:\Users\zacha\...\workplan.md
Файл не найден. Проверяю содержимое директории.
```

**Диагностика:**
```bash
ls "c:\Users\zacha\OneDrive\Рабочий стол\lab14_var17"
# OUT: workpkan.md   ← опечатка: 'pkan' вместо 'plan'
```

**Действие агента:** прочитал `workpkan.md` и продолжил без вопросов.

### ✅ Результат Фазы 0

Создана полная структура проекта, первый коммит:
```
[main b9eb800] feat: Phase 0 — project structure, dependencies, env config
5 files changed, 89 insertions(+)
```

Файлы: `.env`, `.gitignore`, `go.mod`, `requirements.txt`, `data/samples/generate_test_pcap.py`

---

## Фаза 1–3 — Go-сборщик, оконная агрегация, Arrow

### Промпт агента (из WORKPLAN.md)
```
Реализовать collector/main.go — парсер PCAP с горутинами.
Реализовать collector/window.go — tumbling window агрегация.
Реализовать collector/arrow_server.go — Arrow IPC HTTP сервер.
Критерий: go build ./collector/... завершается без ошибок.
```

### Действия агента

Агент последовательно создал три файла:

**`collector/main.go`** (301 строка):
- `parsePCAP` — параллельный парсинг через горутины
- `extractRecord` — извлечение IP/TCP/UDP полей из `gopacket.Packet`
- `writeWorker` — батчевая запись с буфером 100 записей и таймером 5 сек
- `main()` с тремя режимами: обычный / `--windowed` / `--serve-arrow`
- Graceful shutdown через `signal.Notify(SIGINT, SIGTERM)`

**`collector/window.go`** (106 строк):
- `WindowAgg` — структура агрегированного окна (15 полей)
- `aggregateWindow` — подсчёт уникальных IP, портов, TCP флагов, avg/min/max
- `TumblingWindowProcessor` — группировка пакетов по временным окнам

**`collector/arrow_server.go`** (69 строк):
- `buildArrowBatch` — сборка Arrow RecordBatch из 11 типизированных колонок
- `ServeArrow` — HTTP сервер, `/packets` и `/health`

### ✅ Результат

```bash
go build ./collector/...
# (Bash completed with no output) — сборка успешна
```

```
[main 3d9ecdc] feat: Phase 1-3 — Go collector, window aggregation, Arrow server
5 files changed, 549 insertions(+)
```

**Замечание:** агент добавил `go.sum` в коммит — правильно, зависимости зафиксированы.

---

## Фаза 4–6 — Python анализ, визуализация, дашборд

### Промпт агента (из WORKPLAN.md)
```
Создать analyzer/main.py — задания 4-8 (Polars + DuckDB).
Создать analyzer/arrow_client.py — Arrow клиент + сравнение производительности.
Создать analyzer/visualize.py — 4 графика.
Создать analyzer/dashboard.py — Streamlit дашборд.
```

### Действия агента

Агент создал 4 Python-файла за один проход без ошибок.

Ключевые решения:
- В `main.py` использовал `pl.len()` вместо `pl.count()` — современный Polars API
- В `arrow_client.py` исправил баг из WORKPLAN: вместо `resp.headers.get('Content-Length')` (заголовок часто отсутствует при стриминге) использовал `len(resp.content)`
- В `visualize.py` добавил `if df.empty` перед тепловой картой — защита от падения
- В `dashboard.py` добавил комментарий `# Используем параметризованный запрос для безопасности` у `ip_filter` — но реализация осталась небезопасной (исправлено позже в ревью)

### ✅ Результат

```
[main 1ddcc80] feat: Phase 4-6 — Python analyzer, Arrow client, visualizations, dashboard
4 files changed, 472 insertions(+)
```

---

## Фаза 7 — Тесты и README

### Промпт агента (из WORKPLAN.md)
```
Написать collector/main_test.go.
Запустить: go test ./collector/... -v
Создать README.md.
Критерий: все тесты проходят.
```

### Написанные тесты

| Тест | Что проверяет |
|---|---|
| `TestAggregateWindow` | 2 пакета → TotalPackets=2, TotalBytes=300, UniqueSrcIPs=1, SYN=1, avg=150 |
| `TestAggregateWindowEmpty` | Пустое окно → TotalPackets=0, MinPacketSize=0 |
| `TestTumblingWindowGroups` | 3 пакета в 2 минутах → 2 окна, суммарно 3 пакета |
| `TestExtractRecordDefaults` | WindowID усекается до минуты: `10:23:41 → 10:23:00` |

### ✅ Результат тестов

```
=== RUN   TestAggregateWindow
--- PASS: TestAggregateWindow (0.00s)
=== RUN   TestAggregateWindowEmpty
--- PASS: TestAggregateWindowEmpty (0.00s)
=== RUN   TestTumblingWindowGroups
--- PASS: TestTumblingWindowGroups (0.00s)
=== RUN   TestExtractRecordDefaults
--- PASS: TestExtractRecordDefaults (0.00s)
PASS
ok  lab14-var17/collector  0.522s
```

```
[main f6e4e91] feat: Phase 7 — tests and documentation
2 files changed, 217 insertions(+)
```

---

## Код ревью — выявленные проблемы

После завершения всех фаз был проведён код ревью. Найдено 8 замечаний.

---

## Исправление замечаний кода ревью

### Стартовый промпт

Агент получил результаты ревью и приступил к исправлениям.  
Перед правками прочитал актуальные версии всех файлов через `Read`.

---

### Исправление 1 — Deadlock в `collector/main.go`

**Проблема:**
```go
select {
case <-sig:
    wg.Wait()
case <-done:
}
<-done   // DEADLOCK: если сюда пришли через <-done, канал уже закрыт
```

**Диагностика агента:**
> *"Закрытый канал в Go возвращает нулевое значение мгновенно при повторном чтении — это не блокировка, но логика неверна: sig-ветка не дожидается реального завершения горутины. Нужно убрать повторные <-done."*

**Исправление:** убраны все три `<-done` / `<-windowDone` после `select`-блоков:

```go
// Было:
select {
case <-sig:
    wg.Wait()
case <-done:
}
<-done  // ← удалено

// Стало:
select {
case <-sig:
    log.Println("...")
    wg.Wait()
    close(ch)
    <-done  // ← перенесено внутрь sig-ветки
case <-done:
}
```

Та же правка применена в ветках `--windowed` и `--serve-arrow`.  
Дополнительно исправлена ошибка `filepath.Glob`:
```go
// Было:
files, _ := filepath.Glob(...)

// Стало:
files, err := filepath.Glob(...)
if err != nil {
    log.Fatalf("[COLLECTOR] ошибка поиска файлов: %v", err)
}
```

---

### Исправление 2 — Arrow batch на каждый запрос в `arrow_server.go`

**Проблема:**
```go
// buildArrowBatch вызывался при каждом HTTP-запросе
http.HandleFunc("/packets", func(w http.ResponseWriter, r *http.Request) {
    batch := buildArrowBatch(packets)  // пересоздание на каждый запрос
    ...
})
```

**Исправление:** batch строится один раз при старте сервера:
```go
func ServeArrow(packets []PacketRecord, port string) {
    batch := buildArrowBatch(packets)  // ← один раз
    defer batch.Release()

    http.HandleFunc("/packets", func(w http.ResponseWriter, r *http.Request) {
        // используем batch через замыкание
        writer := ipc.NewWriter(w, ipc.WithSchema(batch.Schema()))
        ...
    })
}
```

---

### Исправление 3 — `open()` без `with` в `analyzer/main.py`

**Проблема:**
```python
records = [json.loads(line) for line in open(f, encoding="utf-8")]
# файловый дескриптор не закрывается
```

**Исправление:**
```python
with open(f, encoding="utf-8") as fp:
    records = [json.loads(line) for line in fp]
```

---

### Исправление 4 — SQL-инъекция в `analyzer/dashboard.py`

**Проблема:**
```python
where_clauses.append(f"src_ip LIKE '%{ip_filter.replace('%', '')}%'")
# replace('%','') не защищает от '; DROP TABLE; --
```

**Исправление:** очистка через `re.sub` — разрешены только символы IP-адреса:
```python
import re
safe_ip = re.sub(r"[^0-9a-fA-F.:]", "", ip_filter)
where_clauses.append(f"src_ip LIKE '%{safe_ip}%'")
```

Дополнительно порт приводится к `int()`:
```python
if port_filter.isdigit():
    where_clauses.append(f"dst_port = {int(port_filter)}")
```

---

### Исправление 5 — 4 DuckDB-соединения в `analyzer/visualize.py`

**Проблема:** каждая функция создавала своё `duckdb.connect()`.

**Исправление:** одно соединение в `__main__`, передаётся параметром:
```python
def plot_protocol_distribution(conn):  # ← принимает conn
    df = conn.execute(...)

if __name__ == "__main__":
    conn = duckdb.connect()            # ← один раз
    plot_protocol_distribution(conn)
    plot_traffic_timeline(conn)
    plot_top_ips_heatmap(conn)
    plot_packet_size_distribution(conn)
```

---

### Исправление 6 — `random.seed()` и payload в `generate_test_pcap.py`

**Проблема:** каждый запуск давал разные данные, payload раздувал файл.

**Исправление:**
```python
random.seed(42)  # воспроизводимые тестовые данные

# Было:
pkt = IP(...) / TCP(...) / Raw(b"X" * size)   # до 1500 байт payload

# Стало:
pkt = IP(...) / TCP(...) / Raw(b"X" * 10)     # 10 байт достаточно
```

---

### Финальная проверка после исправлений

```bash
go build ./collector/... && go test ./collector/... -v

# OUT:
=== RUN   TestAggregateWindow       --- PASS
=== RUN   TestAggregateWindowEmpty  --- PASS
=== RUN   TestTumblingWindowGroups  --- PASS
=== RUN   TestExtractRecordDefaults --- PASS
PASS  ok  lab14-var17/collector  (cached)
```

### ✅ Коммит с исправлениями

```
[main 05cc7cf] fix: address code review findings
6 files changed, 33 insertions(+), 31 deletions(-)
```

---

## Итоговый git log

```
05cc7cf fix: address code review findings
f6e4e91 feat: Phase 7 — tests and documentation
1ddcc80 feat: Phase 4-6 — Python analyzer, Arrow client, visualizations, dashboard
3d9ecdc feat: Phase 1-3 — Go collector, window aggregation, Arrow server
b9eb800 feat: Phase 0 — project structure, dependencies, env config
```

---

## Итоговая таблица замечаний и исправлений

| # | Файл | Проблема | Исправлено |
|---|---|---|---|
| 1 | `collector/main.go` | Deadlock: двойное чтение `<-done` | `<-done` перенесён внутрь `sig`-ветки |
| 2 | `collector/main.go` | `filepath.Glob` игнорирует ошибку | `log.Fatalf` при ошибке |
| 3 | `collector/arrow_server.go` | `buildArrowBatch` на каждый HTTP-запрос | Batch строится один раз при старте |
| 4 | `analyzer/main.py` | `open()` без `with` — утечка дескриптора | Переведено на `with open() as fp` |
| 5 | `analyzer/dashboard.py` | SQL-инъекция через `ip_filter` | `re.sub` для очистки + `int(port)` |
| 6 | `analyzer/visualize.py` | 4 DuckDB-соединения вместо одного | Одно `conn` передаётся параметром |
| 7 | `generate_test_pcap.py` | Нет `random.seed()` | Добавлен `random.seed(42)` |
| 8 | `generate_test_pcap.py` | Payload до 1500 байт раздувает PCAP | Заменён на `b"X" * 10` |

---

## Что агент сделал хорошо

- **Самостоятельно нашёл опечатку** в имени файла (`workpkan.md`) и продолжил без вопросов.
- **Исправил баг из WORKPLAN** ещё на этапе написания кода: `len(resp.content)` вместо `resp.headers.get('Content-Length')`.
- **Все 4 теста прошли** с первого запуска, без итераций.
- **Детальные commit message** — каждый коммит содержит полное описание что и зачем изменено.
- **После ревью исправил все 8 замечаний** в одном коммите, тесты снова прошли.

## Что агент сделал неидеально

- **Написал `// Используем параметризованный запрос для безопасности`**, но реализацию оставил небезопасной — комментарий и код противоречили друг другу.
- **`collector.exe` попал в репозиторий** — в `.gitignore` было `*.exe`, но бинарник уже существовал до создания `.gitignore` и не был добавлен через `git rm --cached`. Агент это не заметил.
- **`TestExtractRecordDefaults`** не тестирует реальную функцию `extractRecord` — только форматирование строки. Для полного теста нужен мок `gopacket.Packet`, что сложнее, но агент не упомянул это ограничение в комментарии к тесту.
