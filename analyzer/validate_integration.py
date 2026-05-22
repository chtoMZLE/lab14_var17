"""
Интеграция Rust-библиотеки валидации пакетов (задание 4 повышенного уровня).

Сборка:
    cd validator
    pip install maturin
    maturin develop --release      # разработка (устанавливает в текущий venv)
    # или для production:
    maturin build --release        # создаёт wheel в validator/target/wheels/

Требования: Rust toolchain (https://rustup.rs), maturin >= 1.0
"""

try:
    import packet_validator as _rv
    RUST_AVAILABLE = True
    print(f"[VALIDATOR] Rust модуль загружен, версия {_rv.version()}")
except ImportError:
    RUST_AVAILABLE = False
    print("[VALIDATOR] Rust модуль не найден — используется Python fallback.")
    print("            Соберите: cd validator && maturin develop --release")


# ── Python fallback (идентичная логика) ──────────────────────────────────────

def _validate_packet_py(record: dict) -> list:
    errors = []

    for field in ("src_ip", "dst_ip"):
        ip = record.get(field, "")
        if ip and ip != "0.0.0.0":
            parts = ip.split(".")
            if len(parts) != 4 or not all(
                p.isdigit() and 0 <= int(p) <= 255 for p in parts
            ):
                errors.append(f"invalid {field}: '{ip}' (not a valid IPv4)")

    for field in ("src_port", "dst_port"):
        port = record.get(field, 0)
        if not (0 <= port <= 65535):
            errors.append(f"invalid {field}: {port} (must be 0–65535)")

    ttl = record.get("ttl", 0)
    if not (0 <= ttl <= 255):
        errors.append(f"invalid ttl: {ttl} (must be 0–255)")

    size = record.get("packet_size", 0)
    if size and not (14 <= size <= 65535):
        errors.append(f"invalid packet_size: {size} (expected 14–65535)")

    payload = record.get("payload_size", 0)
    if payload > size > 0:
        errors.append(f"payload_size {payload} > packet_size {size} (impossible)")

    proto = record.get("protocol", "")
    if any(c in proto for c in ("'", '"', ";")):
        errors.append(f"suspicious protocol field: '{proto}'")

    return errors


# ── публичный API ─────────────────────────────────────────────────────────────

def validate_packet(record: dict) -> list:
    """Валидирует одну запись; возвращает список строк с ошибками."""
    if RUST_AVAILABLE:
        return _rv.validate_packet(record)
    return _validate_packet_py(record)


def validate_dataframe(df) -> dict:
    """Валидирует Polars DataFrame; выводит статистику и возвращает dict."""
    import time

    records = df.to_dicts()
    t0 = time.perf_counter()

    if RUST_AVAILABLE:
        valid, invalid, errors = _rv.validate_batch(records)
    else:
        valid = invalid = 0
        errors = []
        for rec in records:
            errs = _validate_packet_py(rec)
            if errs:
                invalid += 1
                errors.extend(errs)
            else:
                valid += 1

    elapsed = time.perf_counter() - t0
    engine = f"Rust v{_rv.version()}" if RUST_AVAILABLE else "Python (fallback)"

    print(f"\n=== Задание 4: Rust-валидация ({engine}) ===")
    print(f"  Валидных записей:    {valid}")
    print(f"  Невалидных записей:  {invalid}")
    print(f"  Время валидации:     {elapsed:.4f}с")
    if errors:
        print(f"  Примеры ошибок:      {errors[:5]}")
    else:
        print("  Ошибок не найдено.")

    return {"valid": valid, "invalid": invalid, "errors": errors[:20], "engine": engine}


# ── демонстрация ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_cases = [
        {
            "src_ip": "192.168.1.5", "dst_ip": "10.0.0.1",
            "src_port": 54321, "dst_port": 443,
            "ttl": 64, "packet_size": 1024, "payload_size": 980,
            "protocol": "TCP", "flags": "SYN",
        },
        {
            "src_ip": "999.999.999.999", "dst_ip": "10.0.0.1",
            "src_port": 99999, "dst_port": 443,
            "ttl": 300, "packet_size": 5, "payload_size": 2000,
            "protocol": "'; DROP TABLE packets; --", "flags": "",
        },
        {
            "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
            "src_port": 12345, "dst_port": 53,
            "ttl": 128, "packet_size": 72, "payload_size": 32,
            "protocol": "UDP", "flags": "",
        },
    ]

    print("=== Тест валидатора ===")
    for i, rec in enumerate(test_cases, 1):
        errors = validate_packet(rec)
        status = "OK" if not errors else f"INVALID ({len(errors)} err)"
        print(f"  [{i}] {rec['src_ip']}:{rec['src_port']} → {rec['dst_ip']}:{rec['dst_port']} — {status}")
        for e in errors:
            print(f"       • {e}")
