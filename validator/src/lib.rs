use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// ── helpers ──────────────────────────────────────────────────────────────────

fn get_str<'a>(dict: &'a PyDict, key: &str) -> &'a str {
    dict.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<&str>().ok())
        .unwrap_or("")
}

fn get_i64(dict: &PyDict, key: &str) -> i64 {
    dict.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<i64>().ok())
        .unwrap_or(0)
}

/// Проверяет строку на корректный IPv4-адрес (допускает пустой и 0.0.0.0)
fn is_valid_ipv4(ip: &str) -> bool {
    if ip.is_empty() || ip == "0.0.0.0" {
        return true;
    }
    let parts: Vec<&str> = ip.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Ядро валидации — возвращает список сообщений об ошибках.
fn check_record(dict: &PyDict) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // IP-адреса
    for field in &["src_ip", "dst_ip"] {
        let ip = get_str(dict, field);
        if !is_valid_ipv4(ip) {
            errors.push(format!("invalid {}: '{}' (not a valid IPv4)", field, ip));
        }
    }

    // Порты (0–65535)
    for field in &["src_port", "dst_port"] {
        let port = get_i64(dict, field);
        if !(0..=65535).contains(&port) {
            errors.push(format!("invalid {}: {} (must be 0–65535)", field, port));
        }
    }

    // TTL (0–255)
    let ttl = get_i64(dict, "ttl");
    if !(0..=255).contains(&ttl) {
        errors.push(format!("invalid ttl: {} (must be 0–255)", ttl));
    }

    // Размер пакета (минимальный Ethernet-кадр 14 байт, максимум 65535)
    let size = get_i64(dict, "packet_size");
    if size != 0 && !(14..=65535).contains(&size) {
        errors.push(format!("invalid packet_size: {} (expected 14–65535)", size));
    }

    // Payload не должен превышать packet_size
    let payload = get_i64(dict, "payload_size");
    if payload > size && size > 0 {
        errors.push(format!(
            "payload_size {} > packet_size {} (impossible)",
            payload, size
        ));
    }

    // Протокол не должен содержать SQL-опасные символы
    let proto = get_str(dict, "protocol");
    if proto.contains('\'') || proto.contains('"') || proto.contains(';') {
        errors.push(format!("suspicious protocol field: '{}'", proto));
    }

    errors
}

// ── публичный Python API ──────────────────────────────────────────────────────

/// Валидирует одну запись пакета.
/// Возвращает список строк с ошибками (пустой список = запись корректна).
#[pyfunction]
fn validate_packet(record: &PyDict) -> PyResult<Vec<String>> {
    Ok(check_record(record))
}

/// Валидирует список записей (Python list[dict]).
/// Возвращает кортеж (valid_count, invalid_count, errors_sample).
#[pyfunction]
fn validate_batch(records: &PyList) -> PyResult<(usize, usize, Vec<String>)> {
    let mut valid = 0usize;
    let mut invalid = 0usize;
    let mut all_errors: Vec<String> = Vec::new();

    for item in records.iter() {
        let dict: &PyDict = item.downcast().map_err(|e| {
            pyo3::exceptions::PyTypeError::new_err(format!(
                "Expected dict, got: {}",
                e
            ))
        })?;

        let errs = check_record(dict);
        if errs.is_empty() {
            valid += 1;
        } else {
            invalid += 1;
            all_errors.extend(errs);
        }
    }

    Ok((valid, invalid, all_errors))
}

/// Возвращает версию библиотеки.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ── регистрация модуля ────────────────────────────────────────────────────────

#[pymodule]
fn packet_validator(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(validate_packet, m)?)?;
    m.add_function(wrap_pyfunction!(validate_batch, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
