import re
import socket
import hashlib

def extract_ip(log_line: str) -> str | None:
    """
    Кейс 1: Парсинг реальных логов VPS с регулярными выражениями (re).
    Ищет IP-адрес в строке лога, сигнализирующей о неудачной попытке входа по SSH.
    """
 
    if ('Failed password' or "Invalid user") not in log_line:
        return None
    
    pattern = r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    match = re.search(pattern, log_line)

    # Возвращаем найденный IP-адрес или None
    if match:
        return match.group(1)
    return None


def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Кейс 2: Группировка атак по IP (Агрегация через dict).
    Подсчитывает общее число неудачных попыток входа для каждого IP-адреса.
    """
    attacks = {}
    for line in log_lines:
        ip = extract_ip(line)
        if ip:
            attacks[ip] = attacks.get(ip, 0) + 1
    return attacks


def detect_brute_force(ip_counts: dict[str, int], threshold: int = 5) -> list[str]:
    """
    Кейс 3: Детектор SSH Brute-Force.
    Выявляет IP-адреса, количество неудачных входов которых превышает порог threshold.
    """
    return [ip for ip, count in ip_counts.items() if count >= threshold]

def detect_suspicious_paths(log_line: str) -> bool:
    """
    Кейс 4: Поиск сигнатур веб-атак в логах Nginx/Apache.
    Проверяет, содержит ли веб-запрос известные сигнатуры угроз (LFI, раскрытие путей, инъекции).
    """
     # 1. Определяем список сигнатур угроз
    signatures = [
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
    ]
 # 1. Определяем список сигнатур угроз
    signatures = [
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php"
    ]

    # 2. Приводим строку лога к нижнему регистру
    log_lower = log_line.lower()

    # 3. Проверяем, содержится ли хотя бы одна сигнатура в строке
    for signature in signatures:
        if signature in log_lower:
            return True

    # 4. Если ничего не найдено → возвращаем False
    return False

def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """
    Кейс 5: Расчет условного уровня риска (Risk Scoring).
    На основе количества сработавших алертов вычисляет общий уровень угрозы.
    """
    # 1. Вычисляем балл риска: брутфорс = 3 балла, веб-алерт = 1 балл
    risk_score = brute_force_alerts * 3 + web_alerts * 1

    # 2. Определяем уровень риска
    if risk_score == 0:
        return "LOW"
    elif risk_score < 5:
        return "MEDIUM"
    else:
        return "HIGH"

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Кейс 6: Безопасный сканер сетевой доступности VPS.
    Проверяет, открыт ли конкретный порт на сервере по протоколу TCP.
    """
    try:
        # 1. Создаём TCP-сокет
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 2. Устанавливаем таймаут подключения
        sock.settimeout(timeout)

        # 3. Пытаемся подключиться к (ip, port)
        result = sock.connect_ex((ip, port))

        # 4. Закрываем сокет
        sock.close()

        # 5. Метод connect_ex возвращает 0 при успешном подключении
        return result == 0

    except Exception:
        # 6. Если произошла любая ошибка → считаем порт закрытым
        return False

def get_file_hash(filepath: str) -> str:
    """
    Кейс 7: Контроль целостности файлов на VPS (SHA-256).
    Вычисляет криптографический хеш файла для отслеживания изменений.
    """
    try:
        # 1. Создаём объект хеша SHA-256
        sha256_hash = hashlib.sha256()

        # 2. Открываем файл в режиме бинарного чтения
        with open(filepath, "rb") as f:
            # 3. Читаем файл порциями (блоками по 4096 байт)
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                # 4. Обновляем хеш прочитанными данными
                sha256_hash.update(chunk)

        # 5. Возвращаем строковое представление хеша (шестнадцатеричный вид)
        return sha256_hash.hexdigest()

    except FileNotFoundError:
        # 6. Если файл не найден → возвращаем специальную строку
        return "FILE_NOT_FOUND"
