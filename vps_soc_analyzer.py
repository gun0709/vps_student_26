import re
import socket
import hashlib

def extract_ip(log_line: str) -> str | None:
    """
    Кейс 1: Парсинг реальных логов VPS с регулярными выражениями (re).
    Ищет IP-адрес в строке лога, сигнализирующей о неудачной попытке входа по SSH.
    """
    # TODO: Напишите код функции
    # 1. Проверьте, содержит ли строка 'Failed password'
    # 2. Используйте регулярное выражение для поиска IPv4-адреса после 'from'
    # 3. Верните найденный IP-адрес или None

    if "Failed password" in log_line:
        match = re.search(
            r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            log_line
        )

        if match:
            return match.group(1)

    return None

def group_by_ip(log_lines: list[str]) -> dict[str, int]:
    """
    Кейс 2: Группировка атак по IP (Агрегация через dict).
    Подсчитывает общее число неудачных попыток входа для каждого IP-адреса.
    """
    # TODO: Напишите код функции
    # 1. Создайте пустой словарь для подсчета
    # 2. Пройдите циклом по всем строкам логов
    # 3. Извлеките IP-адрес из каждой строки с помощью функции extract_ip
    # 4. Если IP найден, обновите счетчик в словаре
    # 5. Верните полученный словарь
    
    attacks: dict[str, int] = {}

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
    # TODO: Напишите код функции
    # 1. Проанализируйте переданный словарь ip_counts
    # 2. Выберите все IP, у которых количество попыток больше или равно threshold
    # 3. Верните список этих IP-адресов
    #pass
    alerts: list[str] = []

    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append(ip)

    return alerts

def detect_suspicious_paths(log_line: str) -> bool:
    """
    Кейс 4: Поиск сигнатур веб-атак в логах Nginx/Apache.
    Проверяет, содержит ли веб-запрос известные сигнатуры угроз (LFI, раскрытие путей, инъекции).
    """
    # TODO: Напишите код функции
    # 1. Определите список сигнатур угроз: /etc/passwd, .env, wp-admin, select+union, union+select, shell.php
    # 2. Приведите строку лога к нижнему регистру
    # 3. Проверьте, содержится ли хотя бы одна сигнатура в строке
    # 4. Верните True, если сигнатура найдена, иначе False
    #pass
    signatures = [
        "/etc/passwd",
        ".env",
        "wp-admin",
        "select+union",
        "union+select",
        "shell.php"
    ]

    log_line = log_line.lower()

    for signature in signatures:
        if signature in log_line:
            return True

    return False

def calculate_risk_score(brute_force_alerts: int, web_alerts: int) -> str:
    """
    Кейс 5: Расчет условного уровня риска (Risk Scoring).
    На основе количества сработавших алертов вычисляет общий уровень угрозы.
    """
    # TODO: Напишите код функции
    # 1. Вычислите балл риска: каждая брутфорс-атака = 3 балла, каждый веб-алерт = 1 балл
    # 2. Если балл равен 0 -> верните "LOW"
    # 3. Если балл меньше 5 -> верните "MEDIUM"
    # 4. В остальных случаях -> верните "HIGH"
    #pass
    risk_score = brute_force_alerts * 3 + web_alerts

    if risk_score == 0:
        return "LOW"

    if risk_score < 5:
        return "MEDIUM"

    return "HIGH"

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Кейс 6: Безопасный сканер сетевой доступности VPS.
    Проверяет, открыт ли конкретный порт на сервере по протоколу TCP.
    """
    # TODO: Напишите код функции
    # 1. Используйте модуль socket для создания TCP-сокета (AF_INET, SOCK_STREAM)
    # 2. Установите таймаут подключения
    # 3. Попробуйте подключиться к (ip, port) с помощью метода connect_ex
    # 4. Метод возвращает 0 при успешном подключении (порт открыт)
    # 5. Обработайте возможные исключения и верните результат (True/False)
    #pass
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))

        sock.close()

        return result == 0

    except (socket.timeout, socket.error, OSError):
        return False

def get_file_hash(filepath: str) -> str:
    """
    Кейс 7: Контроль целостности файлов на VPS (SHA-256).
    Вычисляет криптографический хеш файла для отслеживания изменений.
    """
    # TODO: Напишите код функции
    # 1. Используйте библиотеку hashlib (алгоритм sha256)
    # 2. Попробуйте открыть файл в режиме бинарного чтения 'rb'
    # 3. Прочитайте файл порциями (блоками) и обновите хеш
    # 4. Верните строковое представление хеша в шестнадцатеричном виде (hexdigest)
    # 5. Если файл не найден (FileNotFoundError), верните строку "FILE_NOT_FOUND"
    #pass
    sha256_hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            while True:
                block = file.read(4096)

                if not block:
                    break

                sha256_hash.update(block)

        return sha256_hash.hexdigest()

    except FileNotFoundError:
        return "FILE_NOT_FOUND"
