import re

def extract_ip(log_line: str) -> str | None:
    """
    Анализирует строку лога. Если зафиксирована неудачная попытка входа,
    извлекает и возвращает IPv4-адрес. В противном случае возвращает None.
    """
    if "Failed password" in log_line or "Invalid user" in log_line:
        # Регулярное выражение ищет IPv4-адрес после ключевого слова 'from'
        match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
        if match:
            return match.group(1)
    return None

def aggregate_attacks(log_lines: list[str]) -> dict[str, int]:
    """
    Принимает список строк лога, извлекает IP-адреса нарушителей
    и подсчитывает количество атак для каждого адреса.
    """
    attacks: dict[str, int] = {}
    for line in log_lines:
        ip = extract_ip(line)
        if ip:  
            attacks[ip] = attacks.get(ip, 0) + 1
    return attacks

def detect_brute_force(attacks: dict[str, int], threshold: int = 5) -> set[str]:
    """
    Фильтрует словарь атак и возвращает множество IP-адресов,
    у которых количество зафиксированных атак строго больше или равно порогу (threshold).
    """
    trigger_ips: set[str] = set()
    for ip, count in attacks.items():
        if count >= threshold:
            trigger_ips.add(ip)
    return trigger_ips
