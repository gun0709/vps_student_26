import sys
from vps_soc_analyzer import aggregate_attacks, detect_brute_force

def run_pipeline(log_path: str) -> None:
    """
    Запускает сквозной конвейер анализа: чтение файла,
    агрегацию инцидентов, фильтрацию по порогу и вывод отчета.
    """
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            log_lines: list[str] = f.readlines()
        
        print(f"[+] Успешно прочитано строк из файла: {len(log_lines)}")
        
        attack_counts = aggregate_attacks(log_lines)
        
        suspicious_ips = detect_brute_force(attack_counts, threshold=5)
        
        print("\n" + "="*50)
        print(f" ОТЧЕТ MINI-SOC: ОБНАРУЖЕНЫ SSH BRUTE-FORCE АТАКИ")
        print("="*50)
        
        if not suspicious_ips:
            print("[*] Подозрительных IP-адресов с превышением порога не обнаружено.")
        else:
            print(f"[!] Найдено хостов для блокировки: {len(suspicious_ips)}\n")
            print(f"{'IP-Адрес':<20} | {'Количество попыток':<15}")
            print("-" * 40)
            for ip in sorted(suspicious_ips):
                print(f"{ip:<20} | {attack_counts[ip]:<15}")
                
        print("="*50)

    except FileNotFoundError:
        print(f"[-] Ошибка: Файл по пути '{log_path}' не найден.")
    except Exception as e:
        print(f"[-] Непредвиденная ошибка при обработке: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_log = sys.argv[1]
    else:
        target_log = "/home/student/logs/auth.log"
        
    run_pipeline(target_log)
