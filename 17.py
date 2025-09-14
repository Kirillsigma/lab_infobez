import subprocess


def check_audit_by_guid():

    guid = "Сведения об общем файловом ресурсе"
    command = ['auditpol', '/get', '/subcategory:{}'.format(guid)]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='cp866')
        output = result.stdout
        print(f"Вывод команды:\n{output}")

        # Проверяем наличие Failure в выводе
        if "Failure" in output or "Сбой" in output or "Отказ" in output:
            print("[SUCCESS] Аудит сбоев включен")
            return True
        else:
            print("[FAIL] Аудит сбоев не включен")
            return False

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Ошибка выполнения команды: {e}")
        print(f"STDERR: {e.stderr}")
        return False


# Запускаем проверку
if __name__ == "__main__":
    check_audit_by_guid()