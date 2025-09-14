import winreg

try:
    # 1. ОТКРЫТИЕ КЛЮЧА - получаем дескриптор
    key = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r'SYSTEM\CurrentControlSet\Control\Lsa',
        0,
        winreg.KEY_READ
    )

    # 2. ЧТЕНИЕ ЗНАЧЕНИЙ - используем дескриптор
    try:
        value, regtype = winreg.QueryValueEx(key, 'Guest')
        print(f"Значение: {value}")
        print(f"Тип данных: {regtype}")  # 1=REG_SZ (строка), 4=REG_DWORD (число)

    except FileNotFoundError:
        print("Значение NewGuestName не найдено")

    # 3. ЗАКРЫТИЕ КЛЮЧА - обязательно освобождаем ресурсы!
    winreg.CloseKey(key)

except PermissionError:
    print("Ошибка доступа: требуются права администратора")
except Exception as e:
    print(f"Ошибка: {e}")