import winreg


def simple_guest_account_check():
    """
    Простая и надежная проверка через реестр.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                             0, winreg.KEY_READ)

        guest_name = winreg.QueryValueEx(key, "NewGuestName")[0]
        winreg.CloseKey(key)

        if guest_name != "Guest":
            print(f"СООТВЕТСТВУЕТ: {guest_name}")
            return True
        else:
            print("НЕ СООТВЕТСТВУЕТ: Используется имя 'Guest' по умолчанию")
            return False

    except FileNotFoundError:
        print("НЕ СООТВЕТСТВУЕТ: Параметр не задан (используется 'Guest')")
        return False
    except Exception as e:
        print(f"ОШИБКА: {e}")
        return False


# Запуск проверки
simple_guest_account_check()