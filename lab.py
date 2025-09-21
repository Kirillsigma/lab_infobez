import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple
import winreg



@dataclass
class Result:
    control_id: str
    title: str
    status: str  # PASS | FAIL | ERROR | NOT_IMPLEMENTED
    expected: str
    actual: str


@dataclass
class Control:
    control_id: str
    title: str
    description: str
    rationale: str
    reference: str  # Это обязательное поле!
    check: Callable[[], Tuple[bool, str]] = field(default=lambda: (False, "NOT_IMPLEMENTED"))
    expected_text: str = "—"

    def run(self) -> Result:
        try:
            ok, actual = self.check()
            status = "PASS" if ok else "FAIL"
        except Exception as e:
            status, actual = "ERROR", f"{type(e).__name__}: {e}"
        return Result(
            control_id=self.control_id,
            title=self.title,
            status=status,
            expected=self.expected_text,
            actual=str(actual),
        )


def num_17_6_1():
    subcategory = "Сведения об общем файловом ресурсе"
    command = ['auditpol', '/get', '/subcategory:{}'.format(subcategory)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='cp866')
        output = result.stdout

        ok = ("failure" in output.lower() or "сбой" in output.lower() or "отказ" in output.lower())
        return ok, "Сбой включен" if ok else "Сбой отключен"

    except subprocess.CalledProcessError as e:
        return False, f"Ошибка выполнения команды: {e}"


def num_2_3_1_5():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                             0, winreg.KEY_READ)

        guest_name = winreg.QueryValueEx(key, "NewGuestName")[0]
        winreg.CloseKey(key)

        ok = (guest_name != "Guest" and guest_name != "Гость")
        return ok, f"Текущее имя: '{guest_name}'"

    except FileNotFoundError:
        return False, "Политика не настроена (используется 'Guest')"


def num_2_3_11_7():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "LmCompatibilityLevel")
        winreg.CloseKey(key)

        ok = (value == 5)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр не найден"

def num_2_3_10_10():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "RestrictRemoteSAM")
        winreg.CloseKey(key)

        ok = (value == "O:BAG:BAD:(A;;RC;;;BA)")
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр не найден"

def num_18_10_75_2_1():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\System",
            0,
            winreg.KEY_READ
        )

        value_1, reg_type_1 = winreg.QueryValueEx(key, "EnableSmartScreen")
        value_2, reg_type_2 = winreg.QueryValueEx(key, "ShellSmartScreenLevel")
        winreg.CloseKey(key)

        ok = (value_1 == 1 and value_2 == "Block")
        return ok, f"Текущее значение: {value_1} и {value_2}"

    except FileNotFoundError:
        return False, "Параметр не найден"

def num_18_10_56_3_3_2():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "fDisableCcm")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 1)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр fDisableCсm не найден в реестре (используется значение по умолчанию - разрешено)"

def num_5_19():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\wercplsupport",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "Start")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 4)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр Start не найден в реестре (используется значение по умолчанию - разрешено)"

def num_18_9_20_1_6():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "NoWebServices")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 1)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр NoWebServices не найден в реестре (используется значение по умолчанию - разрешено)"

def num_5_11():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\FTPSVC",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "Start")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 4)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр Start не найден в реестре (используется значение по умолчанию - Disabled or Not Installed)"

def num_18_5_11():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "TcpMaxDataRetransmissions")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 3)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр TcpMaxDataRetransmissions не найден в реестре (используется значение по умолчанию - Disabled or Not Installed)"

def num_18_10_92_4_1():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "ManagePreviewBuildsPolicyValue")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 1)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр ManagePreviewBuildsPolicyValue не найден в реестре (используется значение по умолчанию - Отключено)"

def num_9_3_9():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "LogSuccessfulConnections")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 1)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр LogSuccessfulConnections не найден в реестре (используется значение по умолчанию - Отключено)"

def num_18_10_9_3_11():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\FVE",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "RDVPassphrase")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 0)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр RDVPassphrase не найден в реестре (используется значение по умолчанию"

def num_18_9_4_2():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "AllowProtectedCreds")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 1)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр AllowProtectedCreds не найден в реестре (используется значение по умолчанию"

def num_18_10_9_2_5():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\FVE",
            0,
            winreg.KEY_READ
        )

        value, reg_type = winreg.QueryValueEx(key, "OSRecoveryPassword")
        winreg.CloseKey(key)

        print(value)
        ok = (value == 1)
        return ok, f"Текущее значение: {value}"

    except FileNotFoundError:
        return False, "Параметр OSRecoveryPassword не найден в реестре (используется значение по умолчанию)"

CONTROLS = [
    Control(
        control_id="17.6.1",
        title="Аудит: Detailed File Share включает 'Failure'",
        description="Ведёт аудит попыток доступа к файлам и папкам на общих ресурсах (события вроде 5145).",
        rationale="Фиксация неудачных попыток помогает расследовать попытки несанкционированного доступа.",
        reference="auditpol /get /subcategory:\"Detailed File Share\" → Setting: Failure (или Success and Failure)",
        check=num_17_6_1,
        expected_text="Включает Сбой"
    ),
    Control(
        control_id="2.3.1.5",
        title="Переименование гостевой учетной записи",
        description="Accounts: Rename guest account = переименовано",
        rationale="Защита от угадывания стандартного имени учетной записи.",
        reference="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\NewGuestName",
        check=num_2_3_1_5,
        expected_text="Имя отличное от 'Guest'"
    ),
    Control(
        control_id="2.3.11.7",
        title="Сетевая безопасность: уровень проверки подлинности LAN Manager",
        description="Определяет протокол аутентификации для сетевых входов",
        rationale="Защита от слабых протоколов аутентификации LM и NTLM",
        reference="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel",
        check=num_2_3_11_7,
        expected_text="5"
    ),
    Control(
        control_id="2.3.11.7",
        title="Сетевой доступ: ограничить клиентов, которым разрешено выполнять удаленные вызовы SAM",
        description="Определяет протокол аутентификации для сетевых входов",
        rationale="Защита от пользователей----",
        reference="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictRemoteSAM",
        check=num_2_3_10_10,
        expected_text="O:BAG:BAD:(A;;RC;;;BA)"
    ),
    Control(
        control_id="18.10.75.2.1",
        title="Настройка Windows Defender SmartScreen",
        description="Windows Defender SmartScreen помогает обеспечивать безопасность ПК",
        rationale="Предупреждая пользователей перед запуском нераспознанных программ, загруженных из Интернета",
        reference="SOFTWARE\Policies\Microsoft\Windows\System",
        check=num_18_10_75_2_1,
        expected_text="1"
    ),
    Control(
        control_id="18.10.56.3.3.2",
        title="Не разрешать перенаправление COM-портов",
        description="Блокирует перенаправление данных на COM-порты клиента в RDP-сессиях",
        rationale="Уменьшение поверхности атаки и предотвращение эксфильтрации данных",
        reference="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\fDisableCom",
        check=num_18_10_56_3_3_2,
        expected_text="1"
    ),
    Control(
        control_id="5.19",
        title="Поддержка панели управления отчетов о проблемах и их решений (wercplsupport)",
        description="Эта служба обеспечивает поддержку просмотра, отправки и удаления системных отчетов о проблемах для панели управления Отчеты о проблемах и их решения",
        rationale="Эта служба участвует в процессе отображения/отправки проблем и решений в/из Microsoft",
        reference="HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport:Start",
        check=num_5_19,
        expected_text="4"
    ),
    Control(
        control_id="18.9.20.1.6",
        title="Отключить загрузку из Интернета для мастеров веб-публикации и онлайн-заказов",
        description="Этот параметр политики управляет тем, будет ли Windows загружать список поставщиков для мастеров веб-публикации и онлайн-заказов",
        rationale="Windows предотвращает загрузку поставщиков; отображаются только поставщики услуг, сохраненные в локальном реестре.",
        reference="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoWebServices",
        check=num_18_9_20_1_6,
        expected_text="1 (включено)"
    ),
    Control(
        control_id="5.11",
        title="Обеспечение настройки «Служба Microsoft FTP (FTPSVC)» в значение «Отключено» или «Не установлено»",
        description="Позволяет серверу работать в качестве FTP-сервера (File Transfer Protocol).",
        rationale="Размещение FTP-сервера (особенно незащищенного FTP-сервера) на рабочей станции представляет повышенный риск безопасности, так как поверхность атаки этой рабочей станции значительно увеличивается.",
        reference="HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC:Start",
        check=num_5_11,
        expected_text="4 (Disabled)"
    ),
    Control(
        control_id="18.5.11",
        title=" Обеспечение настройки «MSS: (TcpMaxDataRetransmissions IPv6) Сколько раз повторно передаются неподтвержденные данные» в значение «Включено: 3»",
        description="Этот параметр контролирует количество повторных передач TCP отдельного сегмента данных (неподключенного сегмента) перед прерыванием соединения.",
        rationale="Злоумышленник может исчерпать ресурсы целевого компьютера, если он никогда не отправляет подтверждения для данных, переданных целевым компьютером.",
        reference="HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters:TcpMaxDataRetransmissions",
        check=num_18_5_11,
        expected_text="3 (Enabled)"
    ),
    Control(
        control_id="18.10.92.4.1",
        title="Обеспечение настройки «Управление сборками предварительной оценки» в значение «Отключено»",
        description="Этот параметр политики управляет тем, какие обновления получаются до официального выпуска обновления.",
        rationale="Разрешение экспериментальных функций в управляемой корпоративной среде может быть рискованным, поскольку это может привести к появлению ошибок и уязвимостей в системах, облегчая злоумышленнику получение доступа.",
        reference="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:ManagePreviewBuildsPolicyValue",
        check=num_18_10_92_4_1,
        expected_text="1"
    ),
    Control(
        control_id="9.3.9",
        title="Обеспечение настройки «Брандмауэр Windows: Общедоступная: Ведение журнала: Регистрировать успешные подключения» в значение «Да»",
        description="Используйте этот параметр, чтобы регистрировать случаи, когда Брандмауэр Windows в режиме повышенной безопасности разрешает входящее подключение. Журнал записывает, почему и когда было установлено подключение.",
        rationale="Если события не записываются, может быть трудно или невозможно определить первопричину проблем системы или несанкционированные действия злоумышленников.",
        reference="HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogSuccessfulConnections",
        check=num_9_3_9,
        expected_text="1"
    ),
    Control(
        control_id="18.10.9.3.11",
        title="Обеспечение настройки «Настройка использования паролей для съемных дисков данных»",
        description="Этот параметр политики позволяет указать, требуется ли пароль для разблокировки защищенных BitLocker съемных дисков данных.",
        rationale="Этот параметр применяется при включении BitLocker, а не при разблокировке диска. BitLocker позволит разблокировать диск с помощью любого из доступных на диске средств защиты.",
        reference="HKLM\SOFTWARE\Policies\Microsoft\FVE:RDVPassphrase",
        check=num_18_10_9_3_11,
        expected_text="0"
    ),
    Control(
        control_id="18.9.4.2",
        title="Обеспечение настройки «Удаленный узел разрешает делегирование неэкспортируемых учетных данных» в значение «Включено»",
        description="Удаленный узел разрешает делегирование неэкспортируемых учетных данных. При использовании делегирования учетных данных устройства предоставляют экспортируемую версию учетных данных удаленному узлу.",
        rationale="Режим ограниченного администратора был разработан для защиты учетных записей администраторов путем обеспечения того, чтобы повторно используемые учетные данные не хранились в памяти на удаленных устройствах, которые потенциально могут быть скомпрометированы.",
        reference="HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation:AllowProtectedCreds",
        check=num_18_9_4_2,
        expected_text="1"
    ),
    Control(
        control_id="18.10.9.2.5",
        title="Обеспечение настройки «Выбор способа восстановления защищенных BitLocker дисков операционной системы: Пароль восстановления» в значение «Включено",
        description="Этот параметр политики позволяет управлять способом восстановления защищенных BitLocker дисков операционной системы при отсутствии необходимой ключевой информации для запуска.",
        rationale="В разделе «Настройка хранения пользователем информации для восстановления BitLocker» выберите, разрешено ли пользователям создавать 48-значный пароль восстановления или 256-битный ключ восстановления, требуется это или запрещено.",
        reference="HKLM\SOFTWARE\Policies\Microsoft\FVE:OSRecoveryPassword",
        check=num_18_10_9_2_5,
        expected_text="1"
    )
]


def main():
    results = []
    for c in CONTROLS:
        results.append(c.run())

    implemented = [r for r in results if r.status in ("PASS", "FAIL", "ERROR")]
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    errors = sum(1 for r in results if r.status == "ERROR")
    not_impl = sum(1 for r in results if r.status == "NOT_IMPLEMENTED")

    md_path = "cis_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Отчёт по аудиту CIS\n\n")
        f.write(f"**ФИО:** Мелешко Кирилл Николаевич  \n")
        f.write(f"**Вариант:** 13  \n")
        f.write(f"**Дисциплина:** Информационная безопасность\n\n")
        f.write(f"**Итог:** реализовано {len(implemented)} проверок из {len(results)}"
                f"(PASS: {passed}, FAIL: {failed}, ERROR: {errors}; NOT_IMPLEMENTED: {not_impl}).\n\n")
        f.write("| № | Control ID | Статус | Название |\n")
        f.write("|---:|:---------:|:------:|:---------|\n")
        for i, r in enumerate(results, 1):
            f.write(f"| {i} | {r.control_id} | {r.status} | {r.title} |\n")
        f.write("\n---\n\n")
        for i, r in enumerate(results, 1):
            f.write(f"## {i}. {r.control_id} — {r.title}\n")
            f.write(f"- **Статус:** {r.status}\n")
            f.write(f"- **Ожидается:** {r.expected}\n")
            f.write(f"- **Фактически:** `{r.actual}`\n")
            # Добавляем reference в отчет
            control = CONTROLS[i - 1]
            f.write(f"- **Ссылка:** {control.reference}\n")
            f.write(f"- **Описание:** {control.description}\n")
            f.write(f"- **Обоснование:** {control.rationale}\n\n")

    print(f"Отчёт сохранен: {md_path}")


if __name__ == "__main__":
    main()