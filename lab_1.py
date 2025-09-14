# -*- coding: utf-8 -*-


import argparse
import csv
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

try:
    import winreg  # type: ignore
except ImportError:
    print("Этот скрипт предназначен для Windows: требуется модуль winreg.", file=sys.stderr)
    sys.exit(1)


# -------------------------- Утилиты --------------------------

def run(cmd: str) -> Tuple[int, str, str]:
    """Запуск команды в оболочке, возврат (rc, stdout, stderr)."""
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out.strip(), err.strip()


def read_registry(hive: str, path: str, name: str) -> Optional[Any]:
    """
    Прочитать значение из реестра.
    hive: 'HKLM' | 'HKCU'
    """
    root = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}.get(hive.upper())
    if root is None:
        raise ValueError("hive must be HKLM or HKCU")
    try:
        with winreg.OpenKey(root, path) as key:
            val, _typ = winreg.GetValue(f"{hive}\\{path}", name)
            return val
    except FileNotFoundError:
        try:
            with winreg.OpenKey(root, path) as key:
                val, _typ = winreg.QueryValueEx(key, name)
                return val
        except Exception:
            return None
    except Exception:
        return None


def get_service_state(service_name: str) -> Optional[str]:
    """
    Вернуть состояние службы через sc query (RUNNING/STOPPED/PAUSED/...).
    """
    rc, out, _ = run(f'sc query "{service_name}"')
    if rc != 0:
        return None
    m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", out, flags=re.IGNORECASE)
    return m.group(1).upper() if m else None


def export_secedit() -> Dict[str, str]:
    """
    Экспорт локальной политики безопасности в INI и чтение ключей.
    Возвращает плоский dict: {'MinimumPasswordLength': '14', ...}
    """
    cfg = {}
    with tempfile.TemporaryDirectory() as td:
        out_ini = os.path.join(td, "secpol.ini")
        # areas: SECURITYPOLICY (Account Policies + Security Options) + USER_RIGHTS
        rc, out, err = run(f'secedit /export /cfg "{out_ini}" /areas SECURITYPOLICY USER_RIGHTS')
        if rc != 0:
            return cfg
        try:
            with open(out_ini, "r", encoding="utf-16-le", errors="ignore") as f:
                text = f.read()
        except UnicodeError:
            with open(out_ini, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        for line in text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def get_auditpol() -> Dict[str, str]:
    """
    Считать текущую расширенную аудит-политику.
    Возвращает {'Logon': 'Success and Failure', ...}
    """
    rc, out, err = run('auditpol /get /category:*')
    result: Dict[str, str] = {}
    if rc != 0:
        return result
    # строки вида: "Logon                         Success and Failure"
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("---") or line.lower().startswith("category") or line.lower().startswith("system audit policy"):
            continue
        parts = re.split(r"\s{2,}", line)
        if len(parts) >= 2:
            subcat, setting = parts[0].strip(), parts[-1].strip()
            result[subcat] = setting
    return result


def get_firewall_profiles() -> Dict[str, str]:
    """
    netsh advfirewall show allprofiles => {'Domain Profile Settings': 'ON', ...}
    Возвращаем {'Domain': 'ON', 'Private': 'ON', 'Public': 'ON'}
    """
    rc, out, err = run("netsh advfirewall show allprofiles")
    profiles = {"Domain": "UNKNOWN", "Private": "UNKNOWN", "Public": "UNKNOWN"}
    if rc != 0:
        return profiles
    current = None
    for line in out.splitlines():
        if "Domain Profile Settings" in line:
            current = "Domain"
        elif "Private Profile Settings" in line:
            current = "Private"
        elif "Public Profile Settings" in line:
            current = "Public"
        m = re.search(r"State\s*(ON|OFF)", line, flags=re.IGNORECASE)
        if current and m:
            profiles[current] = m.group(1).upper()
    return profiles


def is_smb1_disabled() -> Tuple[bool, str]:
    """
    Проверяем отключение SMBv1 двумя способами:
    1) Реестр SMB1 = 0
    2) DISM /online /Get-Features /Format:Table -> FeatureName: SMB1Protocol = Disabled
    """
    reg_val = read_registry("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    reg_ok = (reg_val == 0)  # 0 = Off
    rc, out, err = run("dism /online /Get-Features /Format:Table")
    feat_ok = False
    if rc == 0:
        for line in out.splitlines():
            if "SMB1Protocol" in line:
                if "Disabled" in line:
                    feat_ok = True
                break
    return (reg_ok and feat_ok), f"Registry SMB1={reg_val!r}; DISM SMB1Protocol Disabled={feat_ok}"


# -------------------------- Модель контроля --------------------------

@dataclass
class Result:
    control_id: str
    title: str
    status: str              # PASS | FAIL | ERROR | NOT_IMPLEMENTED
    expected: str
    actual: str
    description: str
    rationale: str
    reference: str


@dataclass
class Control:
    control_id: str
    title: str
    description: str
    rationale: str
    reference: str
    check: Callable[[], Tuple[bool, str]] = field(default=lambda: (False, "NOT_IMPLEMENTED"))
    expected_text: str = "—"

    def run(self) -> Result:
        try:
            ok, actual = self.check()
            status = ok
        except Exception as e:
            status, actual = "ERROR", f"{type(e).__name__}: {e}"
        return Result(
            control_id=self.control_id,
            title=self.title,
            status=status,
            expected=self.expected_text,
            actual=str(actual),
            description=self.description,
            rationale=self.rationale,
            reference=self.reference
        )


# -------------------------- Реализация проверок --------------------------

def chk_2_3_1_5():
    # Limit blank passwords to console logon only = Enabled (1)
    val = read_registry("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse")
    return (val == 1), f"HKLM\\...\\Lsa\\LimitBlankPasswordUse={val!r}"

def chk_2_3_11_7():
    # LAN Manager auth level >= 5  ("Send NTLMv2 response only. Refuse LM & NTLM")
    val = read_registry("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel")
    return (isinstance(val, int) and val >= 5), f"LmCompatibilityLevel={val!r}"

def chk_2_3_10_10():
    # Microsoft network server: Digitally sign communications (always) = Enabled (1)
    val = read_registry("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature")
    return (val == 1), f"RequireSecuritySignature={val!r}"

def chk_5_11():
    # Minimum password length >= 14 (подправьте порог под ваш CIS)
    sec = export_secedit()
    val = int(sec.get("MinimumPasswordLength", "0") or "0")
    return (val >= 14), f"MinimumPasswordLength={val}"

def chk_5_19():
    # Password must meet complexity requirements = Enabled (1)
    sec = export_secedit()
    val = int(sec.get("PasswordComplexity", "0") or "0")
    return (val == 1), f"PasswordComplexity={val}"

def chk_18_9_26_1_6():
    # Require user authentication for remote connections by using NLA = Enabled (1)
    val = read_registry("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
    return (val == 1), f"UserAuthentication={val!r}"

def chk_18_5_11():
    # Firewall ON on all profiles
    prof = get_firewall_profiles()
    ok = all(v == "ON" for v in prof.values())
    return ok, f"Firewall profiles: {prof}"

def chk_18_10_92_4_1():
    # SMBv1 disabled
    ok, note = is_smb1_disabled()
    return ok, note

def chk_18_9_4_2():
    # Turn off AutoPlay/AutoRun via policy
    val = read_registry("HKLM", r"Software\Policies\Microsoft\Windows\Explorer", "NoAutoplay")
    return (val == 1), f"NoAutoplay={val!r}"

def chk_18_10_75_2_1():
    # Disable consumer features (Microsoft consumer experiences) = Enabled (1)
    val = read_registry("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableConsumerFeatures")
    return (val == 1), f"DisableConsumerFeatures={val!r}"

def not_implemented():
    return False, "NOT_IMPLEMENTED"

def chk_17_6_1():
    """
    17.6.1 – Ensure 'Audit Detailed File Share' is set to include 'Failure'
    PASS, если настройка содержит Failure (или 'Success and Failure').
    Делает «красивый» вывод в консоль и возвращает (ok, actual).
    """
    # Имена подкатегории на ENG/RU — пробуем оба
    subcats = ['Detailed File Share', 'Сведения об общем файловом ресурсе']

    setting = None
    last_out = ""
    for name in subcats:
        rc, out, err = run(f'auditpol /get /subcategory:"{name}"')
        if rc == 0 and out.strip():
            last_out = out
            print("──────────────────────────────────────────────────────────────")
            print(f"[CMD] auditpol /get /subcategory:\"{name}\"")
            print("──────────────────────────────────────────────────────────────")
            print(out)
            print("──────────────────────────────────────────────────────────────")
            m = re.search(r"Setting\s*:\s*(.+)", out, re.IGNORECASE)
            if m:
                setting = m.group(1).strip()
                break

    # Фоллбэк: читаем сводную таблицу, если прямой запрос не сработал
    if setting is None:
        pol = get_auditpol()
        setting = pol.get('Detailed File Share') or pol.get('Сведения об общем файловом ресурсе')
        if setting:
            print("[INFO] Взято из auditpol /get /category:*  → Detailed File Share =", setting)
        else:
            print("[WARN] Не удалось распарсить значение из вывода auditpol.")
            if last_out:
                print(last_out)

    ok = False
    if isinstance(setting, str):
        low = setting.lower()
        ok = ("failure" in low) and ("no auditing" not in low)

    tag = "[SUCCESS]" if ok else "[FAIL]"
    print(f"{tag} 17.6.1 — 'Detailed File Share' = {setting!r} (нужно включать хотя бы Failure)")

    # для отчёта
    return ok, f"Auditpol: Detailed File Share={setting!r}"


# -------------------------- Описание контролей --------------------------

CONTROLS = [
    Control(
        "17.6.1",
        "Аудит: Detailed File Share включает 'Failure'",
        "Ведёт аудит попыток доступа к файлам и папкам на общих ресурсах (события вроде 5145).",
        "Фиксация неудачных попыток помогает расследовать попытки несанкционированного доступа.",
        "auditpol /get /subcategory:\"Detailed File Share\" → Setting: Failure (или Success and Failure)",
        check=chk_17_6_1,
        expected_text="Включает Failure (OK также 'Success and Failure')"
    ),
    Control(
        "2.3.1.5",
        "Ограничить использование пустых паролей только локальным входом",
        "Accounts: Limit local account use of blank passwords to console logon only = Enabled",
        "Блокирует удаленные попытки входа с пустыми паролями.",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse = 1",
        check=chk_2_3_1_5,
        expected_text="1 (Enabled)"
    ),
    Control(
        "2.3.11.7",
        "Уровень аутентификации LAN Manager",
        "Network security: LAN Manager authentication level ≥ 5 (NTLMv2 only, refuse LM & NTLM).",
        "Снижает риски перехвата/даунгрейда аутентификации.",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel ≥ 5",
        check=chk_2_3_11_7,
        expected_text="≥ 5"
    ),
    Control(
        "2.3.10.10",
        "Подписывать коммуникации SMB (всегда)",
        "Microsoft network server: Digitally sign communications (always) = Enabled.",
        "Защищает от атак «man-in-the-middle» на SMB.",
        r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature = 1",
        check=chk_2_3_10_10,
        expected_text="1 (Enabled)"
    ),
    Control(
        "18.10.75.2.1",
        "Отключить потребительские функции (Consumer Experience)",
        "Turn off Microsoft consumer experiences = Enabled.",
        "Убирает навязчивые приложения/рекомендации, снижает шум и телеметрию.",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableConsumerFeatures = 1",
        check=chk_18_10_75_2_1,
        expected_text="1 (Enabled)"
    ),
    Control(
        "18.10.56.3.3.2",
        "TODO: Уточните параметр (18.10.56.3.3.2)",
        "Заглушка. 18.10.* — раздел Administrative Templates; подпункты зависят от версии CIS.",
        "Требуется точная привязка к вашей версии, иначе возможны ложные срабатывания.",
        "Подставьте конкретный ключ реестра/политику из вашего CIS.",
        check=not_implemented,
        expected_text="См. ваш CIS (18.10.56.3.3.2)"
    ),
    Control(
        "5.19",
        "Сложность пароля",
        "Password must meet complexity requirements = Enabled.",
        "Защита от простых паролей; требуются буквы разного регистра, цифры и спецсимволы.",
        "secedit: PasswordComplexity = 1",
        check=chk_5_19,
        expected_text="1 (Enabled)"
    ),
    Control(
        "18.9.26.1.6",
        "Требовать NLA для RDP",
        "Require user authentication for remote connections by using NLA = Enabled.",
        "Защищает RDP от неаутентифицированного подключения и части атак на протокол.",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 1",
        check=chk_18_9_26_1_6,
        expected_text="1 (Enabled)"
    ),
    Control(
        "5.11",
        "Минимальная длина пароля",
        "Minimum password length ≥ 14 (скорректируйте под вашу редакцию CIS).",
        "Длинный пароль значительно усложняет перебор.",
        "secedit: MinimumPasswordLength ≥ 14",
        check=chk_5_11,
        expected_text="≥ 14"
    ),
    Control(
        "18.5.11",
        "Брандмауэр включен во всех профилях",
        "Windows Defender Firewall: Domain/Private/Public = ON.",
        "Блокирует нежеланные входящие подключения вне разрешённых правил.",
        "netsh advfirewall show allprofiles → State ON",
        check=chk_18_5_11,
        expected_text="Domain/Private/Public = ON"
    ),
    Control(
        "18.10.92.4.1",
        "Отключить SMBv1",
        "SMBv1 должен быть отключен (реестр + Windows Feature).",
        "Старый небезопасный протокол уязвим для множества атак (EternalBlue и др.).",
        "HKLM\\...\\LanmanServer\\Parameters\\SMB1 = 0 и DISM: SMB1Protocol = Disabled",
        check=chk_18_10_92_4_1,
        expected_text="Отключен (0 / Disabled)"
    ),
    Control(
        "9.3.9",
        "TODO: Уточните подпункт аудита (9.3.9)",
        "Заглушка. Раздел 9.x обычно касается Advanced Audit Policy.",
        "Неверная привязка может дать ложные выводы.",
        "Подставьте нужную подкатегорию из auditpol.",
        check=not_implemented,
        expected_text="См. ваш CIS (9.3.9)"
    ),
    Control(
        "18.10.9.3.11",
        "TODO: Уточните параметр (18.10.9.3.11)",
        "Заглушка Administrative Templates.",
        "Требуется точный ключ/политика из вашей версии CIS.",
        "См. ваш CIS.",
        check=not_implemented,
        expected_text="См. ваш CIS (18.10.9.3.11)"
    ),
    Control(
        "18.9.4.2",
        "Отключить автозапуск/автовоспроизведение",
        "Turn off Autoplay = Enabled (или NoAutoplay=1).",
        "Предотвращает авто-выполнение с внешних носителей.",
        r"HKLM\Software\Policies\Microsoft\Windows\Explorer\NoAutoplay = 1",
        check=chk_18_9_4_2,
        expected_text="1 (Enabled)"
    ),
    Control(
        "18.10.9.2.5",
        "TODO: Уточните параметр (18.10.9.2.5)",
        "Заглушка Administrative Templates.",
        "Требуется точный ключ/политика из вашей версии CIS.",
        "См. ваш CIS.",
        check=not_implemented,
        expected_text="См. ваш CIS (18.10.9.2.5)"
    ),
]


# -------------------------- Генерация отчёта --------------------------

def main():
    ap = argparse.ArgumentParser(description="CIS Windows Audit (Python)")
    ap.add_argument("--full-name", required=True, help="ФИО")
    ap.add_argument("--variant", required=True, type=int, help="Вариант")
    ap.add_argument("--discipline", required=True, help="Дисциплина")
    args = ap.parse_args()

    results = []
    for c in CONTROLS:
        results.append(c.run())

    # Сводка
    implemented = [r for r in results if r.status in ("PASS", "FAIL", "ERROR")]
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    errors = sum(1 for r in results if r.status == "ERROR")
    not_impl = sum(1 for r in results if r.status == "NOT_IMPLEMENTED")

    print("\n=== CIS Audit Summary ===")
    print(f"ФИО: {args.full_name} | Вариант: {args.variant} | Дисциплина: {args.discipline}")
    print(f"Всего пунктов в варианте: {len(results)}")
    print(f"Реализовано проверок: {len(implemented)} (PASS: {passed}, FAIL: {failed}, ERROR: {errors})")
    print(f"Не реализовано (требуют маппинга): {not_impl}")
    print()

    # CSV
    csv_path = "cis_report.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["№", "Control ID", "Название", "Статус", "Ожидается", "Фактически", "Описание", "Обоснование", "Ссылка/ключ"])
        for i, r in enumerate(results, 1):
            w.writerow([i, r.control_id, r.title, r.status, r.expected, r.actual, r.description, r.rationale, r.reference])

    # Markdown
    md_path = "cis_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Отчёт по аудиту CIS\n\n")
        f.write(f"**ФИО:** {args.full_name}  \n")
        f.write(f"**Вариант:** {args.variant}  \n")
        f.write(f"**Дисциплина:** {args.discipline}\n\n")
        f.write(f"**Итог:** реализовано {len(implemented)} проверок из {len(results)} "
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
            f.write(f"- **Описание:** {r.description}\n")
            f.write(f"- **Обоснование:** {r.rationale}\n")
            f.write(f"- **Ссылка/ключ:** {r.reference}\n\n")

    print(f"Отчёты сохранены: {csv_path}, {md_path}")


if __name__ == "__main__":
    main()
