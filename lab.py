import subprocess
import winreg
from typing import Callable, List, Optional
import tkinter as tk
from tkinter import messagebox
from ttkbootstrap import Style
from ttkbootstrap.widgets import Frame, Button, Label, Treeview, Progressbar

root: Optional[tk.Tk] = None
progress: Optional[Progressbar] = None
tree: Optional[Treeview] = None

FIO = "Мелешко К.Н."
VARIANT = "13"
DISCIPLINE = "Информационная безопасность"

def verif_winreg(path: str, name: str):
    hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
    try:
        value, _ = winreg.QueryValueEx(hkey, name)
        return value
    finally:
        winreg.CloseKey(hkey)


def run_control(control: tuple[str, str, Callable[[], bool]]) -> tuple[str, str, str]:
    cid, title, func = control
    try:
        ok = func()
        status = "PASS" if ok else "FAIL"
    except Exception:
        status = "ERROR"
    return cid, title, status

def num_17_6_1() -> bool:
    subcategory = "Сведения об общем файловом ресурсе"
    command = ["auditpol", "/get", f"/subcategory:{subcategory}"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding="cp866")
        out = result.stdout.lower()
        return ("failure" in out) or ("сбой" in out) or ("отказ" in out)
    except subprocess.CalledProcessError:
        return False

def num_2_3_1_5() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                             0, winreg.KEY_READ)
        try:
            guest_name = winreg.QueryValueEx(key, "NewGuestName")[0]
        finally:
            winreg.CloseKey(key)
        return guest_name not in ("Guest", "Гость")
    except FileNotFoundError:
        return False

def num_2_3_11_7() -> bool:
    try:
        value = verif_winreg(r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel")
        return value == 5
    except FileNotFoundError:
        return False

def num_2_3_10_10() -> bool:
    try:
        value = verif_winreg(r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictRemoteSAM")
        return value == "O:BAG:BAD:(A;;RC;;;BA)"
    except FileNotFoundError:
        return False

def num_18_10_75_2_1() -> bool:
    try:
        v1 = verif_winreg(r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
        v2 = verif_winreg(r"SOFTWARE\Policies\Microsoft\Windows\System", "ShellSmartScreenLevel")
        return v1 == 1 and v2 == "Block"
    except FileNotFoundError:
        return False

def num_18_10_56_3_3_2() -> bool:
    try:
        v = verif_winreg(r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDisableCcm")
        return v == 1
    except FileNotFoundError:
        return False

def num_5_19() -> bool:
    try:
        v = verif_winreg(r"SYSTEM\CurrentControlSet\Services\wercplsupport", "Start")
        return v == 4
    except FileNotFoundError:
        return False

def num_18_9_20_1_6() -> bool:
    try:
        v = verif_winreg(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoWebServices")
        return v == 1
    except FileNotFoundError:
        return False

def num_5_11() -> bool:
    try:
        v = verif_winreg(r"SYSTEM\CurrentControlSet\Services\FTPSVC", "Start")
        return v == 4
    except FileNotFoundError:
        return False

def num_18_5_11() -> bool:
    try:
        v = verif_winreg(r"SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters", "TcpMaxDataRetransmissions")
        return v == 3
    except FileNotFoundError:
        return False

def num_18_10_92_4_1() -> bool:
    try:
        v = verif_winreg(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "ManagePreviewBuildsPolicyValue")
        return v == 1
    except FileNotFoundError:
        return False

def num_9_3_9() -> bool:
    try:
        v = verif_winreg(r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", "LogSuccessfulConnections")
        return v == 1
    except FileNotFoundError:
        return False

def num_18_10_9_3_11() -> bool:
    try:
        v = verif_winreg(r"SOFTWARE\Policies\Microsoft\FVE", "RDVPassphrase")
        return v == 0
    except FileNotFoundError:
        return False

def num_18_9_4_2() -> bool:
    try:
        v = verif_winreg(r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation", "AllowProtectedCreds")
        return v == 1
    except FileNotFoundError:
        return False

def num_18_10_9_2_5() -> bool:
    try:
        v = verif_winreg(r"SOFTWARE\Policies\Microsoft\FVE", "OSRecoveryPassword")
        return v == 1
    except FileNotFoundError:
        return False

CONTROLS: List[tuple[str, str, Callable[[], bool]]] = [
    ("17.6.1", "Аудит: Detailed File Share включает 'Failure'", num_17_6_1),
    ("2.3.1.5", "Переименование гостевой учетной записи", num_2_3_1_5),
    ("2.3.11.7", "Уровень проверки подлинности LAN Manager", num_2_3_11_7),
    ("2.3.10.10", "Сетевой доступ: ограничить клиентов, которым разрешено выполнять удаленные вызовы SAM", num_2_3_10_10),
    ("18.10.75.2.1", "Настройка Windows Defender SmartScreen", num_18_10_75_2_1),
    ("18.10.56.3.3.2", "Не разрешать перенаправление COM-портов", num_18_10_56_3_3_2),
    ("5.19", "Поддержка панели управления отчетов о проблемах и их решений (wercplsupport)о", num_5_19),
    ("18.9.20.1.6", "Отключить загрузку из Интернета для мастеров веб-публикации", num_18_9_20_1_6),
    ("5.11", "Служба Microsoft FTP (FTPSVC)", num_5_11),
    ("18.5.11", "MSS: (TcpMaxDataRetransmissions IPv6)", num_18_5_11),
    ("18.10.92.4.1", "Управление сборками предварительной оценки", num_18_10_92_4_1),
    ("9.3.9", "Брандмауэр Windows: Общедоступная: Ведение журнала: Регистрировать успешные подключения", num_9_3_9),
    ("18.10.9.3.11", "Настройка использования паролей для съемных дисков данных", num_18_10_9_3_11),
    ("18.9.4.2", "Удаленный узел разрешает делегирование учетных данных»", num_18_9_4_2),
    ("18.10.9.2.5", "Выбор способа восстановления защищенных BitLocker дисков операционной системы", num_18_10_9_2_5),
]

def show_help():
    help_win = tk.Toplevel(root)
    help_win.title("Справка")
    help_win.geometry("520x330")
    help_win.resizable(False, False)

    Style(theme="minty")

    help_frame = Frame(help_win, bootstyle="info")
    help_frame.pack(fill="both", expand=True, padx=15, pady=15)

    Label(help_frame, text="Справка о программе", font=("Arial", 18, "bold"),
          bootstyle="inverse-info").pack(pady=10)
    Label(help_frame, text=f"ФИО: {FIO}", font=("Arial", 13, "bold"),
          bootstyle="dark").pack(pady=5)
    Label(help_frame, text=f"Вариант: {VARIANT}", font=("Arial", 13),
          bootstyle="dark").pack(pady=5)
    Label(help_frame, text=f"Дисциплина:\n{DISCIPLINE}", font=("Arial", 13),
          bootstyle="dark").pack(pady=5)

    Label(
        help_frame,
        text="Программа выполняет аудит конфигурации Windows\n"
             "на соответствие стандарту безопасности CIS Benchmark.",
        font=("Arial", 11),
        bootstyle="secondary"
    ).pack(pady=10)

    Button(help_frame, text="Закрыть", bootstyle="danger-outline",
           command=help_win.destroy, width=15).pack(pady=15)

def run_analysis():
    for row_id in tree.get_children():
        tree.delete(row_id)

    total = len(CONTROLS)
    passed = 0

    progress.configure(maximum=total)
    progress["value"] = 0

    for ctrl in CONTROLS:
        cid, title, status = run_control(ctrl)
        tag = "success" if status == "PASS" else "fail"
        tree.insert("", "end", values=(cid, title, status), tags=(tag,))
        if status == "PASS":
            passed += 1
        progress["value"] += 1
        root.update_idletasks()

    tree.tag_configure("success", foreground="green")
    tree.tag_configure("fail", foreground="red")

    messagebox.showinfo("Итог", f"Выполнено {passed} из {total} проверок")


def main():
    global root, progress, tree
    root = tk.Tk()
    root.title("Анализ безопасности Windows (CIS Benchmark)")
    root.geometry("1200x650")

    Style(theme="minty")

    frame = Frame(root)
    frame.pack(fill="both", expand=True, padx=10, pady=10)

    Label(frame, text="Анализ конфигурации Windows по CIS Benchmark",
          font=("Calibri", 18, "bold")).pack(pady=10)

    btns = Frame(frame)
    btns.pack(pady=5)
    Button(btns, text="Запустить анализ", bootstyle="success-outline",
           command=run_analysis, width=20).pack(side="left", padx=5)
    Button(btns, text="Справка", bootstyle="info-outline",
           command=show_help, width=20).pack(side="left", padx=5)
    Button(btns, text="Выход", bootstyle="danger-outline",
           command=root.destroy, width=20).pack(side="left", padx=5)

    progress = Progressbar(frame, bootstyle="striped-success", length=600)
    progress.pack(pady=15)

    columns = ("Код", "Название", "Статус")
    tree = Treeview(frame, columns=columns, show="headings", height=18, bootstyle="info")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=300)
    tree.pack(fill="both", expand=True, pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
