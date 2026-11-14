# By LainProject — Windows Java/Python Cheat Scanner
# Build: py -m pip install pyinstaller
#       py -m PyInstaller --onefile --windowed --name ByLainProject scanner.py
#
# Scope: Downloads and Desktop folders for all local user profiles on C:.
# This is a heuristic scanner, NOT an antivirus and cannot detect every cheat.
# Selected files are moved to a quarantine folder (reversible), not permanently
# deleted. Review every result before taking action.

import os
import sys
import re
import zipfile
import shutil
import ctypes
import threading
import queue
import hashlib
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

APP_NAME = "By LainProject"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
READ_LIMIT = 2 * 1024 * 1024      # inspect at most 2 MB per text file
SCAN_EXTENSIONS = {".jar", ".class", ".py", ".pyw", ".zip"}
QUARANTINE_NAME = "ByLainProject_Quarantine"

# Known Minecraft/client cheat names and common loader/injection indicators.
# These are indicators only: a match does not prove a file is malicious.
CHEAT_NAMES = [
    "wurst", "liquidbounce", "meteor", "raven", "vape", "rise client",
    "riseclient", "sigma client", "sigmaclient", "impact client", "impactclient",
    "aristois", "bleachhack", "inertia client", "inertiaclient", "future client",
    "futureclient", "konas", "astolfo", "novoline", "zeroday", "zero day",
    "jigsaw", "gamesense", " dortware", "lb++", "liquidbounceplus",
    "exhibition", "moon client", "moonclient", "intent.store", "tenacity",
    " augustus", "spider client", "spiderclient", "horion"
]
CHEAT_NAMES = [x.strip() for x in CHEAT_NAMES if x.strip()]

SUSPICIOUS_TOKENS = [
    "net/minecraft/client", "net.minecraft.client",
    "org/lwjgl", "org.lwjgl",
    "modmenu", "fabric.mod.json", "mixins.json",
    "autoclicker", "aimassist", "aim_assist", "kill_aura", "killaura",
    "velocity", "reach", "triggerbot", "anti-knockback", "antiknockback",
    "cheststealer", "scaffold", "clickgui", "clientmod",
    "javas.lang.instrument", "java.lang.instrument",
    "instrumentation", "attachlistener", "loadlibrary",
    "pynput", "pyautogui", "keyboard.add_hotkey"
]

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def request_admin_restart():
    """Ask Windows UAC and relaunch this script elevated."""
    if os.name != "nt" or is_admin():
        return True
    try:
        params = " ".join(f'"{x}"' for x in sys.argv)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return result > 32
    except Exception:
        return False

def get_scan_roots():
    roots = []
    base = Path("C:/Users")
    if base.exists():
        for profile in base.iterdir():
            if not profile.is_dir():
                continue
            if profile.name.lower() in {"public", "default", "default user", "all users"}:
                continue
            for folder in ("Downloads", "Desktop"):
                candidate = profile / folder
                if candidate.is_dir():
                    roots.append(candidate)
    return roots

def read_file_bytes(path):
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        with path.open("rb") as f:
            return f.read(READ_LIMIT)
    except (OSError, PermissionError):
        return None

def inspect_file(path):
    """Return (score, reasons). Uses names/content hints; no execution."""
    reasons = []
    score = 0
    name = path.name.lower()

    for token in CHEAT_NAMES:
        if token in name:
            score += 5
            reasons.append(f"Известное название в имени файла: {token}")
            break

    ext = path.suffix.lower()
    if ext not in SCAN_EXTENSIONS:
        return score, reasons

    data = read_file_bytes(path)
    if data is None:
        if reasons:
            reasons.append("Содержимое не прочитано (размер/доступ)")
        return score, reasons

    text = data.decode("utf-8", errors="ignore").lower()
    # For JAR/ZIP, inspect archive member names and a bounded amount of text
    # from small class/config files. Never extract or execute archive content.
    if ext in {".jar", ".zip"}:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = "\n".join(zf.namelist()).lower()
                for token in CHEAT_NAMES:
                    if token in names and token not in name:
                        score += 5
                        reasons.append(f"Название/пакет в архиве: {token}")
                        break
                hits = [t for t in SUSPICIOUS_TOKENS if t in names]
                if hits:
                    score += min(3, len(hits))
                    reasons.append("Подозрительные имена компонентов: " + ", ".join(hits[:4]))
                # Inspect only a few small text/config entries.
                inspected = 0
                for info in zf.infolist():
                    if inspected >= 12 or info.file_size > 256_000:
                        continue
                    if info.filename.lower().endswith((".json", ".txt", ".cfg", ".yml", ".properties")):
                        try:
                            chunk = zf.read(info)[:128_000].decode("utf-8", "ignore").lower()
                            for token in SUSPICIOUS_TOKENS:
                                if token in chunk:
                                    score += 1
                                    reasons.append(f"Индикатор в {info.filename}: {token}")
                                    break
                        except Exception:
                            pass
                        inspected += 1
        except (zipfile.BadZipFile, OSError, RuntimeError):
            reasons.append("Архив не удалось прочитать")
    else:
        for token in SUSPICIOUS_TOKENS:
            if token in text:
                score += 2
                reasons.append(f"Индикатор в содержимом: {token}")
                if len(reasons) >= 6:
                    break
        for token in CHEAT_NAMES:
            if token in text:
                score += 4
                reasons.append(f"Название в содержимом: {token}")
                break

    # Only report files with at least one meaningful signal.
    return score, reasons

class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1000x680")
        self.root.minsize(820, 560)
        self.root.configure(bg="#101116")
        self.events = queue.Queue()
        self.results = []
        self.rows = {}
        self.scanning = False
        self._style()
        self._build()
        self.root.after(100, self._poll)

    def _style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#191b23", foreground="#eeeeF4",
                        fieldbackground="#191b23", rowheight=28, borderwidth=0)
        style.configure("Treeview.Heading", background="#252835",
                        foreground="#c9c9d5", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#49316e")],
                  foreground=[("selected", "white")])
        style.configure("TProgressbar", troughcolor="#252835",
                        background="#9b6cff", thickness=9)

    def _build(self):
        top = tk.Frame(self.root, bg="#101116")
        top.pack(fill="x", padx=24, pady=(20, 8))
        tk.Label(top, text="BY LAINPROJECT", bg="#101116", fg="#b58aff",
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(top, text="JAVA / PYTHON CHEAT SCANNER", bg="#101116",
                 fg="#858797", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(2, 0))

        self.status = tk.Label(self.root, text="Готов к проверке",
                               bg="#101116", fg="#e9e9ef", font=("Segoe UI", 11))
        self.status.pack(anchor="w", padx=24, pady=(12, 8))

        stats = tk.Frame(self.root, bg="#191b23")
        stats.pack(fill="x", padx=24, pady=5)
        self.checked_var = tk.StringVar(value="Проверено файлов: 0")
        self.found_var = tk.StringVar(value="Обнаружено: 0")
        for var in (self.checked_var, self.found_var):
            tk.Label(stats, textvariable=var, bg="#191b23", fg="#eeeeF4",
                     font=("Segoe UI", 11, "bold"), padx=18, pady=14).pack(side="left")
        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=24, pady=(10, 14))

        buttons = tk.Frame(self.root, bg="#101116")
        buttons.pack(fill="x", padx=24, pady=(0, 12))
        self.scan_btn = tk.Button(buttons, text="НАЧАТЬ ПРОВЕРКУ НА ЧИТЫ",
            command=self.start_scan, bg="#8d5be8", fg="white",
            activebackground="#a77af3", activeforeground="white",
            relief="flat", padx=20, pady=12, font=("Segoe UI", 10, "bold"))
        self.scan_btn.pack(side="left")
        tk.Button(buttons, text="Выбрать все", command=self.select_all,
            bg="#292c38", fg="white", relief="flat", padx=14, pady=12).pack(side="left", padx=8)
        tk.Button(buttons, text="Снять выбор", command=self.clear_selection,
            bg="#292c38", fg="white", relief="flat", padx=14, pady=12).pack(side="left")
        tk.Button(buttons, text="В карантин выбранное", command=self.quarantine_selected,
            bg="#633f8f", fg="white", relief="flat", padx=14, pady=12).pack(side="right")

        columns = ("select", "name", "type", "score", "reason", "path")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings",
                                 selectmode="browse")
        headings = {"select": "Выбор", "name": "Имя файла", "type": "Тип",
                    "score": "Оценка", "reason": "Причина обнаружения", "path": "Путь"}
        widths = {"select": 58, "name": 170, "type": 60, "score": 65,
                  "reason": 260, "path": 300}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=45,
                             anchor="w", stretch=(col in {"reason", "path"}))
        self.tree.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        self.tree.bind("<Double-1>", self.toggle_row)

        self.footer = tk.Label(self.root,
            text="Проверяются только Java/Python-файлы и архивы в папках Downloads и Desktop профилей C:\\Users.",
            bg="#101116", fg="#777987", font=("Segoe UI", 8), wraplength=940)
        self.footer.pack(anchor="w", padx=24, pady=(0, 14))

    def start_scan(self):
        if self.scanning:
            return
        if os.name == "nt" and not is_admin():
            if messagebox.askyesno(APP_NAME,
                    "Для проверки запросить права администратора Windows?\n"
                    "Приложение перезапустится после подтверждения UAC."):
                if request_admin_restart():
                    self.root.destroy()
                    return
                messagebox.showwarning(APP_NAME, "Не удалось получить права администратора. Проверка продолжится с текущими правами.")
        roots = get_scan_roots()
        if not roots:
            messagebox.showerror(APP_NAME, "Не найдены папки Downloads/Desktop в C:\\Users.")
            return
        self.results.clear()
        self.rows.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.checked_var.set("Проверено файлов: 0")
        self.found_var.set("Обнаружено: 0")
        self.progress["value"] = 0
        self.status.config(text="Сканирование...")
        self.scanning = True
        self.scan_btn.config(state="disabled")
        threading.Thread(target=self._scan_worker, args=(roots,), daemon=True).start()

    def _scan_worker(self, roots):
        candidates = []
        for root in roots:
            for current, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d.lower() not in {
                    ".git", "__pycache__", "node_modules", ".venv", "venv"
                }]
                for filename in files:
                    p = Path(current) / filename
                    if p.suffix.lower() in SCAN_EXTENSIONS:
                        candidates.append(p)
        total = len(candidates)
        self.events.put(("total", total))
        checked = 0
        for path in candidates:
            score, reasons = inspect_file(path)
            checked += 1
            if score >= 2 and reasons:
                self.events.put(("found", str(path), score, reasons))
            if checked % 10 == 0 or checked == total:
                self.events.put(("progress", checked, total))
        self.events.put(("done", checked, total))

    def _poll(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "total":
                    self.progress["maximum"] = max(1, event[1])
                elif kind == "found":
                    _, path, score, reasons = event
                    p = Path(path)
                    iid = self.tree.insert("", "end", values=(
                        "☐", p.name, p.suffix.lower(), score,
                        "; ".join(reasons[:3]), str(p)))
                    self.rows[iid] = {"path": p, "selected": False,
                                      "score": score, "reasons": reasons}
                    self.found_var.set(f"Обнаружено: {len(self.rows)}")
                elif kind == "progress":
                    _, checked, total = event
                    self.progress["maximum"] = max(1, total)
                    self.progress["value"] = checked
                    self.checked_var.set(f"Проверено файлов: {checked}")
                elif kind == "done":
                    _, checked, total = event
                    self.scanning = False
                    self.scan_btn.config(state="normal")
                    self.status.config(text=f"Проверка завершена. Просмотрено файлов: {checked}")
                    messagebox.showinfo(APP_NAME,
                        f"Проверка завершена.\nПроверено файлов: {checked}\n"
                        f"Подозрительных совпадений: {len(self.rows)}\n\n"
                        "Проверьте каждую находку вручную: возможны ложные срабатывания.")
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def toggle_row(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self.rows:
            return
        item = self.rows[iid]
        item["selected"] = not item["selected"]
        vals = list(self.tree.item(iid, "values"))
        vals[0] = "☑" if item["selected"] else "☐"
        self.tree.item(iid, values=vals)

    def select_all(self):
        for iid, item in self.rows.items():
            item["selected"] = True
            vals = list(self.tree.item(iid, "values"))
            vals[0] = "☑"
            self.tree.item(iid, values=vals)

    def clear_selection(self):
        for iid, item in self.rows.items():
            item["selected"] = False
            vals = list(self.tree.item(iid, "values"))
            vals[0] = "☐"
            self.tree.item(iid, values=vals)

    def quarantine_selected(self):
        selected = [(iid, item) for iid, item in self.rows.items() if item["selected"]]
        if not selected:
            messagebox.showwarning(APP_NAME, "Сначала отметьте файлы двойным щелчком по строке.")
            return
        if not messagebox.askyesno(APP_NAME,
            f"Переместить в карантин выбранные файлы: {len(selected)}?\n"
            "Они не будут удалены навсегда. Проверьте список перед продолжением."):
            return
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / QUARANTINE_NAME
        base.mkdir(parents=True, exist_ok=True)
        moved, errors = 0, []
        for iid, item in selected:
            src = item["path"]
            try:
                if not src.exists():
                    raise FileNotFoundError("Файл уже отсутствует")
                # Preserve original path in filename metadata sidecar.
                digest = hashlib.sha256(str(src).encode("utf-8", "ignore")).hexdigest()[:10]
                dest = base / f"{src.stem}_{digest}{src.suffix}"
                n = 1
                while dest.exists():
                    dest = base / f"{src.stem}_{digest}_{n}{src.suffix}"
                    n += 1
                shutil.move(str(src), str(dest))
                (base / (dest.name + ".original_path.txt")).write_text(
                    str(src), encoding="utf-8")
                self.tree.delete(iid)
                del self.rows[iid]
                moved += 1
            except Exception as exc:
                errors.append(f"{src.name}: {exc}")
        self.found_var.set(f"Обнаружено: {len(self.rows)}")
        msg = f"Перемещено в карантин: {moved}\nПапка: {base}"
        if errors:
            msg += "\n\nОшибки:\n" + "\n".join(errors[:5])
        messagebox.showinfo(APP_NAME, msg)

if __name__ == "__main__":
    if os.name != "nt":
        print("By LainProject предназначен для Windows.")
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
