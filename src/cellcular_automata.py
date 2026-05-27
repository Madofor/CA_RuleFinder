import json
import hashlib
import math
from dataclasses import dataclass
import random
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

GRID_SIZE = 32
CELL_SIZE = 18
DEFAULT_ITERATIONS = 10
NIST_PASS_TARGET = 9

BASE_DIR = Path(__file__).resolve().parent
RULES_FILE = BASE_DIR / "ca_rules.json"
FIELD_NIST_CACHE_FILE = BASE_DIR / "field_nist_cache.json"

NEIGHBOR_ORDER = [
    (-1, -1), (-1, 0), (-1, 1),
    (0, -1),           (0, 1),
    (1, -1),  (1, 0),  (1, 1),
]

def generate_rule_by_neighbor_count(active_counts: List[int]) -> Dict[str, str]:
    outputs: Dict[str, str] = {}
    for value in range(256):
        bits = format(value, "08b")
        outputs[bits] = "1" if bits.count("1") in active_counts else "0"
    return outputs

class PersistentSearchCache:
    def __init__(self, file_path: Path, save_every: int = 100):
        self.file_path = file_path
        self.save_every = save_every
        self.failed_set = set()
        self.passed_set = set()
        self.pending_changes = 0
        self.data = self._load()

    def _load(self) -> dict:
        if self.file_path.exists():
            try:
                with self.file_path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
                if isinstance(data, dict):
                    failed = data.get("failed", [])
                    passed = data.get("passed", [])
                    self.failed_set = set(failed if isinstance(failed, list) else [])
                    self.passed_set = set(passed if isinstance(passed, list) else [])
                    return {"failed": list(self.failed_set), "passed": list(self.passed_set)}
            except Exception:
                pass
        self.failed_set = set()
        self.passed_set = set()
        return {"failed": [], "passed": []}

    def save(self, force: bool = True) -> None:
        if not force and self.pending_changes < self.save_every:
            return
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"failed": sorted(self.failed_set), "passed": sorted(self.passed_set)}
        with self.file_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
        self.data = data
        self.pending_changes = 0

    def flush(self) -> None:
        self.save(force=True)

    def has_failed(self, signature: str) -> bool:
        return signature in self.failed_set

    def add_failed(self, signature: str) -> None:
        if signature not in self.failed_set:
            self.failed_set.add(signature)
            self.pending_changes += 1
            self.save(force=False)

    def add_passed(self, signature: str) -> None:
        if signature not in self.passed_set:
            self.passed_set.add(signature)
            self.pending_changes += 1
            self.save(force=False)

    @staticmethod
    def make_signature(parts: List[str]) -> str:
        joined = "||".join(parts)
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

class RuleManager:
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.rules = self._load_rules()

    def _normalize_rule(self, rule_data: Dict) -> Dict[str, Dict[str, str] | str]:
        rule_type = rule_data.get("type", "pattern")
        outputs = rule_data.get("outputs", {})
        normalized_outputs: Dict[str, str] = {}
        for value in range(256):
            bits = format(value, "08b")
            normalized_outputs[bits] = str(outputs.get(bits, "0"))
        return {"type": rule_type, "outputs": normalized_outputs}

    def _load_rules(self) -> Dict[str, Dict[str, Dict[str, str] | str]]:
        if self.file_path.exists():
            try:
                with self.file_path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
                if isinstance(data, dict) and data:
                    return {name: self._normalize_rule(rule) for name, rule in data.items()}
            except Exception:
                pass

        self._save_rules(DEFAULT_RULES)
        return {name: self._normalize_rule(rule) for name, rule in DEFAULT_RULES.items()}

    def _save_rules(self, rules: Dict[str, Dict[str, Dict[str, str] | str]]) -> None:
        with self.file_path.open("w", encoding="utf-8") as file:
            json.dump(rules, file, ensure_ascii=False, indent=2)

    def get_rules(self) -> Dict[str, Dict[str, Dict[str, str] | str]]:
        return self.rules

    def get_rule(self, name: str) -> Dict[str, Dict[str, str] | str]:
        return self.rules[name]

    def add_rule(self, name: str, outputs: Dict[str, str]) -> None:
        self.rules[name] = self._normalize_rule({"type": "pattern", "outputs": outputs})
        self._save_rules(self.rules)

    def update_rule(self, old_name: str, new_name: str, outputs: Dict[str, str]) -> None:
        normalized = self._normalize_rule({"type": "pattern", "outputs": outputs})
        if old_name != new_name and old_name in self.rules:
            del self.rules[old_name]
        self.rules[new_name] = normalized
        self._save_rules(self.rules)

    def delete_rule(self, name: str) -> None:
        if name in self.rules:
            del self.rules[name]
            self._save_rules(self.rules)

    def add_rule_from_hash(self, hash_text: str, name: Optional[str] = None) -> str:
        cleaned_hash = "".join(
            symbol.lower()
            for symbol in hash_text.strip()
            if symbol.lower() in "0123456789abcdef"
        )

        if len(cleaned_hash) != 64:
            raise ValueError("Хеш правила має містити рівно 64 hex-символи.")

        rule_bits = "".join(f"{int(symbol, 16):04b}" for symbol in cleaned_hash)

        outputs: Dict[str, str] = {}
        for value in range(256):
            pattern = format(value, "08b")
            outputs[pattern] = rule_bits[value]

        base_name = name.strip() if name and name.strip() else f"Hash rule {cleaned_hash[:8]}"
        unique_name = self.generate_unique_rule_name(base_name)
        self.add_rule(unique_name, outputs)
        return unique_name

    def generate_unique_rule_name(self, base_name: str) -> str:
        if base_name not in self.rules:
            return base_name
        index = 2
        while f"{base_name} {index}" in self.rules:
            index += 1
        return f"{base_name} {index}"

class CellularAutomaton:
    def __init__(self, size: int = GRID_SIZE):
        self.size = size
        self.grid = self.random_grid()

    def random_grid(self) -> List[List[int]]:
        return [[random.randint(0, 1) for _ in range(self.size)] for _ in range(self.size)]

    def set_random_grid(self) -> None:
        self.grid = self.random_grid()

    def set_grid(self, grid: List[List[int]]) -> None:
        self.grid = [row[:] for row in grid]

    def save_grid_to_file(self, file_path: str) -> None:
        data = {
            "size": self.size,
            "grid": self.grid,
        }
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)

    def load_grid_from_file(self, file_path: str) -> None:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        size = int(data["size"])
        grid = data["grid"]
        if size != self.size:
            raise ValueError(f"Розмір поля у файлі: {size}, очікуваний розмір: {self.size}")
        if len(grid) != self.size or any(len(row) != self.size for row in grid):
            raise ValueError("Некоректні розміри матриці поля у файлі.")
        normalized = []
        for row in grid:
            normalized.append([1 if int(cell) else 0 for cell in row])
        self.grid = normalized

    def get_neighbor_pattern(self, row: int, col: int) -> str:
        bits = []
        for row_offset, col_offset in NEIGHBOR_ORDER:
            neighbor_row = (row + row_offset) % self.size
            neighbor_col = (col + col_offset) % self.size
            bits.append(str(self.grid[neighbor_row][neighbor_col]))
        return "".join(bits)

    def step(self, rule: Dict[str, Dict[str, str] | str]) -> None:
        new_grid = [[0 for _ in range(self.size)] for _ in range(self.size)]
        outputs = rule["outputs"]

        for row in range(self.size):
            for col in range(self.size):
                pattern = self.get_neighbor_pattern(row, col)
                new_grid[row][col] = int(outputs.get(pattern, "0"))

        self.grid = new_grid

    def grid_to_bits(self, mode: str = "mixed", step_index: int = 0) -> str:
        if mode == "row":
            return "".join(str(cell) for row in self.grid for cell in row)
        if mode == "column":
            return "".join(str(self.grid[row][col]) for col in range(self.size) for row in range(self.size))
        if mode == "diagonal":
            bits = []
            for diagonal_sum in range(self.size * 2 - 1):
                for row in range(self.size):
                    col = diagonal_sum - row
                    if 0 <= col < self.size:
                        bits.append(str(self.grid[row][col]))
            return "".join(bits)
        if mode == "zigzag":
            bits = []
            for row_index, row in enumerate(self.grid):
                source = row if row_index % 2 == 0 else list(reversed(row))
                bits.extend(str(cell) for cell in source)
            return "".join(bits)
        if mode == "shuffled":
            coords = [(row, col) for row in range(self.size) for col in range(self.size)]
            rng = random.Random(20260512 + step_index)
            rng.shuffle(coords)
            return "".join(str(self.grid[row][col]) for row, col in coords)

        modes = ("row", "column", "diagonal", "zigzag", "shuffled")
        selected_mode = modes[step_index % len(modes)]
        return self.grid_to_bits(selected_mode, step_index)

class CryptoEngine:
    @staticmethod
    def text_to_bits(text: str) -> str:
        data = text.encode("utf-8")
        return "".join(f"{byte:08b}" for byte in data)

    @staticmethod
    def bits_to_text(bits: str) -> str:
        bytes_list = []
        for index in range(0, len(bits), 8):
            chunk = bits[index:index + 8]
            if len(chunk) == 8:
                bytes_list.append(int(chunk, 2))
        data = bytes(bytes_list).rstrip(b"\x00")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace")

    @staticmethod
    def normalize_message_bits_from_text(text: str, required_length: int = 1024) -> str:
        bit_string = CryptoEngine.text_to_bits(text)
        if len(bit_string) > required_length:
            bit_string = bit_string[:required_length]
        return bit_string.ljust(required_length, "0")

    @staticmethod
    def split_into_blocks(bits: str, block_size: int = 8) -> List[str]:
        return [bits[index:index + block_size] for index in range(0, len(bits), block_size)]

    @staticmethod
    def xor_bits(first_bits: str, second_bits: str) -> str:
        return "".join("1" if left != right else "0" for left, right in zip(first_bits, second_bits))

    @staticmethod
    def bits_to_hex(bits: str) -> str:
        if not bits:
            return ""
        return "".join(f"{int(bits[index:index + 8], 2):02x}" for index in range(0, len(bits), 8))

    @staticmethod
    def hex_to_bits(hex_text: str, required_length: int = 1024) -> str:
        cleaned_hex = "".join(symbol for symbol in hex_text.strip() if symbol.lower() in "0123456789abcdef")
        if len(cleaned_hex) % 2 != 0:
            cleaned_hex = "0" + cleaned_hex

        if not cleaned_hex:
            return "0" * required_length

        bit_string = "".join(
            f"{int(cleaned_hex[index:index + 2], 16):08b}"
            for index in range(0, len(cleaned_hex), 2)
        )
        if len(bit_string) > required_length:
            bit_string = bit_string[:required_length]
        return bit_string.ljust(required_length, "0")

    @staticmethod
    def encrypt(message_bits: str, field_bits: str) -> str:
        return CryptoEngine.xor_bits(message_bits, field_bits)

    @staticmethod
    def decrypt(cipher_bits: str, field_bits: str) -> str:
        return CryptoEngine.xor_bits(cipher_bits, field_bits)

class BasePatternWindow:
    def __init__(self, title: str, geometry: str = "1100x850"):
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry(geometry)
        self.window.minsize(900, 650)
        self.window.resizable(True, True)

        self.container = ttk.Frame(self.window)
        self.container.pack(fill="both", expand=True, padx=10, pady=10)

        self.canvas = tk.Canvas(self.container, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(self.container, orient="vertical", command=self.canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind("<Configure>", self._update_scrollregion)
        self.canvas.bind("<Configure>", self._resize_scrollable_width)
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)

    def _bind_mousewheel(self, _event=None):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mousewheel(self, _event=None):
        self.canvas.unbind_all("<MouseWheel>")

    def _update_scrollregion(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _resize_scrollable_width(self, event):
        self.canvas.itemconfig(self.scrollable_window, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    @staticmethod
    def draw_pattern(canvas: tk.Canvas, pattern: str, result: Optional[str] = None) -> None:
        cell = 22
        positions = [
            (0, 0), (1, 0), (2, 0),
            (0, 1),         (2, 1),
            (0, 2), (1, 2), (2, 2),
        ]
        pattern_map = dict(zip(positions, pattern))

        for y in range(3):
            for x in range(3):
                x1 = x * cell
                y1 = y * cell
                x2 = x1 + cell
                y2 = y1 + cell
                if x == 1 and y == 1:
                    if result is None:
                        fill = "#d9d9d9"
                    else:
                        fill = "black" if result == "1" else "white"
                else:
                    fill = "black" if pattern_map[(x, y)] == "1" else "white"
                canvas.create_rectangle(x1, y1, x2, y2, fill=fill, outline="#666")

class RuleEditorWindow(BasePatternWindow):
    def __init__(
        self,
        rule_manager: RuleManager,
        on_save_callback: Callable[[str], None],
        rule_name: str = "",
        initial_outputs: Optional[Dict[str, str]] = None,
    ):
        super().__init__("Конструктор правила")
        self.rule_manager = rule_manager
        self.on_save_callback = on_save_callback
        self.original_name = rule_name
        self.pattern_vars: Dict[str, tk.StringVar] = {}

        header = ttk.Frame(self.window, padding=10)
        header.pack(fill="x")

        ttk.Label(header, text="Назва правила:").pack(side="left")
        self.rule_name_var = tk.StringVar(value=rule_name)
        ttk.Entry(header, textvariable=self.rule_name_var, width=30).pack(side="left", padx=8)
        ttk.Button(header, text="Згенерувати випадково", command=self.randomize_outputs).pack(side="left", padx=8)
        ttk.Button(header, text="Заповнити нулями", command=self.fill_with_zeros).pack(side="left", padx=8)
        ttk.Button(header, text="Заповнити одиницями", command=self.fill_with_ones).pack(side="left", padx=8)
        ttk.Button(header, text="Зберегти правило", command=self.save_rule).pack(side="left", padx=8)

        hint_text = (
            "Для кожної з 256 комбінацій восьми сусідів задайте новий стан центральної клітинки. "
            "Центральна клітинка на мініатюрі показує результат правила для відповідної конфігурації."
        )
        ttk.Label(self.window, text=hint_text, wraplength=1040, padding=(10, 0)).pack(fill="x")

        self._build_patterns_grid(initial_outputs or {})

    def _build_patterns_grid(self, initial_outputs: Dict[str, str]) -> None:
        columns = 4
        for value in range(256):
            pattern = format(value, "08b")
            card = ttk.LabelFrame(self.scrollable_frame, text=f"Комбінація {value} | {pattern}", padding=8)
            row = value // columns
            col = value % columns
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

            current_value = initial_outputs.get(pattern, "0")
            mini = tk.Canvas(card, width=66, height=66, bg="white", highlightthickness=1, highlightbackground="#999")
            mini.pack()
            self.draw_pattern(mini, pattern, current_value)

            ttk.Label(card, text="Новий стан центру:").pack(pady=(6, 2))
            value_var = tk.StringVar(value=current_value)
            self.pattern_vars[pattern] = value_var

            combo = ttk.Combobox(card, textvariable=value_var, values=["0", "1"], state="readonly", width=4)
            combo.pack()
            combo.bind("<<ComboboxSelected>>", lambda _e, c=mini, p=pattern, v=value_var: self.redraw_card(c, p, v))

        for index in range(columns):
            self.scrollable_frame.columnconfigure(index, weight=1)

    def redraw_card(self, canvas: tk.Canvas, pattern: str, value_var: tk.StringVar) -> None:
        canvas.delete("all")
        self.draw_pattern(canvas, pattern, value_var.get())

    def randomize_outputs(self) -> None:
        for variable in self.pattern_vars.values():
            variable.set(str(random.randint(0, 1)))
        self.refresh_all_cards()

    def fill_with_zeros(self) -> None:
        for variable in self.pattern_vars.values():
            variable.set("0")
        self.refresh_all_cards()

    def fill_with_ones(self) -> None:
        for variable in self.pattern_vars.values():
            variable.set("1")
        self.refresh_all_cards()

    def refresh_all_cards(self) -> None:
        for child in self.scrollable_frame.winfo_children():
            child.destroy()
        outputs = {pattern: var.get() for pattern, var in self.pattern_vars.items()}
        self.pattern_vars = {}
        self._build_patterns_grid(outputs)

    def save_rule(self) -> None:
        rule_name = self.rule_name_var.get().strip()
        if not rule_name:
            messagebox.showwarning("Увага", "Введіть назву правила.")
            return

        outputs = {pattern: var.get() for pattern, var in self.pattern_vars.items()}
        existing_names = set(self.rule_manager.get_rules().keys())
        if rule_name != self.original_name and rule_name in existing_names:
            messagebox.showwarning("Увага", "Правило з такою назвою вже існує.")
            return

        if self.original_name:
            self.rule_manager.update_rule(self.original_name, rule_name, outputs)
        else:
            self.rule_manager.add_rule(rule_name, outputs)

        self.on_save_callback(rule_name)
        messagebox.showinfo("Успіх", f"Правило '{rule_name}' успішно збережено.")
        self.window.destroy()

class RuleViewerWindow(BasePatternWindow):
    def __init__(self, rule_name: str, outputs: Dict[str, str]):
        super().__init__(f"Перегляд правила: {rule_name}")

        header = ttk.Frame(self.window, padding=10)
        header.pack(fill="x")
        active_count = sum(1 for value in outputs.values() if value == "1")
        ttk.Label(
            header,
            text=f"Правило: {rule_name} | Активних комбінацій: {active_count} з 256",
        ).pack(side="left")

        columns = 4
        for value in range(256):
            pattern = format(value, "08b")
            result = outputs.get(pattern, "0")
            card = ttk.LabelFrame(self.scrollable_frame, text=f"Комбінація {value} | {pattern}", padding=8)
            row = value // columns
            col = value % columns
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

            mini = tk.Canvas(card, width=66, height=66, bg="white", highlightthickness=1, highlightbackground="#999")
            mini.pack()
            self.draw_pattern(mini, pattern, result)

            ttk.Label(card, text=f"Результат центру: {result}").pack(pady=(6, 2))

        for index in range(columns):
            self.scrollable_frame.columnconfigure(index, weight=1)

class RuleListWindow:
    def __init__(self, parent: tk.Tk, rule_manager: RuleManager, on_rules_changed: Callable[[Optional[str]], None]):
        self.parent = parent
        self.rule_manager = rule_manager
        self.on_rules_changed = on_rules_changed

        self.window = tk.Toplevel()
        self.window.title("Список правил")
        self.window.geometry("1000x700")
        self.window.minsize(850, 500)
        self.window.resizable(True, True)

        header = ttk.Frame(self.window, padding=10)
        header.pack(fill="x")

        ttk.Button(header, text="Створити нове правило", command=self.create_rule).pack(side="left")
        ttk.Button(header, text="Додати правило за хешем", command=self.create_rule_from_hash).pack(side="left", padx=8)
        ttk.Button(header, text="Оновити список", command=self.refresh).pack(side="left", padx=8)

        self.container = ttk.Frame(self.window)
        self.container.pack(fill="both", expand=True, padx=10, pady=10)

        self.canvas = tk.Canvas(self.container, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(self.container, orient="vertical", command=self.canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.scrollable_frame.bind("<Configure>", self._update_scrollregion)
        self.canvas.bind("<Configure>", self._resize_scrollable_width)
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)

        self.refresh()

    def _bind_mousewheel(self, _event=None):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mousewheel(self, _event=None):
        self.canvas.unbind_all("<MouseWheel>")

    def _update_scrollregion(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _resize_scrollable_width(self, event):
        self.canvas.itemconfig(self.scrollable_window, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def create_rule_from_hash(self) -> None:
        try:
            clipboard_value = self.root.clipboard_get()
        except Exception:
            clipboard_value = ""

        hash_text = simpledialog.askstring(
            "Додати правило за хешем",
            "Введіть 64-символьний hex-хеш правила:",
            initialvalue=clipboard_value
        )
        if not hash_text:
            return

        rule_name = simpledialog.askstring(
            "Назва правила",
            "Введіть назву правила або залиште порожнім для автоматичної назви:"
        )

        try:
            selected_rule_name = self.rule_manager.add_rule_from_hash(hash_text, rule_name)
        except Exception as error:
            messagebox.showerror("Помилка", str(error))
            return

        self.refresh()
        self.on_rules_changed(selected_rule_name)
        messagebox.showinfo("Успіх", f"Правило '{selected_rule_name}' додано до списку правил.")

    def create_rule(self) -> None:
        RuleEditorWindow(self.rule_manager, self._on_rule_saved)

    def _on_rule_saved(self, selected_rule_name: str) -> None:
        self.refresh()
        self.on_rules_changed(selected_rule_name)

    def refresh(self) -> None:
        for child in self.scrollable_frame.winfo_children():
            child.destroy()

        rules = self.rule_manager.get_rules()
        if not rules:
            ttk.Label(self.scrollable_frame, text="Список правил порожній.").pack(anchor="w", padx=10, pady=10)
            return

        for index, (rule_name, rule_data) in enumerate(rules.items()):
            outputs = rule_data["outputs"]
            active_count = sum(1 for value in outputs.values() if value == "1")

            row_frame = ttk.LabelFrame(self.scrollable_frame, text=f"Правило {index + 1}", padding=10)
            row_frame.pack(fill="x", padx=6, pady=6)

            info_frame = ttk.Frame(row_frame)
            info_frame.pack(side="left", fill="x", expand=True)

            ttk.Label(info_frame, text=f"Назва: {rule_name}").pack(anchor="w")
            ttk.Label(info_frame, text=f"Активних комбінацій: {active_count} з 256").pack(anchor="w", pady=(4, 0))

            preview_patterns = [pattern for pattern, value in outputs.items() if value == "1"][:6]
            preview_text = ", ".join(preview_patterns) if preview_patterns else "немає активних шаблонів"
            ttk.Label(info_frame, text=f"Приклади активних шаблонів: {preview_text}", wraplength=520).pack(anchor="w", pady=(4, 0))

            buttons_frame = ttk.Frame(row_frame)
            buttons_frame.pack(side="right")

            ttk.Button(
                buttons_frame,
                text="Переглянути",
                command=lambda name=rule_name, out=outputs: self.view_rule(name, out),
                width=14,
            ).grid(row=0, column=0, padx=4, pady=4)

            ttk.Button(
                buttons_frame,
                text="Оновити",
                command=lambda name=rule_name: self.edit_rule(name),
                width=14,
            ).grid(row=0, column=1, padx=4, pady=4)

            ttk.Button(
                buttons_frame,
                text="Видалити",
                command=lambda name=rule_name: self.delete_rule(name),
                width=14,
            ).grid(row=0, column=2, padx=4, pady=4)

    def view_rule(self, rule_name: str, outputs: Dict[str, str]) -> None:
        RuleViewerWindow(rule_name, outputs)

    def edit_rule(self, rule_name: str) -> None:
        rule = self.rule_manager.get_rule(rule_name)
        RuleEditorWindow(self.rule_manager, self._on_rule_saved, rule_name, rule["outputs"])

    def delete_rule(self, rule_name: str) -> None:
        answer = messagebox.askyesno("Підтвердження", f"Видалити правило '{rule_name}'?")
        if not answer:
            return

        self.rule_manager.delete_rule(rule_name)
        self.refresh()
        remaining_rules = list(self.rule_manager.get_rules().keys())
        self.on_rules_changed(remaining_rules[0] if remaining_rules else None)

@dataclass
class RuleEvaluationConfig:
    num_runs: int = 10
    warmup_iterations: int = 10
    capture_iterations: int = 32
    field_mode: str = "uniform_random"
    field_seed: int = 12345

class RuleEvaluationEngine:
    def __init__(self, rule_manager: RuleManager, grid_size: int = GRID_SIZE):
        self.rule_manager = rule_manager
        self.grid_size = grid_size

    def _make_field(self, mode: str, seed: int) -> List[List[int]]:
        rng = random.Random(seed)
        size = self.grid_size

        if mode == "balanced_random":
            values = [0] * (size * size // 2) + [1] * (size * size - size * size // 2)
            rng.shuffle(values)
            return [values[i * size:(i + 1) * size] for i in range(size)]

        return [[rng.randint(0, 1) for _ in range(size)] for _ in range(size)]

    def _grid_to_bits(self, grid: List[List[int]]) -> str:
        return "".join(str(cell) for row in grid for cell in row)

    def _entropy(self, bit_string: str) -> float:
        if not bit_string:
            return 0.0
        ones = bit_string.count("1")
        zeros = len(bit_string) - ones
        probabilities = []
        if zeros > 0:
            probabilities.append(zeros / len(bit_string))
        if ones > 0:
            probabilities.append(ones / len(bit_string))
        return -sum(p * math.log2(p) for p in probabilities)

    def _hamming_ratio(self, first_bits: str, second_bits: str) -> float:
        if not first_bits or not second_bits or len(first_bits) != len(second_bits):
            return 0.0
        diff = sum(1 for left, right in zip(first_bits, second_bits) if left != right)
        return diff / len(first_bits)

    def _run_nist_tests(self, bit_string: str) -> Dict[str, object]:

        try:
            import numpy as np
            from nistrng import SP800_22R1A_BATTERY, check_eligibility_all_battery, run_all_battery
        except Exception as error:
            return {
                "available": False,
                "message": f"NIST tests unavailable: {error}",
                "passed": 0,
                "total": 0,
                "results": [],
            }

        clean_bits = "".join(bit for bit in bit_string if bit in "01")
        if not clean_bits:
            return {
                "available": False,
                "message": "NIST execution error: empty bit sequence",
                "passed": 0,
                "total": 0,
                "results": [],
            }

        sequence = np.array([1 if bit == "1" else 0 for bit in clean_bits], dtype=np.int8)

        try:
            eligible_tests = check_eligibility_all_battery(sequence, SP800_22R1A_BATTERY)
            results = run_all_battery(sequence, eligible_tests, False)
        except Exception as error:
            return {
                "available": False,
                "message": f"NIST execution error: {error}",
                "passed": 0,
                "total": 0,
                "results": [],
            }

        normalized_results = []
        passed_count = 0

        for item in results:
            elapsed_ms = None

            if isinstance(item, tuple) and len(item) >= 1:
                result_obj = item[0]
                if len(item) >= 2:
                    elapsed_ms = item[1]
            else:
                result_obj = item

            test_name = str(getattr(result_obj, "name", "unknown"))
            passed = bool(getattr(result_obj, "passed", False))

            score = None
            if hasattr(result_obj, "score"):
                try:
                    score = float(getattr(result_obj, "score"))
                except Exception:
                    score = None

            if passed:
                passed_count += 1

            normalized_results.append({
                "name": test_name,
                "passed": passed,
                "score": score,
                "elapsed_ms": elapsed_ms,
                "error": None,
                "raw": repr(result_obj)[:180],
            })

        return {
            "available": True,
            "message": "ok",
            "passed": passed_count,
            "total": len(normalized_results),
            "results": normalized_results,
        }

    def evaluate_rule(self, rule_name: str, config: Optional[RuleEvaluationConfig] = None) -> Dict[str, object]:
        config = config or RuleEvaluationConfig()
        rule = self.rule_manager.get_rule(rule_name)

        full_bitstream_parts: List[str] = []
        hamming_values: List[float] = []
        cycle_hits = 0

        for run_index in range(config.num_runs):
            automaton = CellularAutomaton(self.grid_size)
            automaton.grid = self._make_field(config.field_mode, config.field_seed + run_index)

            for _ in range(config.warmup_iterations):
                automaton.step(rule)

            seen_states = set()
            previous_bits: Optional[str] = None

            for _ in range(config.capture_iterations):
                current_bits = automaton.grid_to_bits(mode="mixed", step_index=_)
                full_bitstream_parts.append(current_bits)

                if current_bits in seen_states:
                    cycle_hits += 1
                else:
                    seen_states.add(current_bits)

                if previous_bits is not None:
                    hamming_values.append(self._hamming_ratio(previous_bits, current_bits))
                previous_bits = current_bits
                automaton.step(rule)

        bit_string = "".join(full_bitstream_parts)
        ones_ratio = bit_string.count("1") / len(bit_string) if bit_string else 0.0
        entropy = self._entropy(bit_string)
        avg_hamming = sum(hamming_values) / len(hamming_values) if hamming_values else 0.0

        balance_score = 1.0 - abs(ones_ratio - 0.5) * 2
        entropy_score = entropy
        hamming_score = 1.0 - abs(avg_hamming - 0.5) * 2
        repeat_penalty = min(1.0, cycle_hits / max(1, config.num_runs * config.capture_iterations))
        composite_score = max(0.0, (balance_score + entropy_score + hamming_score) / 3 - repeat_penalty * 0.5)

        nist_summary = self._run_nist_tests(bit_string)

        return {
            "target_type": "rule",
            "name": rule_name,
            "bit_length": len(bit_string),
            "ones_ratio": round(ones_ratio, 6),
            "entropy": round(entropy, 6),
            "avg_hamming_ratio": round(avg_hamming, 6),
            "cycle_hits": cycle_hits,
            "composite_score": round(composite_score, 6),
            "field_mode": config.field_mode,
            "runs": config.num_runs,
            "capture_iterations": config.capture_iterations,
            "nist": nist_summary,
        }

    def evaluate_field_generation(self, field_mode: str = "uniform_random", sample_count: int = 100, progress_callback=None) -> Dict[str, object]:
        full_bitstream_parts: List[str] = []
        hamming_values: List[float] = []
        previous_bits: Optional[str] = None

        for sample_index in range(sample_count):
            if progress_callback is not None:
                progress_callback(sample_index + 1, sample_count, f"Генерація поля: {sample_index + 1}/{sample_count}")
            grid = self._make_field(field_mode, 100000 + sample_index)
            current_bits = self._grid_to_bits(grid)
            full_bitstream_parts.append(current_bits)
            if previous_bits is not None:
                hamming_values.append(self._hamming_ratio(previous_bits, current_bits))
            previous_bits = current_bits

        bit_string = "".join(full_bitstream_parts)
        ones_ratio = bit_string.count("1") / len(bit_string) if bit_string else 0.0
        entropy = self._entropy(bit_string)
        avg_hamming = sum(hamming_values) / len(hamming_values) if hamming_values else 0.0

        balance_score = 1.0 - abs(ones_ratio - 0.5) * 2
        entropy_score = entropy
        hamming_score = 1.0 - abs(avg_hamming - 0.5) * 2
        composite_score = max(0.0, (balance_score + entropy_score + hamming_score) / 3)

        nist_summary = self._run_nist_tests(bit_string)

        return {
            "target_type": "field_generation",
            "name": field_mode,
            "bit_length": len(bit_string),
            "ones_ratio": round(ones_ratio, 6),
            "entropy": round(entropy, 6),
            "avg_hamming_ratio": round(avg_hamming, 6),
            "cycle_hits": 0,
            "composite_score": round(composite_score, 6),
            "field_mode": field_mode,
            "runs": sample_count,
            "capture_iterations": 1,
            "nist": nist_summary,
        }

    def compare_rules(self, rule_names: Optional[List[str]] = None, config: Optional[RuleEvaluationConfig] = None) -> List[Dict[str, object]]:
        config = config or RuleEvaluationConfig()
        names = rule_names or list(self.rule_manager.get_rules().keys())
        results = [self.evaluate_rule(name, config) for name in names]
        return sorted(results, key=lambda item: item["composite_score"], reverse=True)

    @staticmethod
    def format_evaluation_report(result: Dict[str, object]) -> str:
        nist = result["nist"]
        lines = [
            f"Довжина бітової послідовності: {result['bit_length']}",
            f"Частка одиниць: {result['ones_ratio']}",
            f"Ентропія: {result['entropy']}",
            f"Середня відстань Хеммінга: {result['avg_hamming_ratio']}",
            f"Повтори станів: {result['cycle_hits']}",
            f"Підсумкова оцінка: {result['composite_score']}",
        ]

        if nist["available"]:
            lines.append(f"NIST: {nist['passed']} / {nist['total']}")
            if nist["results"]:
                lines.append("")
                lines.append("Деталізація NIST-тестів:")
                for item in nist["results"]:
                    status = "пройдено" if item["passed"] else "завалено"
                    score = item.get("score")
                    error = item.get("error")
                    if score is not None:
                        lines.append(f" - {item['name']}: {status} (score={score:.6g})")
                    elif error:
                        lines.append(f" - {item['name']}: {status} ({error})")
                    else:
                        lines.append(f" - {item['name']}: {status}")
        else:
            lines.append(f"NIST: {nist['message']}")

        return "\n".join(lines)

class TextReportWindow:
    def __init__(self, title: str, content: str):
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry("900x700")
        self.window.minsize(700, 500)

        frame = ttk.Frame(self.window, padding=10)
        frame.pack(fill="both", expand=True)

        text_widget = tk.Text(frame, wrap="word")
        text_widget.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.insert("1.0", content)
        text_widget.configure(state="disabled")

class FieldSearchEngine:
    def __init__(self, rule_manager: RuleManager, cache: Optional[PersistentSearchCache] = None, grid_size: int = GRID_SIZE):
        self.rule_manager = rule_manager
        self.grid_size = grid_size
        self.evaluator = RuleEvaluationEngine(rule_manager, grid_size)
        self.cache = cache

    def _field_signature(self, rule_name: str, grid: List[List[int]], warmup_iterations: int, capture_iterations: int, mode: str) -> str:
        field_bits = "".join(str(cell) for row in grid for cell in row)
        return PersistentSearchCache.make_signature([
            "field_search", rule_name, mode, str(warmup_iterations), str(capture_iterations), field_bits
        ])

    def _quick_stream_metrics(self, rule: Dict[str, Dict[str, str] | str], initial_grid: List[List[int]], iterations: int = 32) -> Dict[str, object]:
        automaton = CellularAutomaton(self.grid_size)
        automaton.set_grid(initial_grid)
        stream_parts: List[str] = []
        previous_bits: Optional[str] = None
        hamming_values: List[float] = []
        seen_states = set()
        cycle_hits = 0
        for _ in range(iterations):
            bits = automaton.grid_to_bits(mode="mixed", step_index=_)
            stream_parts.append(bits)
            if bits in seen_states:
                cycle_hits += 1
            else:
                seen_states.add(bits)
            if previous_bits is not None:
                hamming_values.append(self.evaluator._hamming_ratio(previous_bits, bits))
            previous_bits = bits
            automaton.step(rule)
        bit_string = "".join(stream_parts)
        ones_ratio = bit_string.count("1") / len(bit_string) if bit_string else 0.0
        entropy = self.evaluator._entropy(bit_string)
        avg_hamming = sum(hamming_values) / len(hamming_values) if hamming_values else 0.0
        return {"ones_ratio": ones_ratio, "entropy": entropy, "avg_hamming_ratio": avg_hamming, "cycle_hits": cycle_hits}

    def _passes_quick_filter(self, metrics: Dict[str, object]) -> bool:
        ones_ratio = float(metrics["ones_ratio"])
        entropy = float(metrics["entropy"])
        avg_hamming = float(metrics["avg_hamming_ratio"])
        cycle_hits = int(metrics["cycle_hits"])
        if abs(ones_ratio - 0.5) > 0.30:
            return False
        if entropy < 0.65:
            return False
        if avg_hamming < 0.15:
            return False
        if cycle_hits > 1:
            return False
        return True

    def evaluate_single_field(self, grid: List[List[int]]) -> Dict[str, float]:
        bit_string = "".join(str(cell) for row in grid for cell in row)
        ones_ratio = bit_string.count("1") / len(bit_string) if bit_string else 0.0
        entropy = self.evaluator._entropy(bit_string)

        row_changes = 0
        col_changes = 0
        total_row_pairs = 0
        total_col_pairs = 0

        for row in grid:
            for i in range(len(row) - 1):
                total_row_pairs += 1
                if row[i] != row[i + 1]:
                    row_changes += 1

        for col in range(self.grid_size):
            for row in range(self.grid_size - 1):
                total_col_pairs += 1
                if grid[row][col] != grid[row + 1][col]:
                    col_changes += 1

        local_change_ratio = 0.0
        denom = total_row_pairs + total_col_pairs
        if denom > 0:
            local_change_ratio = (row_changes + col_changes) / denom

        balance_score = 1.0 - abs(ones_ratio - 0.5) * 2
        entropy_score = entropy
        local_score = 1.0 - abs(local_change_ratio - 0.5) * 2
        composite_score = max(0.0, (balance_score + entropy_score + local_score) / 3)

        return {
            "ones_ratio": round(ones_ratio, 6),
            "entropy": round(entropy, 6),
            "local_change_ratio": round(local_change_ratio, 6),
            "composite_score": round(composite_score, 6),
        }

    def find_best_field_by_metrics(self, candidate_count: int = 300, mode: str = "uniform_random") -> Dict[str, object]:
        best_result = None

        for index in range(candidate_count):
            grid = self.evaluator._make_field(mode, 700000 + index)
            metrics = self.evaluate_single_field(grid)
            result = {
                "index": index + 1,
                "mode": mode,
                "grid": grid,
                **metrics,
            }
            if best_result is None or result["composite_score"] > best_result["composite_score"]:
                best_result = result

        return best_result

    def find_good_field_by_nist(
        self,
        rule_name: str,
        candidate_count: Optional[int] = None,
        warmup_iterations: int = 10,
        capture_iterations: int = 100,
        mode: str = "uniform_random",
        progress_callback=None,
        should_stop=None,
        quick_filter_iterations: int = 32,
    ) -> Optional[Dict[str, object]]:
        rule = self.rule_manager.get_rule(rule_name)
        checked_count = 0
        skipped_count = 0
        filtered_count = 0
        nist_checked_count = 0
        seed_index = 0
        while True:
            if should_stop is not None and should_stop():
                return {"stopped": True, "checked_count": checked_count, "skipped_count": skipped_count, "filtered_count": filtered_count, "nist_checked_count": nist_checked_count}
            if candidate_count is not None and checked_count >= candidate_count:
                return None
            initial_grid = self.evaluator._make_field(mode, 900000 + seed_index)
            seed_index += 1
            signature = self._field_signature(rule_name, initial_grid, warmup_iterations, capture_iterations, mode)
            if self.cache is not None and self.cache.has_failed(signature):
                skipped_count += 1
                if progress_callback is not None:
                    total_label = "∞" if candidate_count is None else str(candidate_count)
                    progress_callback(checked_count, max(checked_count if candidate_count is None else candidate_count, 1), f"Поле NIST: нових {checked_count}/{total_label} | NIST {nist_checked_count} | фільтр {filtered_count} | кеш {skipped_count}")
                continue
            checked_count += 1
            quick_metrics = self._quick_stream_metrics(rule, initial_grid, iterations=quick_filter_iterations)
            if not self._passes_quick_filter(quick_metrics):
                filtered_count += 1
                if self.cache is not None:
                    self.cache.add_failed(signature)
                if progress_callback is not None:
                    total_label = "∞" if candidate_count is None else str(candidate_count)
                    progress_callback(checked_count, max(checked_count if candidate_count is None else candidate_count, 1), f"Поле NIST: нових {checked_count}/{total_label} | NIST {nist_checked_count} | фільтр {filtered_count} | кеш {skipped_count}")
                continue
            nist_checked_count += 1
            if progress_callback is not None:
                total_label = "∞" if candidate_count is None else str(candidate_count)
                progress_callback(checked_count, max(checked_count if candidate_count is None else candidate_count, 1), f"Поле NIST: нових {checked_count}/{total_label} | NIST {nist_checked_count} | фільтр {filtered_count} | кеш {skipped_count}")
            automaton = CellularAutomaton(self.grid_size)
            automaton.set_grid(initial_grid)
            for _ in range(warmup_iterations):
                automaton.step(rule)
            stream_parts = []
            prev_bits = None
            hamming_values = []
            for _ in range(capture_iterations):
                bits = automaton.grid_to_bits(mode="mixed", step_index=_)
                stream_parts.append(bits)
                if prev_bits is not None:
                    hamming_values.append(self.evaluator._hamming_ratio(prev_bits, bits))
                prev_bits = bits
                automaton.step(rule)
            bit_string = "".join(stream_parts)
            ones_ratio = bit_string.count("1") / len(bit_string) if bit_string else 0.0
            entropy = self.evaluator._entropy(bit_string)
            avg_hamming = sum(hamming_values) / len(hamming_values) if hamming_values else 0.0
            nist = self.evaluator._run_nist_tests(bit_string)
            nist_passed = nist["passed"] if nist["available"] else 0
            nist_total = nist["total"] if nist["available"] else 0
            nist_ratio = nist_passed / max(1, nist_total) if nist["available"] else 0.0
            balance_score = 1.0 - abs(ones_ratio - 0.5) * 2
            entropy_score = entropy
            hamming_score = 1.0 - abs(avg_hamming - 0.5) * 2
            composite_score = max(0.0, (balance_score + entropy_score + hamming_score + nist_ratio) / 4)
            result = {"index": seed_index, "mode": mode, "rule_name": rule_name, "grid": initial_grid, "bit_length": len(bit_string), "ones_ratio": round(ones_ratio, 6), "entropy": round(entropy, 6), "avg_hamming_ratio": round(avg_hamming, 6), "composite_score": round(composite_score, 6), "nist": nist, "checked_count": checked_count, "skipped_count": skipped_count, "filtered_count": filtered_count, "nist_checked_count": nist_checked_count, "name": f"Поле для {rule_name}", "target_type": "field_via_rule", "cycle_hits": 0}
            if nist["available"] and nist_passed >= NIST_PASS_TARGET:
                if self.cache is not None:
                    self.cache.add_passed(signature)
                return result
            if self.cache is not None:
                self.cache.add_failed(signature)

class CAApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("2D Cellular Automaton Crypto System")
        self.root.geometry("1200x900")

        self.rule_manager = RuleManager(RULES_FILE)
        self.field_nist_cache = PersistentSearchCache(FIELD_NIST_CACHE_FILE)
        self.ca = CellularAutomaton()
        self.crypto = CryptoEngine()
        self.ciphertext_bits: str | None = None

        rule_names = list(self.rule_manager.get_rules().keys())
        self.selected_rule = tk.StringVar(value=rule_names[0] if rule_names else "")
        self.iterations_var = tk.IntVar(value=DEFAULT_ITERATIONS)
        self.message_var = tk.StringVar()
        self.cipher_var = tk.StringVar()
        self.cipher_bits_var = tk.StringVar()
        self.decrypted_var = tk.StringVar()
        self.message_blocks_var = tk.StringVar()
        self.cipher_blocks_var = tk.StringVar()

        self.is_animating = False
        self.remaining_iterations = 0
        self.base_delay_ms = 150
        self.fast_batch_iterations = 25
        self.speed_var = tk.StringVar(value="1")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_text_var = tk.StringVar(value="Готово")
        self.stop_search_requested = False

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.refresh_rule_combobox()
        self.update_rule_info()
        self.draw_grid()

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root)
        container.pack(fill="both", expand=True)

        self.main_canvas = tk.Canvas(container, highlightthickness=0)
        self.main_canvas.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.main_canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.main_canvas.configure(yscrollcommand=scrollbar.set)

        self.scrollable_frame = ttk.Frame(self.main_canvas)
        self.scrollable_window = self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind("<Configure>", self._update_scrollregion)
        self.main_canvas.bind("<Configure>", self._resize_scrollable_width)
        self.main_canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        top_frame = ttk.Frame(self.scrollable_frame, padding=10)
        top_frame.pack(fill="x")

        ttk.Label(top_frame, text="Правило:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.rule_combobox = ttk.Combobox(
            top_frame,
            textvariable=self.selected_rule,
            values=[],
            state="readonly",
            width=20,
        )
        self.rule_combobox.grid(row=0, column=1, sticky="w")
        self.rule_combobox.bind("<<ComboboxSelected>>", lambda _: self.update_rule_info())

        ttk.Button(top_frame, text="Показати правило", command=self.show_rule_details).grid(row=0, column=2, padx=6)
        ttk.Button(top_frame, text="Список правил", command=self.open_rule_list).grid(row=0, column=3, padx=6)
        ttk.Button(top_frame, text="Додати правило за хешем", command=self.add_rule_by_hash_ui).grid(row=0, column=4, padx=6)

        ttk.Label(top_frame, text="Ітерації:").grid(row=0, column=5, sticky="w", padx=(18, 6))
        ttk.Entry(top_frame, textvariable=self.iterations_var, width=8).grid(row=0, column=6, sticky="w")

        ttk.Label(top_frame, text="Швидкість:").grid(row=0, column=7, padx=(18, 4), sticky="w")
        speed_box = ttk.Combobox(top_frame, textvariable=self.speed_var, state="readonly", width=10)
        speed_box["values"] = ("0.5", "1", "1.25", "1.5", "1.75", "2", "3", "5", "10", "Без анімації")
        speed_box.grid(row=0, column=8, sticky="w")
        speed_box.bind("<<ComboboxSelected>>", lambda _: self.update_speed())

        self.rule_info_label = ttk.Label(self.scrollable_frame, text="", padding=(10, 0))
        self.rule_info_label.pack(fill="x")

        progress_frame = ttk.Frame(self.scrollable_frame, padding=(10, 4))
        progress_frame.pack(fill="x")
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode="determinate",
        )
        self.progress_bar.pack(side="left", fill="x", expand=True)
        ttk.Label(progress_frame, textvariable=self.progress_text_var, width=28).pack(side="left", padx=(10, 0))

        workspace_frame = ttk.Frame(self.scrollable_frame, padding=10)
        workspace_frame.pack()

        canvas_frame = ttk.Frame(workspace_frame)
        canvas_frame.grid(row=0, column=0, sticky="n")

        self.canvas = tk.Canvas(
            canvas_frame,
            width=GRID_SIZE * CELL_SIZE,
            height=GRID_SIZE * CELL_SIZE,
            bg="white",
            highlightthickness=1,
            highlightbackground="#888888",
        )
        self.canvas.pack()
        self.canvas.bind("<Button-1>", self.toggle_cell)

        controls_frame = ttk.LabelFrame(workspace_frame, text="Керування", padding=10)
        controls_frame.grid(row=0, column=1, sticky="n", padx=(16, 0))

        ttk.Button(controls_frame, text="Нове поле", width=22, command=self.new_grid).pack(pady=4)
        ttk.Button(controls_frame, text="1 крок", width=22, command=self.single_step).pack(pady=4)
        ttk.Button(controls_frame, text="Запустити ітерації", width=22, command=self.run_iterations).pack(pady=4)
        ttk.Button(controls_frame, text="Стоп", width=22, command=self.stop_animation).pack(pady=4)

        ttk.Separator(controls_frame, orient="horizontal").pack(fill="x", pady=8)

        ttk.Button(controls_frame, text="Оцінити правило", width=22, command=self.evaluate_selected_rule_ui).pack(pady=4)
        ttk.Button(controls_frame, text="Оцінити поле", width=22, command=self.evaluate_field_generation_ui).pack(pady=4)

        ttk.Separator(controls_frame, orient="horizontal").pack(fill="x", pady=8)

        ttk.Button(controls_frame, text="Поле через NIST", width=22, command=self.find_nist_field_ui).pack(pady=4)
        ttk.Button(controls_frame, text="Зупинити пошук", width=22, command=self.request_stop_search).pack(pady=4)

        ttk.Separator(controls_frame, orient="horizontal").pack(fill="x", pady=8)

        ttk.Button(controls_frame, text="Зберегти поле", width=22, command=self.save_current_field_ui).pack(pady=4)
        ttk.Button(controls_frame, text="Завантажити поле", width=22, command=self.load_field_ui).pack(pady=4)

        crypto_frame = ttk.LabelFrame(self.scrollable_frame, text="Шифрування та дешифрування", padding=10)
        crypto_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(crypto_frame, text="Повідомлення (звичайний текст):").grid(row=0, column=0, sticky="w")

        entry_frame = ttk.Frame(crypto_frame)
        entry_frame.grid(row=0, column=1, sticky="ew", padx=6)

        self.message_entry = ttk.Entry(entry_frame, textvariable=self.message_var)
        self.message_entry.pack(fill="x")

        button_tile = ttk.Frame(crypto_frame)
        button_tile.grid(row=0, column=2, rowspan=3, sticky="ne", padx=(12, 0))

        for col in range(2):
            button_tile.columnconfigure(col, weight=1, uniform="btn")
        for row in range(4):
            button_tile.rowconfigure(row, weight=1)

        ttk.Button(button_tile, text="Вставити", width=18, command=self.paste_message).grid(row=0, column=0, padx=4, pady=4, sticky="ew")
        ttk.Button(button_tile, text="Очистити", width=18, command=self.clear_message_field).grid(row=0, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(button_tile, text="Зашифрувати", width=18, command=self.encrypt_message).grid(row=1, column=0, padx=4, pady=4, sticky="ew")
        ttk.Button(button_tile, text="Розшифрувати", width=18, command=self.decrypt_message).grid(row=1, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(button_tile, text="Копіювати", width=18, command=self.copy_ciphertext).grid(row=2, column=0, padx=4, pady=4, sticky="ew")
        ttk.Button(button_tile, text="Вставити шифртекст", width=18, command=self.paste_ciphertext).grid(row=2, column=1, padx=4, pady=4, sticky="ew")
        ttk.Button(button_tile, text="Очистити шифртекст", width=18, command=self.clear_ciphertext_field).grid(row=3, column=0, columnspan=2, padx=4, pady=4, sticky="ew")

        ttk.Label(crypto_frame, text="Біти повідомлення (по 8 біт):").grid(row=1, column=0, sticky="nw", pady=(10, 0))
        ttk.Label(crypto_frame, textvariable=self.message_blocks_var, wraplength=700, justify="left").grid(
            row=1, column=1, sticky="w", pady=(10, 0)
        )

        ttk.Label(crypto_frame, text="Шифротекст (hex):").grid(row=2, column=0, sticky="nw", pady=(10, 0))
        self.cipher_entry = ttk.Entry(crypto_frame, textvariable=self.cipher_var)
        self.cipher_entry.grid(row=2, column=1, sticky="ew", pady=(10, 0))


        ttk.Label(crypto_frame, text="Блоки шифротексту (по 8 біт):").grid(row=3, column=0, sticky="nw", pady=(10, 0))
        ttk.Label(crypto_frame, textvariable=self.cipher_blocks_var, wraplength=920, justify="left").grid(
            row=3, column=1, columnspan=2, sticky="w", pady=(10, 0)
        )

        ttk.Label(crypto_frame, text="Результат дешифрування:").grid(row=4, column=0, sticky="nw", pady=(10, 0))
        ttk.Label(crypto_frame, textvariable=self.decrypted_var, wraplength=920, justify="left").grid(
            row=4, column=1, columnspan=2, sticky="w", pady=(10, 0)
        )

        crypto_frame.columnconfigure(1, weight=1)

    def refresh_rule_combobox(self, selected_rule_name: Optional[str] = None) -> None:
        rule_names = list(self.rule_manager.get_rules().keys())
        self.rule_combobox["values"] = rule_names
        if not rule_names:
            self.selected_rule.set("")
            return

        if selected_rule_name and selected_rule_name in rule_names:
            self.selected_rule.set(selected_rule_name)
        elif self.selected_rule.get() not in rule_names:
            self.selected_rule.set(rule_names[0])

    def _update_scrollregion(self, _event=None) -> None:
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))

    def _resize_scrollable_width(self, event) -> None:
        self.main_canvas.itemconfig(self.scrollable_window, width=event.width)

    def _on_mousewheel(self, event) -> None:
        self.main_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def current_rule(self) -> Optional[Dict[str, Dict[str, str] | str]]:
        rule_name = self.selected_rule.get()
        if not rule_name:
            return None
        return self.rule_manager.get_rules()[rule_name]

    def update_rule_info(self) -> None:
        rule_name = self.selected_rule.get()
        if not rule_name:
            self.rule_info_label.config(text="Правила відсутні.")
            return

        outputs = self.current_rule()["outputs"]
        active_count = sum(1 for value in outputs.values() if value == "1")
        self.rule_info_label.config(
            text=f"Поточне правило: {rule_name} | Активних комбінацій: {active_count} з 256"
        )

    def _set_progress(self, value: float, text: str) -> None:
        value = max(0.0, min(100.0, value))
        self.progress_var.set(value)
        self.progress_text_var.set(text)

    def _reset_progress(self) -> None:
        self.progress_var.set(0.0)
        self.progress_text_var.set("Готово")

    def request_stop_search(self) -> None:
        self.stop_search_requested = True
        self.progress_text_var.set("Зупинка запитана...")

    def _prepare_long_search(self) -> None:
        self.stop_search_requested = False

    def on_close(self) -> None:
        try:
            self.field_nist_cache.flush()
        except Exception:
            pass
        self.root.destroy()

    def draw_grid(self) -> None:
        self.canvas.delete("all")
        for row in range(self.ca.size):
            for col in range(self.ca.size):
                x1 = col * CELL_SIZE
                y1 = row * CELL_SIZE
                x2 = x1 + CELL_SIZE
                y2 = y1 + CELL_SIZE
                fill_color = "black" if self.ca.grid[row][col] == 1 else "white"
                self.canvas.create_rectangle(x1, y1, x2, y2, fill=fill_color, outline="#d0d0d0")

    def toggle_cell(self, event) -> None:
        col = event.x // CELL_SIZE
        row = event.y // CELL_SIZE
        if 0 <= row < self.ca.size and 0 <= col < self.ca.size:
            self.ca.grid[row][col] = 1 - self.ca.grid[row][col]
            self.draw_grid()

    def new_grid(self) -> None:
        if self.is_animating:
            self.stop_animation()
        self.ca.set_random_grid()
        self.draw_grid()
        self._set_progress(0, "Нове поле")

    def update_speed(self) -> None:
        speed_value = self.speed_var.get()
        if speed_value == "Без анімації":
            self.base_delay_ms = 0
            return
        try:
            multiplier = float(speed_value)
        except ValueError:
            multiplier = 1.0
        self.base_delay_ms = max(10, int(150 / max(multiplier, 0.1)))

    def single_step(self) -> None:
        if self.is_animating:
            return
        rule = self.current_rule()
        if rule is None:
            messagebox.showwarning("Увага", "Спочатку виберіть правило.")
            return
        self.ca.step(rule)
        self.draw_grid()
        self._set_progress(100, "Виконано 1 крок")

    def run_iterations(self) -> None:
        if self.is_animating:
            messagebox.showwarning("Увага", "Еволюція вже виконується.")
            return
        rule = self.current_rule()
        if rule is None:
            messagebox.showwarning("Увага", "Спочатку виберіть правило.")
            return
        try:
            iterations = int(self.iterations_var.get())
        except (TypeError, ValueError):
            messagebox.showwarning("Увага", "Кількість ітерацій має бути цілим числом.")
            return
        if iterations <= 0:
            messagebox.showwarning("Увага", "Кількість ітерацій має бути більшою за нуль.")
            return

        self.remaining_iterations = iterations
        self.total_animation_iterations = iterations
        self.is_animating = True

        if self.speed_var.get() == "Без анімації":
            for _ in range(iterations):
                self.ca.step(rule)
            self.draw_grid()
            self.is_animating = False
            self.remaining_iterations = 0
            self._set_progress(100, f"Виконано {iterations} ітерацій")
            return

        self._animate_next_step()

    def _animate_next_step(self) -> None:
        if not self.is_animating:
            return
        if self.remaining_iterations <= 0:
            self.is_animating = False
            self._set_progress(100, "Еволюцію завершено")
            return

        rule = self.current_rule()
        if rule is None:
            self.is_animating = False
            messagebox.showwarning("Увага", "Правило відсутнє.")
            return

        self.ca.step(rule)
        self.draw_grid()
        self.remaining_iterations -= 1

        done = self.total_animation_iterations - self.remaining_iterations
        percent = done / max(1, self.total_animation_iterations) * 100
        self._set_progress(percent, f"Ітерація {done}/{self.total_animation_iterations}")

        if self.remaining_iterations > 0:
            self.root.after(self.base_delay_ms, self._animate_next_step)
        else:
            self.is_animating = False
            self._set_progress(100, "Еволюцію завершено")

    def stop_animation(self) -> None:
        self.is_animating = False
        self.remaining_iterations = 0
        self._set_progress(0, "Еволюцію зупинено")

    def show_rule_details(self) -> None:
        rule = self.current_rule()
        if rule is None:
            messagebox.showinfo("Інформація", "Правила відсутні.")
            return

        outputs = rule["outputs"]
        active_patterns = [pattern for pattern, value in outputs.items() if value == "1"]
        preview = ", ".join(active_patterns[:12]) if active_patterns else "немає"
        if len(active_patterns) > 12:
            preview += ", ..."
        messagebox.showinfo(
            "Інформація про правило",
            f"Назва: {self.selected_rule.get()}\n"
            f"Кількість комбінацій, що дають 1: {len(active_patterns)}\n"
            f"Приклади активних шаблонів: {preview}",
        )

    def add_rule_by_hash_ui(self) -> None:
        try:
            clipboard_value = self.root.clipboard_get()
        except Exception:
            clipboard_value = ""

        hash_text = simpledialog.askstring(
            "Додати правило за хешем",
            "Введіть 64-символьний hex-хеш правила:",
            initialvalue=clipboard_value
        )
        if not hash_text:
            return

        rule_name = simpledialog.askstring(
            "Назва правила",
            "Введіть назву правила або залиште порожнім для автоматичної назви:"
        )

        try:
            selected_rule_name = self.rule_manager.add_rule_from_hash(hash_text, rule_name)
        except Exception as error:
            messagebox.showerror("Помилка", str(error))
            return

        self.refresh_rule_combobox(selected_rule_name)
        self.update_rule_info()
        messagebox.showinfo("Успіх", f"Правило '{selected_rule_name}' додано до списку правил.")

    def open_rule_list(self) -> None:
        RuleListWindow(self.root, self.rule_manager, self.on_rules_changed)

    def on_rules_changed(self, selected_rule_name: Optional[str]) -> None:
        self.refresh_rule_combobox(selected_rule_name)
        self.update_rule_info()

    def _run_evaluation_in_background(self, worker, title: str) -> None:
        if self.is_animating:
            messagebox.showwarning("Увага", "Дочекайтесь завершення поточної еволюції системи")
            return

        self.rule_info_label.config(text="Виконується статистичне оцінювання")
        self._prepare_long_search()
        self._set_progress(0, "Підготовка")

        def progress_callback(current: int, total: int, label: str = "Виконання") -> None:
            percent = (current / total * 100) if total else 0
            self.root.after(0, lambda: self._set_progress(percent, label))

        def task():
            try:
                result_text = worker(progress_callback)
            except Exception as error:
                self.root.after(0, lambda: messagebox.showerror("Помилка оцінювання", str(error)))
                self.root.after(0, self.update_rule_info)
                self.root.after(0, self._reset_progress)
                self.root.after(0, lambda: setattr(self, "stop_search_requested", False))
                return

            def show_result():
                self.update_rule_info()
                self._set_progress(100, "Завершено")
                self.stop_search_requested = False
                TextReportWindow(title, result_text)

            self.root.after(0, show_result)

        threading.Thread(target=task, daemon=True).start()

    def evaluate_selected_rule_ui(self) -> None:
        rule_name = self.selected_rule.get()
        if not rule_name:
            messagebox.showwarning("Увага", "Спочатку виберіть правило")
            return

        def worker(progress_callback) -> str:
            engine = RuleEvaluationEngine(self.rule_manager)
            config = self._quick_rule_config()
            result = engine.evaluate_rule(rule_name, config)
            self.root.after(0, lambda: self._set_progress(100, "Оцінка правила завершена"))
            return engine.format_evaluation_report(result)

        self._run_evaluation_in_background(worker, f"Оцінювання правила: {rule_name}")

    def evaluate_field_generation_ui(self) -> None:
        def worker(progress_callback) -> str:
            engine = RuleEvaluationEngine(self.rule_manager)
            result_a = engine.evaluate_field_generation("uniform_random", sample_count=100, progress_callback=progress_callback)
            result_b = engine.evaluate_field_generation("balanced_random", sample_count=100, progress_callback=lambda c, t, _l: progress_callback(c, t, f"Генерація поля (balanced): {c}/{t}"))
            return (
                engine.format_evaluation_report(result_a)
                + "\n\n"
                + "=" * 70
                + "\n\n"
                + engine.format_evaluation_report(result_b)
            )

        self._run_evaluation_in_background(worker, "Оцінювання генерації поля")

    def _quick_rule_config(self) -> RuleEvaluationConfig:
        return RuleEvaluationConfig(
            num_runs=10,
            warmup_iterations=10,
            capture_iterations=32,
            field_mode="uniform_random",
            field_seed=12345,
        )

    def _main_rule_config(self) -> RuleEvaluationConfig:
        return RuleEvaluationConfig(
            num_runs=15,
            warmup_iterations=10,
            capture_iterations=100,
            field_mode="uniform_random",
            field_seed=12345,
        )

    def find_nist_field_ui(self) -> None:
        rule_name = self.selected_rule.get()
        if not rule_name:
            messagebox.showwarning("Увага", "Спочатку виберіть правило.")
            return

        def worker(progress_callback) -> str:
            engine = FieldSearchEngine(self.rule_manager, self.field_nist_cache, GRID_SIZE)
            result = engine.find_good_field_by_nist(
                rule_name=rule_name,
                candidate_count=None,
                warmup_iterations=10,
                capture_iterations=256,
                mode="uniform_random",
                progress_callback=progress_callback,
                should_stop=lambda: self.stop_search_requested,
                quick_filter_iterations=32,
            )
            self.field_nist_cache.flush()

            if result is None:
                return (
                    "ПОШУК ПОЛЯ ЧЕРЕЗ NIST"
                    f"Правило: {rule_name}"
                    "Не знайдено жодного початкового поля, яке проходить 9 або більше NIST-тестів."
                    "Усі перевірені невдалі комбінації збережено у field_nist_cache.json і буде пропущено під час наступних запусків."
                )

            def apply_best():
                self.ca.set_grid(result["grid"])
                self.draw_grid()

            self.root.after(0, apply_best)

            evaluator = RuleEvaluationEngine(self.rule_manager, GRID_SIZE)
            report = [
                "ЗНАЙДЕНО ПОЧАТКОВЕ ПОЛЕ, ЯКЕ ПРОХОДИТЬ 9 АБО БІЛЬШЕ NIST-ТЕСТІВ",
                f"Правило: {rule_name}",
                f"Номер кандидата: {result['index']}",
                f"Перевірено нових комбінацій: {result['checked_count']}",
                f"Відсіяно швидким фільтром: {result.get('filtered_count', 0)}",
                f"Перевірено через NIST: {result.get('nist_checked_count', 0)}",
                f"Пропущено вже відомих невдалих комбінацій: {result.get('skipped_count', 0)}",
                "",
                evaluator.format_evaluation_report({
                    "bit_length": result["bit_length"],
                    "ones_ratio": result["ones_ratio"],
                    "entropy": result["entropy"],
                    "avg_hamming_ratio": result["avg_hamming_ratio"],
                    "cycle_hits": 0,
                    "composite_score": result["composite_score"],
                    "nist": result["nist"],
                }),
                "",
                "Поле застосовано до екрана.",
            ]
            return "\n".join(report)

        self._run_evaluation_in_background(worker, "Пошук поля через NIST")

    def _apply_found_rule(self, rule_name: str, outputs: Dict[str, str]) -> None:
        unique_name = self.rule_manager.generate_unique_rule_name(rule_name)
        self.rule_manager.add_rule(unique_name, outputs)
        self.refresh_rule_combobox(unique_name)
        self.update_rule_info()

    def save_current_field_ui(self) -> None:
        file_path = filedialog.asksaveasfilename(
            title="Зберегти поле",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not file_path:
            return
        try:
            self.ca.save_grid_to_file(file_path)
            messagebox.showinfo("Успіх", "Поточне поле збережено.")
        except Exception as error:
            messagebox.showerror("Помилка", str(error))

    def load_field_ui(self) -> None:
        if self.is_animating:
            messagebox.showwarning("Увага", "Спочатку зупиніть еволюцію системи.")
            return
        file_path = filedialog.askopenfilename(
            title="Завантажити поле",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not file_path:
            return
        try:
            self.ca.load_grid_from_file(file_path)
            self.draw_grid()
            messagebox.showinfo("Успіх", "Поле успішно завантажено.")
        except Exception as error:
            messagebox.showerror("Помилка", str(error))

    def encrypt_message(self) -> None:
        field_bits = self.ca.grid_to_bits(mode="row")
        normalized_message = self.crypto.normalize_message_bits_from_text(self.message_var.get(), len(field_bits))
        cipher_bits = self.crypto.encrypt(normalized_message, field_bits)
        cipher_hex = self.crypto.bits_to_hex(cipher_bits)

        self.message_blocks_var.set(" ".join(self.crypto.split_into_blocks(normalized_message)))
        self.cipher_bits_var.set(cipher_bits)
        self.cipher_var.set(cipher_hex)
        self.cipher_blocks_var.set(" ".join(self.crypto.split_into_blocks(cipher_bits)))
        self.decrypted_var.set("")
        self.ciphertext_bits = cipher_bits

    def decrypt_message(self) -> None:
        cipher_hex = self.cipher_var.get().strip()
        if not cipher_hex:
            messagebox.showwarning("Увага", "Шифротекст відсутній. Спочатку виконайте шифрування або вставте шифртекст.")
            return

        field_bits = self.ca.grid_to_bits(mode="row")
        cipher_bits = self.crypto.hex_to_bits(cipher_hex, len(field_bits))
        plaintext_bits = self.crypto.decrypt(cipher_bits, field_bits)
        decoded_text = self.crypto.bits_to_text(plaintext_bits)

        self.ciphertext_bits = cipher_bits
        self.cipher_bits_var.set(cipher_bits)
        self.cipher_var.set(self.crypto.bits_to_hex(cipher_bits))
        self.cipher_blocks_var.set(" ".join(self.crypto.split_into_blocks(cipher_bits)))
        self.decrypted_var.set(decoded_text)
        self.message_var.set(decoded_text)
        self.message_blocks_var.set(" ".join(self.crypto.split_into_blocks(plaintext_bits)))

    def paste_message(self) -> None:
        try:
            clipboard_text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showwarning("Увага", "Буфер обміну порожній або недоступний.")
            return
        self.message_var.set(clipboard_text.strip())
        self.message_entry.focus_set()

    def clear_message_field(self) -> None:
        self.message_var.set("")
        self.message_blocks_var.set("")
        self.decrypted_var.set("")

    def paste_ciphertext(self) -> None:
        try:
            clipboard_text = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showwarning("Увага", "Буфер обміну порожній або недоступний.")
            return
        self.cipher_var.set(clipboard_text.strip())
        if hasattr(self, "cipher_entry"):
            self.cipher_entry.focus_set()

    def clear_ciphertext_field(self) -> None:
        self.cipher_var.set("")
        self.cipher_bits_var.set("")
        self.cipher_blocks_var.set("")
        self.decrypted_var.set("")

    def copy_ciphertext(self) -> None:
        ciphertext = self.cipher_var.get().strip()
        if not ciphertext:
            messagebox.showwarning("Увага", "Шифротекст відсутній.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(ciphertext)
        self.root.update()
        messagebox.showinfo("Успіх", "Шифротекст у шістнадцятковому вигляді скопійовано в буфер обміну.")

def main() -> None:
    root = tk.Tk()
    CAApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
