import math
import random
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

VARIANT_NUMBER = 10
N_DIGITS = 35
DEFAULT_PUBLIC_EXPONENT = 65537


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime_with_digits(digits: int) -> int:
    if digits < 1:
        raise ValueError("Количество цифр должно быть положительным")

    lower = 10 ** (digits - 1)
    upper = (10 ** digits) - 1

    while True:
        candidate = random.randrange(lower, upper)
        candidate |= 1
        if is_probable_prime(candidate):
            return candidate


def egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Обратный элемент не существует")
    return x % m


def generate_rsa_keys(n_digits: int = N_DIGITS):
    half = n_digits // 2
    p_digits = half
    q_digits = n_digits - half

    while True:
        p = random_prime_with_digits(p_digits)
        q = random_prime_with_digits(q_digits)
        if p == q:
            continue
        n = p * q
        if len(str(n)) != n_digits:
            continue

        phi = (p - 1) * (q - 1)
        e = DEFAULT_PUBLIC_EXPONENT
        if math.gcd(e, phi) != 1:
            e = 3
            while e < phi and math.gcd(e, phi) != 1:
                e += 2
        d = mod_inverse(e, phi)
        return {
            "p": p,
            "q": q,
            "n": n,
            "phi": phi,
            "e": e,
            "d": d,
        }


def block_size_bytes(n: int) -> int:
    return max(1, (n.bit_length() - 1) // 8)


def split_blocks(data: bytes, block_size: int):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def rsa_encrypt_text(plain_text: str, e: int, n: int):
    data = plain_text.encode("ascii")
    k = block_size_bytes(n)
    blocks = split_blocks(data, k)
    encrypted_blocks = []
    for block in blocks:
        m = int.from_bytes(block, byteorder="big")
        c = pow(m, e, n)
        encrypted_blocks.append(c)
    return encrypted_blocks, k


def rsa_decrypt_blocks(cipher_blocks, d: int, n: int, k: int):
    recovered = bytearray()
    for i, c in enumerate(cipher_blocks):
        m = pow(c, d, n)
        min_len = 1 if i == len(cipher_blocks) - 1 else k
        part = m.to_bytes(max(min_len, (m.bit_length() + 7) // 8), byteorder="big")
        if i != len(cipher_blocks) - 1 and len(part) < k:
            part = b"\x00" * (k - len(part)) + part
        recovered.extend(part)
    return recovered.decode("ascii")


class RSAWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSA шифратор/дешифратор — вариант 10 (N=35)")
        self.geometry("980x760")

        self.keys = None
        self.current_block_size = None

        self._build_ui()

    def _build_ui(self):
        header = ttk.Label(
            self,
            text=f"ЛР: RSA, вариант {VARIANT_NUMBER}. Модуль N содержит {N_DIGITS} десятичных знаков",
            font=("Segoe UI", 11, "bold"),
        )
        header.pack(pady=10)

        key_frame = ttk.LabelFrame(self, text="Ключи RSA")
        key_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(key_frame, text="Сгенерировать ключи", command=self.generate_keys).grid(
            row=0, column=0, padx=6, pady=6, sticky="w"
        )

        self.n_var = tk.StringVar(value="-")
        self.e_var = tk.StringVar(value="-")
        self.d_var = tk.StringVar(value="-")
        self.k_var = tk.StringVar(value="-")

        ttk.Label(key_frame, text="n:").grid(row=1, column=0, sticky="nw", padx=6)
        ttk.Entry(key_frame, textvariable=self.n_var, width=120).grid(row=1, column=1, padx=6, pady=2)

        ttk.Label(key_frame, text="e:").grid(row=2, column=0, sticky="w", padx=6)
        ttk.Entry(key_frame, textvariable=self.e_var, width=30).grid(row=2, column=1, sticky="w", padx=6, pady=2)

        ttk.Label(key_frame, text="d:").grid(row=3, column=0, sticky="w", padx=6)
        ttk.Entry(key_frame, textvariable=self.d_var, width=120).grid(row=3, column=1, padx=6, pady=2)

        ttk.Label(key_frame, text="Размер блока K (байт):").grid(row=4, column=0, sticky="w", padx=6)
        ttk.Entry(key_frame, textvariable=self.k_var, width=10).grid(row=4, column=1, sticky="w", padx=6, pady=2)

        io_frame = ttk.LabelFrame(self, text="Ввод / вывод")
        io_frame.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(io_frame, text="Открытый текст (ASCII):").pack(anchor="w", padx=6, pady=(6, 2))
        self.plain_text = scrolledtext.ScrolledText(io_frame, height=8, wrap=tk.WORD)
        self.plain_text.pack(fill="x", padx=6)

        btn_frame = ttk.Frame(io_frame)
        btn_frame.pack(fill="x", padx=6, pady=8)
        ttk.Button(btn_frame, text="Зашифровать", command=self.encrypt_text).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Расшифровать", command=self.decrypt_text).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Проверка (10 примеров)", command=self.run_self_check).pack(side="left", padx=4)

        ttk.Label(io_frame, text="Шифртекст (числа через пробел):").pack(anchor="w", padx=6, pady=(6, 2))
        self.cipher_text = scrolledtext.ScrolledText(io_frame, height=8, wrap=tk.WORD)
        self.cipher_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        ttk.Label(
            self,
            text="Примечание: для совместимости с условием используется ASCII. Русские символы вводить нельзя.",
            foreground="#7a3e00",
        ).pack(anchor="w", padx=12, pady=(0, 10))

    def generate_keys(self):
        self.keys = generate_rsa_keys(N_DIGITS)
        self.current_block_size = block_size_bytes(self.keys["n"])

        self.n_var.set(str(self.keys["n"]))
        self.e_var.set(str(self.keys["e"]))
        self.d_var.set(str(self.keys["d"]))
        self.k_var.set(str(self.current_block_size))

    def encrypt_text(self):
        if not self.keys:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключи")
            return

        text = self.plain_text.get("1.0", tk.END).rstrip("\n")
        try:
            encrypted, k = rsa_encrypt_text(text, self.keys["e"], self.keys["n"])
        except UnicodeEncodeError:
            messagebox.showerror("Ошибка", "Текст должен содержать только ASCII-символы")
            return

        self.current_block_size = k
        self.k_var.set(str(k))
        self.cipher_text.delete("1.0", tk.END)
        self.cipher_text.insert(tk.END, " ".join(map(str, encrypted)))

    def decrypt_text(self):
        if not self.keys:
            messagebox.showwarning("Внимание", "Сначала сгенерируйте ключи")
            return

        raw = self.cipher_text.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showwarning("Внимание", "Введите шифртекст")
            return

        try:
            blocks = [int(x) for x in raw.split()]
            text = rsa_decrypt_blocks(blocks, self.keys["d"], self.keys["n"], self.current_block_size)
        except ValueError:
            messagebox.showerror("Ошибка", "Шифртекст должен содержать только целые числа")
            return
        except UnicodeDecodeError:
            messagebox.showerror("Ошибка", "Не удалось декодировать ASCII — возможно, неверные ключи/данные")
            return

        self.plain_text.delete("1.0", tk.END)
        self.plain_text.insert(tk.END, text)

    def run_self_check(self):
        if not self.keys:
            self.generate_keys()

        samples = [
            "HELLO",
            "RSA TEST 123",
            "A quick brown fox",
            "Symbols: !?,.-_",
            "Line1 Line2",
            "Python3.12",
            "ASCII ONLY",
            "1234567890",
            "Short",
            "Final control example",
        ]

        failures = []
        for sample in samples:
            encrypted, k = rsa_encrypt_text(sample, self.keys["e"], self.keys["n"])
            decrypted = rsa_decrypt_blocks(encrypted, self.keys["d"], self.keys["n"], k)
            if decrypted != sample:
                failures.append(sample)

        if failures:
            messagebox.showerror("Self-check", f"Проверка не пройдена. Ошибки: {len(failures)}")
        else:
            messagebox.showinfo("Self-check", "Успех: 10/10 примеров зашифрованы и расшифрованы корректно")


if __name__ == "__main__":
    app = RSAWindow()
    app.mainloop()
