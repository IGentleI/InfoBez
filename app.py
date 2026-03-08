import random
import time
import tkinter as tk
from tkinter import ttk, messagebox
from math import gcd


TARGET_DIGITS = 35


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


def random_prime(digits: int) -> int:
    low = 10 ** (digits - 1)
    high = (10 ** digits) - 1
    while True:
        candidate = random.randrange(low, high)
        candidate |= 1
        if is_probable_prime(candidate):
            return candidate


def modular_inverse(a: int, m: int) -> int:
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r > 1:
        raise ValueError("Обратный элемент не существует")
    if t < 0:
        t += m
    return t


def block_size_for_modulus(n: int) -> int:
    k = 1
    while 256 ** (k + 1) < n:
        k += 1
    return k


def generate_rsa_for_variant_10() -> dict:
    while True:
        p = random_prime(17)
        q = random_prime(18)
        if p == q:
            continue
        n = p * q
        if len(str(n)) == TARGET_DIGITS:
            break

    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = modular_inverse(e, phi)

    return {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d,
        "k": block_size_for_modulus(n),
    }


def encrypt_ascii(plaintext: str, e: int, n: int, k: int):
    try:
        data = plaintext.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Текст должен быть в ASCII (символы с кодами 0..127)") from exc

    blocks = [data[i : i + k] for i in range(0, len(data), k)]
    encrypted = []
    for block in blocks:
        value = int.from_bytes(block, byteorder="big")
        encrypted.append(pow(value, e, n))
    return encrypted, len(data)


def decrypt_ascii(cipher_blocks, d: int, n: int, k: int, data_length: int):
    decoded = bytearray()
    for i, block in enumerate(cipher_blocks):
        value = pow(block, d, n)
        if i < len(cipher_blocks) - 1:
            block_bytes = value.to_bytes(k, byteorder="big")
        else:
            tail = data_length - k * (len(cipher_blocks) - 1)
            block_bytes = value.to_bytes(max(tail, 1), byteorder="big")
        decoded.extend(block_bytes)
    return decoded[:data_length].decode("ascii")


class RSAWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSA — вариант 10 (N=35)")
        self.geometry("1100x780")

        self.keys = None

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Button(top, text="1) Сгенерировать ключи", command=self.generate_keys).pack(side="left", padx=5)
        ttk.Button(top, text="2) Зашифровать", command=self.encrypt_text).pack(side="left", padx=5)
        ttk.Button(top, text="3) Расшифровать", command=self.decrypt_text).pack(side="left", padx=5)
        ttk.Button(top, text="Проверка (10 примеров)", command=self.run_control_tests).pack(side="left", padx=5)

        middle = ttk.Panedwindow(self, orient="horizontal")
        middle.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(middle, padding=8)
        right = ttk.Frame(middle, padding=8)
        middle.add(left, weight=1)
        middle.add(right, weight=1)

        ttk.Label(left, text="Открытый текст (ASCII):").pack(anchor="w")
        self.input_text = tk.Text(left, height=12, wrap="word")
        self.input_text.pack(fill="both", expand=True)

        ttk.Label(left, text="Шифртекст (числа через пробел):").pack(anchor="w", pady=(8, 0))
        self.cipher_text = tk.Text(left, height=12, wrap="word")
        self.cipher_text.pack(fill="both", expand=True)

        ttk.Label(right, text="Расшифрованный текст:").pack(anchor="w")
        self.output_text = tk.Text(right, height=12, wrap="word")
        self.output_text.pack(fill="both", expand=True)

        ttk.Label(right, text="Журнал и параметры:").pack(anchor="w", pady=(8, 0))
        self.log_text = tk.Text(right, height=15, wrap="word")
        self.log_text.pack(fill="both", expand=True)

    def log(self, message: str):
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")

    def generate_keys(self):
        self.log("Генерация ключей RSA...")
        t0 = time.perf_counter()
        self.keys = generate_rsa_for_variant_10()
        elapsed = (time.perf_counter() - t0) * 1000

        self.log(
            f"Готово за {elapsed:.1f} мс | N={self.keys['n']}\n"
            f"digits(N)={len(str(self.keys['n']))}, e={self.keys['e']}, k={self.keys['k']} байт/блок"
        )

    def encrypt_text(self):
        if not self.keys:
            messagebox.showwarning("Нет ключей", "Сначала сгенерируйте ключи")
            return

        plaintext = self.input_text.get("1.0", "end").rstrip("\n")
        try:
            cipher_blocks, data_len = encrypt_ascii(plaintext, self.keys["e"], self.keys["n"], self.keys["k"])
        except ValueError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return

        self.cipher_text.delete("1.0", "end")
        self.cipher_text.insert("1.0", " ".join(map(str, cipher_blocks)))

        self.log(f"Зашифровано блоков: {len(cipher_blocks)}, длина текста: {data_len} байт")

    def decrypt_text(self):
        if not self.keys:
            messagebox.showwarning("Нет ключей", "Сначала сгенерируйте ключи")
            return

        raw = self.cipher_text.get("1.0", "end").strip()
        source = self.input_text.get("1.0", "end").rstrip("\n")
        data_length = len(source.encode("ascii", errors="ignore"))

        try:
            blocks = [int(x) for x in raw.split()] if raw else []
            plain = decrypt_ascii(blocks, self.keys["d"], self.keys["n"], self.keys["k"], data_length)
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось расшифровать: {exc}")
            return

        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", plain)
        self.log(f"Расшифровано блоков: {len(blocks)}")

    def run_control_tests(self):
        if not self.keys:
            self.generate_keys()

        samples = [
            "HELLO",
            "RSA TEST 123",
            "A quick brown fox",
            "ASCII only: !@#$%^&*()",
            "Data block splitting check",
            "0123456789",
            "OpenAI GPT",
            "Information Security",
            "Lorem ipsum dolor sit amet",
            "Final control example",
        ]

        ok = 0
        t0 = time.perf_counter()
        for sample in samples:
            c, ln = encrypt_ascii(sample, self.keys["e"], self.keys["n"], self.keys["k"])
            p = decrypt_ascii(c, self.keys["d"], self.keys["n"], self.keys["k"], ln)
            if p == sample:
                ok += 1
        elapsed = (time.perf_counter() - t0) * 1000

        self.log(f"Контроль: {ok}/{len(samples)} примеров прошли успешно. Время: {elapsed:.2f} мс")
        if ok == len(samples):
            messagebox.showinfo("Проверка", "Все 10 контрольных примеров успешно обработаны")
        else:
            messagebox.showwarning("Проверка", f"Ошибок: {len(samples) - ok}")


if __name__ == "__main__":
    app = RSAWindow()
    app.mainloop()
