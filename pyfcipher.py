#!/usr/bin/env python3
from __future__ import annotations

import base64
import getpass
import hashlib
import os
from pathlib import Path
import sys

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("Не установлена библиотека cryptography.")
    print("Установите её: python -m pip install cryptography")
    raise SystemExit(1)

MAGIC = b"FCIPHER1"
SALT_SIZE = 16
ITERATIONS = 600_000


def password_key(password: str, salt: bytes) -> bytes:
    raw_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32
    )
    return base64.urlsafe_b64encode(raw_key)


def nonexisting_path(path: Path) -> Path:
    candidate = path
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.{counter}")
        counter += 1
    return candidate


def encrypt(source: Path, password: str) -> Path:
    salt = os.urandom(SALT_SIZE)
    token = Fernet(password_key(password, salt)).encrypt(source.read_bytes())
    target = nonexisting_path(source.with_name(source.name + ".enc"))
    target.write_bytes(MAGIC + salt + token)
    return target


def decrypt(source: Path, password: str) -> Path:
    content = source.read_bytes()
    if len(content) <= len(MAGIC) + SALT_SIZE or not content.startswith(MAGIC):
        raise ValueError("Это не файл, созданный этим инструментом.")
    salt = content[len(MAGIC):len(MAGIC) + SALT_SIZE]
    token = content[len(MAGIC) + SALT_SIZE:]
    try:
        plaintext = Fernet(password_key(password, salt)).decrypt(token)
    except InvalidToken as exc:
        raise ValueError("Неверный пароль либо файл повреждён.") from exc

    name = source.name[:-4] if source.name.endswith(".enc") else source.name + ".decrypted"
    target = nonexisting_path(source.with_name(name))
    target.write_bytes(plaintext)
    return target


def main() -> None:
    print("Шифратор файлов — исходный файл не изменяется.")
    mode = input("Выберите действие: [1] шифровать, [2] дешифровать: ").strip()
    if mode not in {"1", "2"}:
        print("Нужно выбрать 1 или 2.")
        return

    raw_path = input("Введите путь к файлу: ").strip().strip('"')
    source = Path(raw_path).expanduser()
    if not source.is_file():
        print("Файл не найден или это не обычный файл.")
        return

    password = getpass.getpass("Пароль: ")
    if not password:
        print("Пустой пароль использовать нельзя.")
        return
    if mode == "1":
        repeat = getpass.getpass("Повторите пароль: ")
        if password != repeat:
            print("Пароли не совпадают.")
            return

    try:
        result = encrypt(source, password) if mode == "1" else decrypt(source, password)
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}")
        return

    print(f"Готово: {result}")
    if mode == "1":
        print("Сохраните пароль: без него расшифровка невозможна.")


if __name__ == "__main__":
    main()
