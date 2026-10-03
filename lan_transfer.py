import hashlib
import json
import mimetypes
import os
import socket
import struct
import sys
import time

PORT = 9000
CHUNK_SIZE = 4 * 1024 * 1024  # 4 МБ — идеально для i5 (2 ядра)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def detect_file_type(file_path):
    """'Мозг' скрипта: определяет категория файла."""
    mime, _ = mimetypes.guess_type(file_path)
    if mime:
        if mime.startswith("video") or mime.startswith("image"):
            return "MEDIA"
    return "DATA"


def get_chunk_hash(data):
    return hashlib.md5(data).hexdigest()


# ================= ОТПРАВИТЕЛЬ =================


def run_sender():
    print(f"\n[ОТПРАВИТЕЛЬ] Ваш IP: {get_local_ip()}")
    folder_path = input("Введите путь к папке/файлу: ").strip(" '\"")

    if not os.path.exists(folder_path):
        print("Путь не найден!")
        return

    # Собираем список файлов
    files_list = []
    if os.path.isfile(folder_path):
        files_list.append(folder_path)
    else:
        for root, _, files in os.walk(folder_path):
            for f in files:
                files_list.append(os.path.join(root, f))

    print("\n[1/3] Анализ файлов и сборка манифеста...")
    manifest = []

    for path in files_list:
        ftype = detect_file_type(path)
        fsize = os.path.getsize(path)
        rel_path = (
            os.path.relpath(path, folder_path)
            if os.path.isdir(folder_path)
            else os.path.basename(path)
        )

        file_entry = {
            "path": rel_path,
            "size": fsize,
            "type": ftype,
            "chunks": [],
        }

        # Нарезка на блоки и расчет хэшей
        with open(path, "rb") as f:
            idx = 0
            while chunk := f.read(CHUNK_SIZE):
                file_entry["chunks"].append(
                    {"idx": idx, "hash": get_chunk_hash(chunk), "size": len(chunk)}
                )
                idx += 1

        manifest.append(file_entry)
        print(f"[{ftype}] Добавлен: {rel_path} ({len(file_entry['chunks'])} блоков)")

    print(f"\nОжидание подключения на порту {PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", PORT))
        s.listen(1)
        conn, addr = s.accept()
        print(f"[+] Подключен получатель: {addr[0]}")

        # 1. Отправка манифеста
        m_bytes = json.dumps(manifest).encode("utf-8")
        conn.sendall(struct.pack("!I", len(m_bytes)) + m_bytes)

        # Ждем подтверждения
        conn.recv(1)

        # 2. Отправка файлов по рецепту
        print("\n[2/3] Передача данных...")
        for entry in manifest:
            full_path = (
                os.path.join(folder_path, entry["path"])
                if os.path.isdir(folder_path)
                else folder_path
            )
            with open(full_path, "rb") as f:
                for chunk_info in entry["chunks"]:
                    chunk_data = f.read(chunk_info["size"])
                    # Отправка размера и данных
                    conn.sendall(
                        struct.pack("!I", len(chunk_data)) + chunk_data
                    )

    print("\n[3/3] Передача успешно завершена!")


# ================= ПОЛУЧАТЕЛЬ =================


def run_receiver():
    sender_ip = input("Введите IP-адрес отправителя: ").strip()
    save_dir = input("Введите папку для сохранения: ").strip(" '\"")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((sender_ip, PORT))

        # 1. Приём манифеста
        m_len = struct.unpack("!I", conn.recv(4))[0]
        m_bytes = b""
        while len(m_bytes) < m_len:
            m_bytes += conn.recv(min(4096, m_len - len(m_bytes)))

        manifest = json.loads(m_bytes.decode("utf-8"))
        conn.sendall(b"\x01")  # Готов к приему

        # 2. Приём и проверка на лету
        for entry in manifest:
            out_path = os.path.join(save_dir, entry["path"])
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            print(
                f"\nПриём [{entry['type']}]: {entry['path']} ({entry['size'] / (1024**2):.1f} МБ)"
            )

            with open(out_path, "wb") as f:
                for chunk_info in entry["chunks"]:
                    raw_len = conn.recv(4)
                    if not raw_len:
                        break
                    c_len = struct.unpack("!I", raw_len)[0]

                    chunk_data = b""
                    while len(chunk_data) < c_len:
                        chunk_data += conn.recv(min(65536, c_len - len(chunk_data)))

                    # Проверка хэша блока
                    if get_chunk_hash(chunk_data) != chunk_info["hash"]:
                        print(
                            f"[ОШИБКА] Ошибка целостности в блоке {chunk_info['idx']}!"
                        )
                        sys.exit(1)

                    f.write(chunk_data)

    print("\n[✓] Все данные успешно приняты и проверены!")


if __name__ == "__main__":
    print("1. Отправить\n2. Принять")
    c = input("Выберите роль: ").strip()
    if c == "1":
        run_sender()
    elif c == "2":
        run_receiver()
