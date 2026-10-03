import hashlib
import json
import mimetypes
import os
import socket
import struct
import sys
import time

SENDER_IP = "169.254.184.235"
PORT = 9000
CHUNK_SIZE = 4 * 1024 * 1024  # 4 МБ


def detect_file_type(file_path):
    mime, _ = mimetypes.guess_type(file_path)
    if mime and (mime.startswith("video") or mime.startswith("image")):
        return "MEDIA"
    return "DATA"


def get_chunk_hash(data):
    return hashlib.md5(data).hexdigest()


def send_exact(sock, data):
    """Гарантированная отправка всех байт."""
    sock.sendall(data)


def recv_exact(sock, length):
    """Гарантированный прием ровно length байт."""
    buf = bytearray()
    while len(buf) < length:
        more = sock.recv(length - len(buf))
        if not more:
            raise ConnectionResetError("Обрыв сети при чтении данных")
        buf.extend(more)
    return bytes(buf)


# ================= 1. ОТПРАВИТЕЛЬ =================


def run_sender():
    folder_path = input("\nВведите путь к папке или файлу: ").strip(" '\"")
    if not os.path.exists(folder_path):
        print("Ошибка: Путь не найден!")
        return

    files_list = []
    if os.path.isfile(folder_path):
        files_list.append(folder_path)
    else:
        for root, _, files in os.walk(folder_path):
            for f in files:
                files_list.append(os.path.join(root, f))

    meta_files = []
    for path in files_list:
        rel_path = (
            os.path.relpath(path, folder_path)
            if os.path.isdir(folder_path)
            else os.path.basename(path)
        )
        # ЗАЩИТА: Заменяем Windows-слэши '\' на универсальные '/' для JSON
        safe_rel_path = rel_path.replace("\\", "/")

        meta_files.append(
            {
                "path": safe_rel_path,
                "size": os.path.getsize(path),
                "type": detect_file_type(path),
            }
        )

    print(
        f"\n[!] Ожидание подключения получателя по кабелю (порт {PORT})..."
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", PORT))
        s.listen(1)

        while True:
            try:
                conn, addr = s.accept()
                print(f"[+] Подключен получатель: {addr[0]}")

                # Безопасная отправка JSON-структуры
                header_bytes = json.dumps(
                    meta_files, ensure_ascii=False
                ).encode("utf-8")
                send_exact(conn, struct.pack("!I", len(header_bytes)))
                send_exact(conn, header_bytes)

                for meta in meta_files:
                    # Восстанавливаем локальный путь для чтения с диска
                    local_rel_path = meta["path"].replace("/", os.sep)
                    full_path = (
                        os.path.join(folder_path, local_rel_path)
                        if os.path.isdir(folder_path)
                        else folder_path
                    )

                    offset_data = recv_exact(conn, 8)
                    start_offset = struct.unpack("!Q", offset_data)[0]
                    start_chunk = start_offset // CHUNK_SIZE

                    with open(full_path, "rb") as f:
                        f.seek(start_chunk * CHUNK_SIZE)
                        idx = start_chunk

                        while chunk := f.read(CHUNK_SIZE):
                            chunk_hash = get_chunk_hash(chunk)
                            header = struct.pack(
                                "!II32s",
                                idx,
                                len(chunk),
                                chunk_hash.encode("utf-8"),
                            )
                            send_exact(conn, header)
                            send_exact(conn, chunk)
                            idx += 1

                    # Конец файла
                    send_exact(
                        conn, struct.pack("!II32s", 0xFFFFFFFF, 0, b"0" * 32)
                    )

                print("\n[✓] ВСЕ ДАННЫЕ УСПЕШНО ПЕРЕДАНЫ!")
                break
            except (socket.error, ConnectionResetError) as e:
                print(
                    f"\n[!] Связь оборвалась ({e}). Ожидание переподключения..."
                )


# ================= 2. ПОЛУЧАТЕЛЬ =================


def run_receiver():
    save_dir = input("\nВведите папку для сохранения: ").strip(" '\"")
    if not save_dir:
        save_dir = "Received_Files"

    while True:
        print(f"Попытка подключения к {SENDER_IP}...")
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((SENDER_IP, PORT))
            print("[+] Соединение установлено!")

            # Читаем длину JSON заголовка
            h_len = struct.unpack("!I", recv_exact(conn, 4))[0]
            meta_bytes = recv_exact(conn, h_len)
            meta_files = json.loads(meta_bytes.decode("utf-8"))

            for meta in meta_files:
                local_rel_path = meta["path"].replace("/", os.sep)
                out_path = os.path.join(save_dir, local_rel_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)

                existing_size = (
                    os.path.getsize(out_path) if os.path.exists(out_path) else 0
                )
                completed_chunks = existing_size // CHUNK_SIZE
                resume_offset = completed_chunks * CHUNK_SIZE

                send_exact(conn, struct.pack("!Q", resume_offset))

                if resume_offset >= meta["size"]:
                    continue

                print(
                    f"Приём [{meta['type']}]: {meta['path']} (скачано {resume_offset / (1024**2):.1f} из {meta['size'] / (1024**2):.1f} МБ)"
                )

                mode = "r+b" if os.path.exists(out_path) else "wb"
                with open(out_path, mode) as f:
                    f.seek(resume_offset)

                    while True:
                        raw_header = recv_exact(conn, 40)
                        idx, chunk_len, expected_hash = struct.unpack(
                            "!II32s", raw_header
                        )
                        if idx == 0xFFFFFFFF:
                            break

                        expected_hash = expected_hash.decode("utf-8")
                        chunk_data = recv_exact(conn, chunk_len)

                        if get_chunk_hash(chunk_data) != expected_hash:
                            print(
                                f"\n[ОШИБКА] Повреждение в блоке №{idx}!"
                            )
                            sys.exit(1)

                        f.write(chunk_data)
                        f.flush()

            print("\n[✓] ПРИЁМ УСПЕШНО ЗАВЕРШЕН!")
            conn.close()
            break

        except (socket.error, ConnectionResetError) as e:
            print(
                f"[!] Ошибка/Обрыв сети ({e}). Повтор через 3 секунды..."
            )
            time.sleep(3)


if __name__ == "__main__":
    print("1. Отправить\n2. Принять")
    choice = input("Выберите роль: ").strip()
    if choice == "1":
        run_sender()
    elif choice == "2":
        run_receiver()
