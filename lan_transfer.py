#!/usr/bin/env python3
"""
LAN Transfer: передача файлов и папок по локальной сети.

Три способа использования
-------------------------
1) Интерактивное меню:        python lan_transfer.py
2) Командная строка (утилита):
       python lan_transfer.py devices [--wait 3] [--json]
       python lan_transfer.py send ПУТЬ [--to ИМЯ_ИЛИ_ID | --ip АДРЕС[:ПОРТ]]
       python lan_transfer.py receive [--dir ПАПКА] [--yes] [--from ИМЯ_ИЛИ_ID] [--once]
       python lan_transfer.py name [НОВОЕ_ИМЯ]      python lan_transfer.py id
       python lan_transfer.py unfinished
3) Как библиотека:
       import lan_transfer as lt
       lt.discover()                                  # список устройств
       lt.send(r"C:\\photos", to="Ноутбук")            # или ip="192.168.1.5"
       lt.receive(r"D:\\inbox", auto_accept=True, once=True)

Что умеет
---------
* автопоиск устройств (UDP-broadcast) и ручной ввод IP;
* постоянный ID устройства (dev_<24 hex>) + изменяемое имя, всё в device.json;
  одинаковые имена различаются по ID: "Ноутбук #a1b2";
* отправитель выбирает устройство и ждёт подтверждения получателя;
* манифест передачи у обеих сторон (manifests/): источник, папка сохранения,
  отправитель, получатель, сколько блоков передано и полный список блоков;
* докачка с места остановки;
* передача изменений: если файл на получателе уже есть (или была недокачана
  старая версия), по сети идут только изменённые куски (как rsync). Совпадающие
  куски ищутся в любой позиции, поэтому вставка или удаление в середине файла
  не заставляет слать всё заново;
* пустые папки передаются; при выборе папки она передаётся целиком вместе с собой.

Порты: UDP 9001 (поиск), TCP 9000 (передача). Шифрования нет, только для доверенной сети.
"""

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
import zlib
from collections import Counter
from datetime import datetime

APP = "lantransfer"
PROTO = 2
TCP_PORT = 9000
DISCOVERY_PORT = 9001
CHUNK_SIZE = 4 * 1024 * 1024  # размер блока (пакета), 4 МБ
BROADCAST_INTERVAL = 2.0
PEER_TTL = 8.0
IDLE_TIMEOUT = 30.0
CONFIRM_TIMEOUT = 120.0
OFFER_TIMEOUT = 600.0
SAVE_EVERY = 16
MIN_DELTA_SIZE = 8192  # файлы меньше этого просто отправляются целиком
DELTA_PROBE = 8 * 1024 * 1024  # сколько данных пробуем, прежде чем отказаться от сравнения
ADLER_MOD = 65521
SIG_ENTRY = 12  # 4 байта быстрой суммы + 8 байт точного хэша

BASE_DIR = os.environ.get("LAN_TRANSFER_HOME") or os.path.dirname(
    os.path.abspath(__file__)
)

TID_RE = re.compile(r"^tr_[0-9a-f]{20}$")
ID_RE = re.compile(r"^dev_[0-9a-f]{24}$")


def ask(prompt=""):
    return input(prompt)


def _noop(*_a, **_k):
    pass


# ============================ УТИЛИТЫ ============================


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def clean(text, limit=32):
    s = "".join(ch for ch in str(text) if ch.isprintable()).strip()
    return s[:limit]


def clean_path(text):
    return text.strip().strip("'\"")


def fmt_size(n):
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return f"{int(n)} Б" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024


def atomic_write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def chunk_hash(data):
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def make_labels(entries):
    """entries: [(id, name)]. Одинаковые имена получают суффикс из ID."""
    counts = Counter(name.casefold() for _, name in entries)
    return {
        i: (f"{n} #{i[-4:]}" if counts[n.casefold()] > 1 else n) for i, n in entries
    }


def safe_join(base, rel):
    """Защита от выхода за пределы папки сохранения."""
    parts = str(rel).replace("\\", "/").split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"небезопасный путь: {rel!r}")
    if os.name == "nt" and any(":" in p for p in parts):
        raise ValueError(f"небезопасный путь: {rel!r}")
    base_abs = os.path.abspath(base)
    dest = os.path.abspath(os.path.join(base_abs, *parts))
    if os.path.commonpath([base_abs, dest]) != base_abs:
        raise ValueError(f"небезопасный путь: {rel!r}")
    return dest


def parse_hostport(text, default_port=TCP_PORT):
    text = text.strip()
    if ":" in text:
        host, _, port = text.rpartition(":")
        return host.strip(), int(port)
    return text, default_port


# ============================ СЕТЕВОЙ ПРОТОКОЛ ============================
# Сообщение: 4 байта длины + JSON. За сообщениями chunk/delta/sig следуют сырые байты.


def send_all(sock, data):
    view = memoryview(data)
    sent, last = 0, time.time()
    while sent < len(view):
        try:
            n = sock.send(view[sent : sent + (1 << 20)])
        except socket.timeout:
            if time.time() - last > IDLE_TIMEOUT:
                raise ConnectionError("таймаут отправки")
            continue
        if n == 0:
            raise ConnectionError("соединение закрыто")
        sent += n
        last = time.time()


def recv_exact(sock, n, idle=IDLE_TIMEOUT):
    buf = bytearray(n)
    view = memoryview(buf)
    got, last = 0, time.time()
    while got < n:
        try:
            r = sock.recv_into(view[got:], n - got)
        except socket.timeout:
            if time.time() - last > idle:
                raise ConnectionError("нет ответа (таймаут)")
            continue
        if r == 0:
            raise ConnectionError("соединение закрыто")
        got += r
        last = time.time()
    return buf


def send_msg(sock, obj):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    send_all(sock, struct.pack("!I", len(body)) + body)


def recv_msg(sock, wait=IDLE_TIMEOUT):
    (length,) = struct.unpack("!I", recv_exact(sock, 4, idle=wait))
    if length > 64 * 1024 * 1024:
        raise ConnectionError("слишком большое сообщение")
    return json.loads(bytes(recv_exact(sock, length)).decode("utf-8"))


def safe_send_msg(sock, obj):
    try:
        send_msg(sock, obj)
    except Exception:
        pass


# ============================ СРАВНЕНИЕ ВЕРСИЙ (delta) ============================
# Идея как у rsync. Получатель режет СТАРУЮ версию файла на блоки и присылает их
# "отпечатки". Отправитель двигает окно по НОВОЙ версии и ищет блоки, которые уже есть
# у получателя, в любой позиции. Совпавшее не передаётся, вместо него идёт команда
# "возьми у себя кусок с такого-то места", а между совпадениями передаются только
# новые байты.
#
# Быстрая сумма окна = Adler-32. Её можно обновлять при сдвиге на 1 байт за O(1);
# найденное совпадение подтверждается точным хэшем блока.


def choose_block_size(size):
    s = int(math.sqrt(max(size, 1)))
    bs = 2048
    while bs < s and bs < 131072:
        bs <<= 1
    return bs


def strong_hash(data):
    return hashlib.blake2b(data, digest_size=8).digest()


def make_signature(fileobj, bs):
    """Отпечатки всех полных блоков файла. Возвращает (число_блоков, байты)."""
    sig = bytearray()
    n = 0
    while True:
        blk = fileobj.read(bs)
        if len(blk) < bs:
            break
        sig += struct.pack("!I", zlib.adler32(blk)) + strong_hash(blk)
        n += 1
    return n, bytes(sig)


def build_table(sig, n):
    table = {}
    for k in range(n):
        base = k * SIG_ENTRY
        weak = struct.unpack_from("!I", sig, base)[0]
        table.setdefault(weak, []).append((k, bytes(sig[base + 4 : base + SIG_ENTRY])))
    return table


def compute_delta(data, bs, table):
    """
    Сравнивает новый блок данных с базой получателя.
    Возвращает (ops, literal_bytes, matched_bytes), где ops:
      ["c", смещение_в_базе, длина]  - взять кусок из старой версии
      ["l", длина]                    - вставить новые байты (идут в literal_bytes)
    """
    n = len(data)
    if n < bs:
        return [["l", n]], bytes(data), 0
    mv = memoryview(data)
    ops, lits = [], bytearray()
    matched = 0
    lit_start = 0
    i = 0
    weak = zlib.adler32(mv[0:bs])
    a, b = weak & 0xFFFF, weak >> 16
    while True:
        hit = None
        cands = table.get((b << 16) | a)
        if cands:
            s = strong_hash(mv[i : i + bs])
            for idx, st in cands:
                if st == s:
                    hit = idx
                    break
        if hit is not None:
            if i > lit_start:
                ops.append(["l", i - lit_start])
                lits += mv[lit_start:i]
            off = hit * bs
            if ops and ops[-1][0] == "c" and ops[-1][1] + ops[-1][2] == off:
                ops[-1][2] += bs
            else:
                ops.append(["c", off, bs])
            matched += bs
            i += bs
            lit_start = i
            if i + bs > n:
                break
            weak = zlib.adler32(mv[i : i + bs])
            a, b = weak & 0xFFFF, weak >> 16
            continue
        if i + bs >= n:
            break
        out, inn = data[i], data[i + bs]
        a = (a - out + inn) % ADLER_MOD
        b = (b - bs * out + a - 1) % ADLER_MOD
        i += 1
    if n > lit_start:
        ops.append(["l", n - lit_start])
        lits += mv[lit_start:n]
    return ops, bytes(lits), matched


def rebuild_chunk(ops, payload, basis, expected):
    out = bytearray()
    pos = 0
    for op in ops:
        kind = op[0]
        if kind == "l":
            ln = int(op[1])
            if ln < 0 or pos + ln > len(payload):
                raise ValueError("повреждённый список изменений")
            out += payload[pos : pos + ln]
            pos += ln
        elif kind == "c":
            off, ln = int(op[1]), int(op[2])
            if basis is None or off < 0 or ln < 0 or ln > expected:
                raise ValueError("повреждённый список изменений")
            basis.seek(off)
            piece = basis.read(ln)
            if len(piece) != ln:
                raise ValueError("базовый файл изменился")
            out += piece
        else:
            raise ValueError("неизвестная операция")
    if len(out) != expected or pos != len(payload):
        raise ValueError("размер собранного блока не совпал")
    return bytes(out)


# ============================ УСТРОЙСТВО (ID + имя) ============================


class Device:
    """Постоянные данные устройства: device.json (id, name, known_peers)."""

    def __init__(self, base_dir=None):
        base_dir = base_dir or BASE_DIR
        self.base_dir = base_dir
        self.file = os.path.join(base_dir, "device.json")
        self.manifest_dir = os.path.join(base_dir, "manifests")
        self.lock = threading.RLock()
        self.data = self._load()

    def _load(self):
        data = {}
        if os.path.exists(self.file):
            try:
                with open(self.file, encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, ValueError):
                data = {}
        if not isinstance(data, dict):
            data = {}
        changed = False
        if not ID_RE.match(str(data.get("id", ""))):
            data["id"] = "dev_" + secrets.token_hex(12)
            changed = True
        if not clean(data.get("name", "")):
            data["name"] = clean(socket.gethostname()) or "device"
            changed = True
        if not isinstance(data.get("known_peers"), dict):
            data["known_peers"] = {}
            changed = True
        if changed:
            atomic_write_json(self.file, data)
        return data

    @property
    def id(self):
        return self.data["id"]

    @property
    def name(self):
        return self.data["name"]

    def set_name(self, name):
        name = clean(name)
        if not name:
            raise ValueError("пустое имя")
        with self.lock:
            self.data["name"] = name
            atomic_write_json(self.file, self.data)

    def remember(self, peer_id, name, ip):
        with self.lock:
            cur = self.data["known_peers"].get(peer_id)
            if cur and cur.get("name") == name and cur.get("last_ip") == ip:
                return
            self.data["known_peers"][peer_id] = {
                "name": name,
                "last_ip": ip,
                "last_seen": now_iso(),
            }
            atomic_write_json(self.file, self.data)

    def is_known(self, peer_id):
        return peer_id in self.data["known_peers"]


_default_device = None


def get_device(home=None):
    global _default_device
    if home:
        return Device(home)
    if _default_device is None:
        _default_device = Device()
    return _default_device


# ============================ АВТОПОИСК ============================


class Discovery:
    def __init__(self, device):
        self.device = device
        self.peers = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.receiving = False
        self.tcp_port = TCP_PORT
        self.listen_ok = True
        self.on_error = print

    def start(self):
        threading.Thread(target=self._listen, daemon=True).start()
        threading.Thread(target=self._announce, daemon=True).start()
        return self

    def close(self):
        self.stop.set()

    def set_receiving(self, flag, port=None):
        self.receiving = flag
        if port:
            self.tcp_port = port

    def _targets(self):
        targets = {"255.255.255.255", "127.0.0.1"}
        ip = get_local_ip()
        parts = ip.split(".")
        if len(parts) == 4 and not ip.startswith("127."):
            targets.add(".".join(parts[:3] + ["255"]))
        return targets

    def _announce(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            while not self.stop.is_set():
                payload = json.dumps(
                    {
                        "app": APP,
                        "v": PROTO,
                        "id": self.device.id,
                        "name": self.device.name,
                        "port": self.tcp_port,
                        "receiving": self.receiving,
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
                for target in self._targets():
                    try:
                        s.sendto(payload, (target, DISCOVERY_PORT))
                    except OSError:
                        pass
                self.stop.wait(BROADCAST_INTERVAL)
        finally:
            s.close()

    def _listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s.bind(("", DISCOVERY_PORT))
        except OSError as e:
            self.listen_ok = False
            if self.on_error:
                self.on_error(
                    f"[!] Автопоиск не работает: порт UDP {DISCOVERY_PORT} занят ({e}). "
                    "Можно подключаться по IP."
                )
            s.close()
            return
        s.settimeout(1.0)
        try:
            while not self.stop.is_set():
                try:
                    data, addr = s.recvfrom(4096)
                except (socket.timeout, OSError):
                    continue
                try:
                    msg = json.loads(data.decode("utf-8"))
                    if msg.get("app") != APP:
                        continue
                    pid = str(msg["id"])
                    if not ID_RE.match(pid) or pid == self.device.id:
                        continue
                    name = clean(msg.get("name", "")) or "без имени"
                    port = int(msg["port"])
                except (ValueError, KeyError, TypeError):
                    continue
                with self.lock:
                    self.peers[pid] = {
                        "id": pid,
                        "name": name,
                        "ip": addr[0],
                        "port": port,
                        "receiving": bool(msg.get("receiving")),
                        "seen": time.time(),
                    }
                self.device.remember(pid, name, addr[0])
        finally:
            s.close()

    def snapshot(self):
        now = time.time()
        with self.lock:
            for pid in [p for p, v in self.peers.items() if now - v["seen"] > PEER_TTL]:
                del self.peers[pid]
            return sorted(
                (dict(v) for v in self.peers.values()), key=lambda v: v["name"].lower()
            )

    def find(self, pid):
        for p in self.snapshot():
            if p["id"] == pid:
                return p
        return None

    def labels(self):
        peers = self.snapshot()
        entries = [(self.device.id, self.device.name)] + [
            (p["id"], p["name"]) for p in peers
        ]
        return make_labels(entries), peers


def resolve_peer(disc, query, wait=5.0):
    """Ищет устройство по ID, имени или метке «Имя #abcd». Ждёт до wait секунд."""
    q = query.strip().casefold()
    deadline = time.time() + wait
    while True:
        labels, peers = disc.labels()
        found = [
            p
            for p in peers
            if q in (p["id"].casefold(), p["name"].casefold(), labels[p["id"]].casefold())
        ]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            names = ", ".join(f"{labels[p['id']]} [{p['id']}]" for p in found)
            raise ValueError(f"имя «{query}» неоднозначно, укажите ID или метку: {names}")
        if time.time() >= deadline:
            raise LookupError(f"устройство «{query}» не найдено в сети")
        time.sleep(0.4)


# ============================ МАНИФЕСТ ============================


def chunk_list(size, chunk_size):
    count = (size + chunk_size - 1) // chunk_size
    return [
        {
            "idx": i,
            "offset": i * chunk_size,
            "size": min(chunk_size, size - i * chunk_size),
            "done": False,
        }
        for i in range(count)
    ]


def make_transfer_id(sender_id, receiver_id, source_path, files, dirs):
    h = hashlib.sha256()
    h.update(f"{sender_id}|{receiver_id}|{source_path}\n".encode("utf-8"))
    for d in dirs:
        h.update(f"D|{d}\n".encode("utf-8"))
    for f in files:
        h.update(f"{f['path']}|{f['size']}|{f['mtime_ns']}\n".encode("utf-8"))
    return "tr_" + h.hexdigest()[:20]


class Manifest:
    """Манифест передачи (есть у обеих сторон, роль sender / receiver)."""

    def __init__(self, dev, data):
        self.d = data
        self.path = os.path.join(
            dev.manifest_dir, f"{data['transfer_id']}_{data['role']}.json"
        )
        self.unsaved = 0

    @classmethod
    def load(cls, dev, tid, role):
        path = os.path.join(dev.manifest_dir, f"{tid}_{role}.json")
        try:
            with open(path, encoding="utf-8") as f:
                return cls(dev, json.load(f))
        except (OSError, ValueError):
            return None

    @classmethod
    def create(cls, dev, role, tid, sender, receiver, source_path, save_dir,
               chunk_size, files, dirs):
        entries = [
            {
                "path": f["path"],
                "size": f["size"],
                "mtime_ns": f["mtime_ns"],
                "chunks": chunk_list(f["size"], chunk_size),
            }
            for f in files
        ]
        data = {
            "transfer_id": tid,
            "role": role,
            "status": "in_progress",
            "created": now_iso(),
            "updated": now_iso(),
            "sender": sender,
            "receiver": receiver,
            "source_path": source_path,
            "save_dir": save_dir,
            "chunk_size": chunk_size,
            "dirs": list(dirs),
            "total_size": sum(f["size"] for f in files),
            "total_chunks": sum(len(e["chunks"]) for e in entries),
            "chunks_done": 0,
            "files": entries,
        }
        return cls(dev, data)

    def compatible(self, chunk_size, files, sender_id):
        d = self.d
        if d["chunk_size"] != chunk_size or d["sender"]["id"] != sender_id:
            return False
        if len(d["files"]) != len(files):
            return False
        return all(
            a["path"] == b["path"] and a["size"] == b["size"] and a["mtime_ns"] == b["mtime_ns"]
            for a, b in zip(d["files"], files)
        )

    def recount(self):
        self.d["chunks_done"] = sum(
            1 for f in self.d["files"] for c in f["chunks"] if c["done"]
        )

    def mark(self, fi, idx):
        c = self.d["files"][fi]["chunks"][idx]
        if not c["done"]:
            c["done"] = True
            self.d["chunks_done"] += 1
            self.unsaved += 1

    def done_indices(self, fi):
        return [c["idx"] for c in self.d["files"][fi]["chunks"] if c["done"]]

    def apply_have(self, have):
        """Получатель - источник истины: помечаем только то, что он реально принял."""
        for fi, f in enumerate(self.d["files"]):
            got = set(have.get(str(fi), []))
            for c in f["chunks"]:
                c["done"] = c["idx"] in got
        self.recount()

    def reset_file(self, fi):
        for c in self.d["files"][fi]["chunks"]:
            c["done"] = False
        self.recount()

    def file_complete(self, fi):
        return all(c["done"] for c in self.d["files"][fi]["chunks"])

    def all_complete(self):
        return self.d["chunks_done"] >= self.d["total_chunks"]

    def bytes_done(self):
        return sum(c["size"] for f in self.d["files"] for c in f["chunks"] if c["done"])

    def save(self):
        self.d["updated"] = now_iso()
        self.recount()
        atomic_write_json(self.path, self.d)
        self.unsaved = 0


def _all_manifests(dev):
    if not os.path.isdir(dev.manifest_dir):
        return
    for name in sorted(os.listdir(dev.manifest_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(dev.manifest_dir, name)
        try:
            with open(path, encoding="utf-8") as f:
                yield path, json.load(f)
        except (OSError, ValueError):
            continue


def list_unfinished(dev):
    return [d for _, d in _all_manifests(dev) if d.get("status") == "in_progress"]


def supersede_old(dev, role, other_id, source_path, keep_tid):
    """Старые незавершённые передачи того же источника заменяются новой."""
    side = "receiver" if role == "sender" else "sender"
    for path, d in _all_manifests(dev):
        if (
            d.get("role") == role
            and d.get("status") == "in_progress"
            and d.get("transfer_id") != keep_tid
            and d.get(side, {}).get("id") == other_id
            and d.get("source_path") == source_path
        ):
            d["status"] = "superseded"
            atomic_write_json(path, d)


# ============================ ПРОГРЕСС ============================


class Progress:
    def __init__(self, label, total_bytes, base_bytes, total_chunks, cb=None, show=True):
        self.label = label
        self.total = max(total_bytes, 1)
        self.base = base_bytes
        self.moved = 0
        self.total_chunks = total_chunks
        self.cb = cb
        self.show = show
        self.start = time.time()
        self.last = 0.0

    def update(self, nbytes, chunks_done, force=False):
        self.moved += nbytes
        now = time.time()
        if not force and now - self.last < 0.3:
            return
        self.last = now
        done = min(self.total, self.base + self.moved)
        speed = self.moved / max(now - self.start, 0.001)
        if self.cb:
            self.cb(
                {
                    "label": self.label,
                    "bytes_done": done,
                    "bytes_total": self.total,
                    "chunks_done": chunks_done,
                    "chunks_total": self.total_chunks,
                    "speed": speed,
                }
            )
        elif self.show:
            sys.stdout.write(
                f"\r{self.label}: {done * 100 / self.total:5.1f}% | блоков "
                f"{chunks_done}/{self.total_chunks} | {speed / 1048576:6.1f} МБ/с   "
            )
            sys.stdout.flush()

    def finish(self, chunks_done):
        self.update(0, chunks_done, force=True)
        if self.show and not self.cb:
            print()


# ============================ ОТПРАВИТЕЛЬ ============================


def scan_source(path):
    """Возвращает (файлы, абсолютные пути файлов, папки). Папки включают пустые."""
    path = os.path.abspath(path)
    files, abs_paths, dirs = [], [], []
    if os.path.isfile(path):
        st = os.stat(path)
        files.append(
            {"path": os.path.basename(path), "size": st.st_size, "mtime_ns": st.st_mtime_ns}
        )
        abs_paths.append(path)
        return files, abs_paths, dirs
    base = os.path.basename(path.rstrip("\\/")) or "folder"
    dirs.append(base)
    for root, dirnames, names in os.walk(path):
        dirnames.sort()
        for d in dirnames:
            full = os.path.join(root, d)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            dirs.append(f"{base}/{rel}")
        for name in sorted(names):
            full = os.path.join(root, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            rel = os.path.relpath(full, path).replace(os.sep, "/")
            files.append(
                {"path": f"{base}/{rel}", "size": st.st_size, "mtime_ns": st.st_mtime_ns}
            )
            abs_paths.append(full)
    return files, abs_paths, dirs


def _result(**kw):
    base = {
        "ok": False,
        "status": "error",
        "message": "",
        "transfer_id": None,
        "peer": None,
        "chunks_done": 0,
        "total_chunks": 0,
        "wire_bytes": 0,
        "reused_bytes": 0,
        "stop": False,
    }
    base.update(kw)
    return base


def _send_session(dev, peer, source, *, log=print, progress=None, show_progress=True,
                  confirm_timeout=CONFIRM_TIMEOUT):
    """
    Одна передача. peer: {"id" (или None при ручном IP), "name", "ip", "port"}.
    source: путь или функция без аргументов, которая вернёт путь (вызывается после подтверждения).
    """
    log = log or _noop
    res = _result(peer={"id": peer.get("id"), "name": peer.get("name")})
    try:
        sock = socket.create_connection((peer["ip"], peer["port"]), timeout=5)
    except OSError as e:
        res["message"] = f"Не удалось подключиться к {peer['ip']}:{peer['port']}: {e}"
        log(res["message"])
        return res
    sock.settimeout(2.0)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    man = None
    status_msg = None
    try:
        send_msg(
            sock,
            {
                "t": "hello",
                "app": APP,
                "v": PROTO,
                "from_id": dev.id,
                "from_name": dev.name,
                "to_id": peer.get("id"),
            },
        )
        log(f"Ждём подтверждения от «{peer['name']}» (до {int(confirm_timeout)} с)...")
        reply = recv_msg(sock, wait=confirm_timeout)
        if reply.get("t") != "accept":
            res.update(status="rejected", message="Получатель отклонил подключение.")
            log(res["message"])
            return res
        rid = str(reply.get("id", peer.get("id") or ""))
        if not ID_RE.match(rid):
            res["message"] = "Получатель не сообщил корректный ID."
            log(res["message"])
            return res
        if peer.get("id") and rid != peer["id"]:
            res["message"] = "ID получателя не совпал с выбранным устройством."
            log(res["message"])
            return res
        rname = clean(reply.get("name", "")) or peer["name"]
        save_dir = str(reply.get("save_dir", ""))
        dev.remember(rid, rname, peer["ip"])
        res["peer"] = {"id": rid, "name": rname}
        log("Подключение подтверждено.")

        if callable(source):
            source = source()
        if not source or not os.path.exists(source):
            res.update(status="error", message="Путь не найден.")
            log(res["message"])
            safe_send_msg(sock, {"t": "bye"})
            return res
        source = os.path.abspath(source)
        files, abs_paths, dirs = scan_source(source)
        if not files and not dirs:
            res.update(status="error", message="В выбранном месте нет файлов.")
            log(res["message"])
            safe_send_msg(sock, {"t": "bye"})
            return res

        tid = make_transfer_id(dev.id, rid, source, files, dirs)
        res["transfer_id"] = tid
        total_size = sum(f["size"] for f in files)
        log(f"Файлов: {len(files)}, папок: {len(dirs)}, размер: {fmt_size(total_size)}")
        send_msg(
            sock,
            {
                "t": "offer",
                "transfer_id": tid,
                "source_path": source,
                "chunk_size": CHUNK_SIZE,
                "files": files,
                "dirs": dirs,
            },
        )
        ready = recv_msg(sock, wait=60)
        if ready.get("t") == "error":
            res["message"] = f"Получатель отказал: {ready.get('msg')}"
            log(res["message"])
            return res
        if ready.get("t") != "ready":
            res["message"] = "Неожиданный ответ получателя."
            log(res["message"])
            return res

        sender = {"id": dev.id, "name": dev.name}
        receiver = {"id": rid, "name": rname}
        man = Manifest.load(dev, tid, "sender")
        if man is None or not man.compatible(CHUNK_SIZE, files, dev.id):
            man = Manifest.create(
                dev, "sender", tid, sender, receiver, source, save_dir, CHUNK_SIZE, files, dirs
            )
            supersede_old(dev, "sender", rid, source, tid)
        man.d.update(sender=sender, receiver=receiver, save_dir=save_dir, status="in_progress")
        man.apply_have(ready.get("have", {}))
        man.save()
        res["total_chunks"] = man.d["total_chunks"]

        if man.d["chunks_done"]:
            log(
                f"Продолжаем передачу: у получателя уже есть {man.d['chunks_done']}"
                f" из {man.d['total_chunks']} блоков."
            )

        prog = Progress("Отправка", man.d["total_size"], man.bytes_done(),
                        man.d["total_chunks"], progress, show_progress)
        status_msg = "Передача прервана."
        wire = reused = 0
        try:
            for fi, finfo in enumerate(man.d["files"]):
                pending = [c for c in finfo["chunks"] if not c["done"]]
                if not pending:
                    continue
                table, bs = None, 0
                if finfo["size"] >= MIN_DELTA_SIZE:
                    send_msg(sock, {"t": "sigreq", "f": fi})
                    sg = recv_msg(sock, wait=600)
                    if sg.get("t") != "sig" or sg.get("f") != fi:
                        raise ValueError("неверный ответ на запрос сравнения")
                    n_blocks, bs = int(sg.get("n", 0)), int(sg.get("bs", 0))
                    if n_blocks > 20_000_000:
                        raise ValueError("слишком большой список блоков")
                    if n_blocks > 0 and bs >= 512:
                        raw = bytes(recv_exact(sock, n_blocks * SIG_ENTRY, idle=120))
                        table = build_table(raw, n_blocks)
                tried = matched_total = 0
                with open(abs_paths[fi], "rb") as src:
                    for c in pending:
                        src.seek(c["offset"])
                        data = src.read(c["size"])
                        if len(data) != c["size"]:
                            raise OSError(f"файл изменился во время передачи: {finfo['path']}")
                        sent_delta = False
                        if table is not None:
                            ops, lits, matched = compute_delta(data, bs, table)
                            tried += len(data)
                            matched_total += matched
                            if matched > 0:
                                send_msg(
                                    sock,
                                    {
                                        "t": "delta", "f": fi, "i": c["idx"], "n": len(data),
                                        "h": chunk_hash(data), "ops": ops, "lit": len(lits),
                                    },
                                )
                                if lits:
                                    send_all(sock, lits)
                                wire += len(lits)
                                reused += matched
                                sent_delta = True
                            if tried >= DELTA_PROBE and matched_total < tried * 0.1:
                                table = None  # совпадений почти нет, дальше шлём целиком
                        if not sent_delta:
                            send_msg(
                                sock,
                                {"t": "chunk", "f": fi, "i": c["idx"], "n": len(data),
                                 "h": chunk_hash(data)},
                            )
                            send_all(sock, data)
                            wire += len(data)
                        man.mark(fi, c["idx"])
                        if man.unsaved >= SAVE_EVERY:
                            man.save()
                        prog.update(len(data), man.d["chunks_done"])
            prog.finish(man.d["chunks_done"])
            res.update(wire_bytes=wire, reused_bytes=reused)
            send_msg(sock, {"t": "done"})
            final = recv_msg(sock, wait=60)
            if final.get("t") == "complete":
                man.d["status"] = "complete"
                man.save()
                status_msg = None
                res.update(ok=True, status="complete", message="Передача успешно завершена.")
                log("Передача успешно завершена, получатель проверил все блоки.")
                if reused:
                    log(f"По сети отправлено {fmt_size(wire)}, "
                        f"{fmt_size(reused)} уже было у получателя.")
            else:
                status_msg = f"Получатель сообщил об ошибке: {final.get('msg')}"
        except KeyboardInterrupt:
            if show_progress:
                print()
            status_msg = "Остановлено пользователем."
            res["stop"] = True
        except (ConnectionError, OSError, ValueError) as e:
            if show_progress:
                print()
            status_msg = f"Соединение прервано: {e}"
    except KeyboardInterrupt:
        status_msg = "Остановлено пользователем."
        res["stop"] = True
    except (ConnectionError, OSError, ValueError) as e:
        status_msg = f"Ошибка соединения: {e}"
    finally:
        if man is not None:
            try:
                man.save()
                res["chunks_done"] = man.d["chunks_done"]
            except OSError:
                pass
        try:
            sock.close()
        except OSError:
            pass

    if status_msg:
        res.update(status="interrupted" if man is not None else "error")
        if man is not None:
            status_msg += (
                f" Передано блоков: {man.d['chunks_done']}/{man.d['total_chunks']}."
                " Повторите отправку, она продолжится с этого места."
            )
        res["message"] = status_msg
        log(status_msg)
    elif res["ok"]:
        res["chunks_done"] = res["total_chunks"]
    return res


# ============================ ПОЛУЧАТЕЛЬ ============================


def open_server(port=TCP_PORT):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError:
        srv.bind(("0.0.0.0", 0))
    srv.listen(1)
    srv.settimeout(1.0)
    return srv


def reconcile_receiver(man, save_dir):
    """Сверяет манифест с файлами на диске: что не подтверждается, считаем не принятым."""
    for fi, f in enumerate(man.d["files"]):
        final = safe_join(save_dir, f["path"])
        part = final + ".part"
        done = sum(1 for c in f["chunks"] if c["done"])
        if done == 0:
            continue
        if man.file_complete(fi):
            ok = (os.path.exists(final) and os.path.getsize(final) == f["size"]) or os.path.exists(part)
        else:
            ok = os.path.exists(part)
        if not ok:
            man.reset_file(fi)


def finalize_files(man, save_dir):
    for f in man.d["files"]:
        final = safe_join(save_dir, f["path"])
        part = final + ".part"
        os.makedirs(os.path.dirname(final), exist_ok=True)
        if os.path.exists(part):
            if os.path.getsize(part) != f["size"]:
                raise ValueError(f"размер файла не совпал: {f['path']}")
            os.replace(part, final)
        elif f["size"] == 0:
            open(final, "wb").close()
        elif not os.path.exists(final):
            raise ValueError(f"файл отсутствует: {f['path']}")
        try:
            os.remove(final + ".basis")
        except OSError:
            pass


def _matches(only_from, pid, name):
    if not only_from:
        return True
    items = [only_from] if isinstance(only_from, str) else list(only_from)
    return any(x.casefold() in (pid.casefold(), name.casefold()) for x in items)


def _receive_session(dev, conn, addr, accept_cb, *, only_from=None, log=print,
                     progress=None, show_progress=True):
    """Одно входящее подключение. accept_cb(info) -> папка сохранения или None (отклонить)."""
    log = log or _noop
    res = _result(status="ignored")
    conn.settimeout(2.0)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    man = None
    handle = None
    basis_handles = {}
    status_msg = None
    try:
        hello = recv_msg(conn, wait=10)
        sid = str(hello.get("from_id", ""))
        if hello.get("t") != "hello" or hello.get("app") != APP or not ID_RE.match(sid):
            return res
        if hello.get("to_id") not in (None, dev.id):
            safe_send_msg(conn, {"t": "reject", "msg": "подключение адресовано другому устройству"})
            return res
        sname = clean(hello.get("from_name", "")) or "без имени"
        res["peer"] = {"id": sid, "name": sname}
        info = {"id": sid, "name": sname, "ip": addr[0], "known": dev.is_known(sid)}
        dev.remember(sid, sname, addr[0])

        save_dir = None
        if _matches(only_from, sid, sname):
            save_dir = accept_cb(info)
        if not save_dir:
            safe_send_msg(conn, {"t": "reject"})
            res.update(status="rejected", message=f"Подключение от «{sname}» отклонено.")
            log(res["message"])
            return res
        save_dir = os.path.abspath(save_dir)
        os.makedirs(save_dir, exist_ok=True)
        send_msg(conn, {"t": "accept", "id": dev.id, "name": dev.name, "save_dir": save_dir})
        log(f"Подтверждено. Ждём, пока «{sname}» выберет файлы...")

        offer = recv_msg(conn, wait=OFFER_TIMEOUT)
        res["status"] = "error"
        if offer.get("t") == "bye":
            res.update(status="rejected", message="Отправитель завершил сеанс.")
            log(res["message"])
            return res
        tid = str(offer.get("transfer_id", ""))
        chunk_size = offer.get("chunk_size")
        files = offer.get("files")
        dirs = offer.get("dirs", [])
        if (
            offer.get("t") != "offer"
            or not TID_RE.match(tid)
            or not isinstance(chunk_size, int)
            or not (64 * 1024 <= chunk_size <= 64 * 1024 * 1024)
            or not isinstance(files, list)
            or not isinstance(dirs, list)
            or not (files or dirs)
        ):
            safe_send_msg(conn, {"t": "error", "msg": "некорректное предложение"})
            res["message"] = "Некорректное предложение от отправителя."
            return res
        for f in files:
            if not (
                isinstance(f, dict)
                and isinstance(f.get("path"), str)
                and isinstance(f.get("size"), int)
                and f["size"] >= 0
                and isinstance(f.get("mtime_ns"), int)
            ):
                safe_send_msg(conn, {"t": "error", "msg": "некорректный список файлов"})
                res["message"] = "Некорректный список файлов."
                return res
            safe_join(save_dir, f["path"])
        for d in dirs:
            if not isinstance(d, str):
                raise ValueError("некорректный список папок")
            safe_join(save_dir, d)

        sender = {"id": sid, "name": sname}
        receiver = {"id": dev.id, "name": dev.name}
        res["transfer_id"] = tid
        man = Manifest.load(dev, tid, "receiver")
        if man is not None and man.compatible(chunk_size, files, sid):
            save_dir = man.d["save_dir"]
            os.makedirs(save_dir, exist_ok=True)
            for f in files:
                safe_join(save_dir, f["path"])
        else:
            man = Manifest.create(
                dev, "receiver", tid, sender, receiver,
                str(offer.get("source_path", "")), save_dir, chunk_size, files, dirs,
            )
            supersede_old(dev, "receiver", sid, str(offer.get("source_path", "")), tid)
            # недокачанная старая версия становится базой для сравнения
            for f in files:
                part = safe_join(save_dir, f["path"]) + ".part"
                if os.path.exists(part):
                    os.replace(part, part[: -len(".part")] + ".basis")
        man.d.update(sender=sender, receiver=receiver, save_dir=save_dir, status="in_progress")
        reconcile_receiver(man, save_dir)
        man.recount()
        man.save()
        res["total_chunks"] = man.d["total_chunks"]
        res["save_dir"] = save_dir
        for d in dirs:
            os.makedirs(safe_join(save_dir, d), exist_ok=True)

        total_size = man.d["total_size"]
        log(f"Файлов: {len(files)}, папок: {len(dirs)}, размер: {fmt_size(total_size)}, "
            f"папка: {save_dir}")
        if man.d["chunks_done"]:
            log(f"Продолжаем: уже есть {man.d['chunks_done']} из {man.d['total_chunks']} блоков.")
        send_msg(
            conn,
            {"t": "ready", "have": {str(i): man.done_indices(i) for i in range(len(files))}},
        )

        def get_basis(fi):
            if fi not in basis_handles:
                final = safe_join(save_dir, files[fi]["path"])
                h = None
                for p in (final, final + ".basis"):
                    if os.path.isfile(p):
                        h = open(p, "rb")
                        break
                basis_handles[fi] = h
            return basis_handles[fi]

        prog = Progress("Приём", total_size, man.bytes_done(), man.d["total_chunks"],
                        progress, show_progress)
        cur = -1
        wire = reused = 0
        status_msg = "Приём прерван."
        try:
            while True:
                msg = recv_msg(conn)
                t = msg.get("t")
                if t in ("chunk", "delta"):
                    fi, idx, n = msg.get("f"), msg.get("i"), msg.get("n")
                    if not (isinstance(fi, int) and 0 <= fi < len(files)):
                        raise ValueError("неверный индекс файла")
                    chunks = man.d["files"][fi]["chunks"]
                    if not (isinstance(idx, int) and 0 <= idx < len(chunks)):
                        raise ValueError("неверный индекс блока")
                    c = chunks[idx]
                    if n != c["size"]:
                        raise ValueError("неверный размер блока")
                    if t == "chunk":
                        data = bytes(recv_exact(conn, n))
                        wire += n
                    else:
                        ops, lit = msg.get("ops"), msg.get("lit")
                        if not isinstance(ops, list) or not isinstance(lit, int) or not (0 <= lit <= n):
                            raise ValueError("некорректная команда изменений")
                        payload = bytes(recv_exact(conn, lit)) if lit else b""
                        data = rebuild_chunk(ops, payload, get_basis(fi), n)
                        wire += lit
                        reused += n - lit
                    if chunk_hash(data) != msg.get("h"):
                        safe_send_msg(conn, {"t": "error", "msg": "ошибка целостности блока"})
                        raise ValueError(f"ошибка целостности: файл {fi}, блок {idx}")
                    if fi != cur:
                        if handle:
                            handle.flush()
                            handle.close()
                        part = safe_join(save_dir, files[fi]["path"]) + ".part"
                        os.makedirs(os.path.dirname(part), exist_ok=True)
                        handle = open(part, "r+b" if os.path.exists(part) else "wb")
                        cur = fi
                    handle.seek(c["offset"])
                    handle.write(data)
                    man.mark(fi, idx)
                    if man.unsaved >= SAVE_EVERY:
                        handle.flush()
                        os.fsync(handle.fileno())
                        man.save()
                    prog.update(n, man.d["chunks_done"])
                elif t == "sigreq":
                    fi = msg.get("f")
                    if not (isinstance(fi, int) and 0 <= fi < len(files)):
                        raise ValueError("неверный индекс файла")
                    bh = get_basis(fi)
                    if bh is None:
                        send_msg(conn, {"t": "sig", "f": fi, "bs": 0, "n": 0})
                    else:
                        bs = choose_block_size(os.fstat(bh.fileno()).st_size)
                        bh.seek(0)
                        n_blocks, sig = make_signature(bh, bs)
                        send_msg(conn, {"t": "sig", "f": fi, "bs": bs, "n": n_blocks})
                        if n_blocks:
                            send_all(conn, sig)
                elif t == "done":
                    break
                elif t == "bye":
                    raise ConnectionError("отправитель завершил сеанс")
                else:
                    raise ValueError("неожиданное сообщение")
            prog.finish(man.d["chunks_done"])
            if handle:
                handle.flush()
                os.fsync(handle.fileno())
                handle.close()
                handle = None
            for h in basis_handles.values():
                if h:
                    h.close()
            basis_handles.clear()
            res.update(wire_bytes=wire, reused_bytes=reused)
            if not man.all_complete():
                safe_send_msg(conn, {"t": "error", "msg": "получены не все блоки"})
                status_msg = "Получены не все блоки."
            else:
                finalize_files(man, save_dir)
                man.d["status"] = "complete"
                man.save()
                send_msg(conn, {"t": "complete"})
                status_msg = None
                res.update(ok=True, status="complete", message=f"Принято. Папка: {save_dir}")
                log(f"[✓] Все данные приняты и проверены. Сохранено в: {save_dir}")
                if reused:
                    log(f"По сети получено {fmt_size(wire)}, "
                        f"{fmt_size(reused)} взято из имеющейся версии файла.")
        except KeyboardInterrupt:
            if show_progress:
                print()
            status_msg = "Остановлено пользователем."
            res["stop"] = True
        except (ConnectionError, OSError, ValueError) as e:
            if show_progress:
                print()
            status_msg = f"Приём прерван: {e}"
    except KeyboardInterrupt:
        status_msg = "Остановлено пользователем."
        res["stop"] = True
    except (ConnectionError, OSError, ValueError) as e:
        status_msg = f"Ошибка соединения: {e}"
        res["status"] = "error" if res["status"] == "ignored" else res["status"]
    finally:
        if handle:
            try:
                handle.flush()
                handle.close()
            except OSError:
                pass
        for h in basis_handles.values():
            if h:
                h.close()
        if man is not None:
            try:
                man.save()
                res["chunks_done"] = man.d["chunks_done"]
            except OSError:
                pass
        try:
            conn.close()
        except OSError:
            pass

    if status_msg:
        res["status"] = "interrupted" if man is not None else "error"
        if man is not None:
            status_msg += (f" Принято блоков: {man.d['chunks_done']}/{man.d['total_chunks']}."
                           " Отправитель может продолжить позже.")
        res["message"] = status_msg
        log(status_msg)
    elif res["ok"]:
        res["chunks_done"] = res["total_chunks"]
    return res


# ============================ ПУБЛИЧНЫЙ API (для импорта) ============================


def discover(timeout=3.0, device=None, discovery=None):
    """Возвращает список найденных устройств (dict с ключами id, name, label, ip, port, receiving)."""
    dev = device or get_device()
    own = discovery is None
    disc = discovery or Discovery(dev)
    if own:
        disc.on_error = None
        disc.start()
    try:
        time.sleep(timeout if own else 0)
        labels, peers = disc.labels()
        for p in peers:
            p["label"] = labels[p["id"]]
        return peers
    finally:
        if own:
            disc.close()


def send(source, to=None, ip=None, *, device=None, discovery=None, discover_timeout=5.0,
         confirm_timeout=CONFIRM_TIMEOUT, log=print, on_progress=None, show_progress=True):
    """
    Отправить файл или папку. Укажите to (имя, метка или ID устройства) или ip ("1.2.3.4[:порт]").
    Возвращает dict: ok, status (complete / rejected / interrupted / error), message,
    transfer_id, peer, chunks_done, total_chunks, wire_bytes, reused_bytes.
    """
    dev = device or get_device()
    if ip:
        host, port = parse_hostport(ip)
        peer = {"id": None, "name": host, "ip": host, "port": port}
    elif to:
        own = discovery is None
        disc = discovery or Discovery(dev)
        if own:
            disc.on_error = None
            disc.start()
        try:
            peer = resolve_peer(disc, to, wait=discover_timeout)
        except (LookupError, ValueError) as e:
            return _result(status="error", message=str(e))
        finally:
            if own:
                disc.close()
        if not peer["receiving"]:
            return _result(status="error", message="Устройство не в режиме приёма.")
    else:
        raise ValueError("укажите to= или ip=")
    return _send_session(dev, peer, source, log=log, progress=on_progress,
                         show_progress=show_progress, confirm_timeout=confirm_timeout)


def receive(save_dir=None, *, device=None, discovery=None, announce=True, auto_accept=False,
            accept_cb=None, only_from=None, once=False, timeout=None, stop_event=None,
            server=None, log=print, on_progress=None, show_progress=True):
    """
    Режим приёма. auto_accept=True принимает все подключения (или только от only_from)
    в папку save_dir. accept_cb(info) -> папка или None даёт полный контроль.
    once=True: обработать одно подключение и выйти. Возвращает список результатов.
    """
    dev = device or get_device()
    log = log or _noop
    default_dir = os.path.abspath(save_dir) if save_dir else os.path.join(dev.base_dir, "received")
    if accept_cb is None:
        if auto_accept:
            accept_cb = lambda info: default_dir
        else:
            def accept_cb(info):
                known = "известное устройство" if info["known"] else "новое устройство"
                print(f"\n[?] Запрос на передачу от «{info['name']}» [{info['id']}] "
                      f"{info['ip']} ({known}).")
                if ask("Принять подключение? [y/N]: ").strip().lower() not in ("y", "yes", "д", "да"):
                    return None
                chosen = clean_path(ask(f"Папка для сохранения [{default_dir}]: "))
                return chosen or default_dir

    own_srv = server is None
    srv = server or open_server()
    port = srv.getsockname()[1]
    own_disc = False
    disc = discovery
    if announce and disc is None:
        disc = Discovery(dev)
        disc.on_error = None
        disc.start()
        own_disc = True
    if disc:
        disc.set_receiving(True, port)
    log(f"Режим приёма включён (порт {port}). Вас видят как «{dev.name}».")
    results = []
    deadline = time.time() + timeout if timeout else None
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break
            if deadline and time.time() > deadline:
                break
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            res = _receive_session(dev, conn, addr, accept_cb, only_from=only_from, log=log,
                                   progress=on_progress, show_progress=show_progress)
            if res["status"] != "ignored":
                results.append(res)
                if once or res["stop"]:
                    break
            if log is not _noop:
                log("Ожидание подключений...")
    except KeyboardInterrupt:
        pass
    finally:
        if disc:
            disc.set_receiving(False)
        if own_disc:
            disc.close()
        if own_srv:
            srv.close()
    return results


def get_name(device=None):
    return (device or get_device()).name


def set_name(name, device=None):
    (device or get_device()).set_name(name)


def get_id(device=None):
    return (device or get_device()).id


def unfinished(device=None):
    return list_unfinished(device or get_device())


# ============================ ИНТЕРАКТИВНОЕ МЕНЮ ============================


def choose_peer(dev, disc):
    while True:
        labels, peers = disc.labels()
        print("\nУстройства в сети:")
        if not peers:
            print("  (пока никого не видно)")
        for n, p in enumerate(peers, 1):
            status = "ждёт файлы" if p["receiving"] else "не в режиме приёма"
            mark = "" if dev.is_known(p["id"]) else " (новое)"
            print(f"  {n}. {labels[p['id']]}  [{p['id']}]  {p['ip']}  - {status}{mark}")
        s = ask("Номер устройства, r - обновить, m - ввести IP, q - назад: ").strip().lower()
        if s == "q":
            return None
        if s in ("r", ""):
            time.sleep(1.0)
            continue
        if s == "m":
            try:
                host, port = parse_hostport(ask("IP-адрес получателя (можно IP:порт): "))
                if not host:
                    continue
            except ValueError:
                print("Неверный адрес.")
                continue
            return {"id": None, "name": host, "ip": host, "port": port}
        if s.isdigit() and 1 <= int(s) <= len(peers):
            p = peers[int(s) - 1]
            if not p["receiving"]:
                print("Это устройство сейчас не принимает файлы. Пусть выберет «Принять».")
                continue
            return p
        print("Неверный выбор.")


def send_flow(dev, disc, peer=None, source=None):
    if peer is None:
        peer = choose_peer(dev, disc)
        if peer is None:
            return
    if source is None:
        source = lambda: clean_path(ask("Что отправить (путь к файлу или папке): "))
    res = _send_session(dev, peer, source)
    if res["status"] == "interrupted":
        print("Чтобы продолжить: меню «Незавершённые передачи» (пункт 3).")


def receive_flow(dev, disc):
    print("Ctrl+C - выйти в меню.")
    receive(device=dev, discovery=disc, announce=True)


def show_devices(dev, disc):
    labels, peers = disc.labels()
    print(f"\nЭто устройство: {labels[dev.id]}  [{dev.id}]")
    if not peers:
        print("Других устройств не видно.")
    for p in peers:
        status = "ждёт файлы" if p["receiving"] else "не в режиме приёма"
        print(f"  - {labels[p['id']]}  [{p['id']}]  {p['ip']}  - {status}")
    online = {p["id"] for p in peers}
    known = [k for k in dev.data["known_peers"] if k not in online]
    if known:
        print("Известные, но сейчас не в сети:")
        for k in known:
            info = dev.data["known_peers"][k]
            print(f"  - {info.get('name')}  [{k}]  последний IP {info.get('last_ip')}")


def rename_flow(dev, disc):
    print(f"\nТекущее имя: {dev.name}  (ID {dev.id} не меняется)")
    new = clean(ask("Новое имя (Enter - оставить): "))
    if not new:
        return
    _, peers = disc.labels()
    if any(p["name"].casefold() == new.casefold() for p in peers):
        print("В сети уже есть устройство с таким именем. Вас будут различать по ID: "
              f"«{new} #{dev.id[-4:]}».")
    dev.set_name(new)
    print(f"Имя изменено на «{new}».")


def unfinished_flow(dev, disc):
    items = list_unfinished(dev)
    if not items:
        print("\nНезавершённых передач нет.")
        return
    print("\nНезавершённые передачи:")
    for n, d in enumerate(items, 1):
        role = "отправка" if d["role"] == "sender" else "приём"
        other = d["receiver"] if d["role"] == "sender" else d["sender"]
        where = d["source_path"] if d["role"] == "sender" else d["save_dir"]
        print(f"  {n}. {role} ↔ «{other['name']}»  {d['chunks_done']}/{d['total_chunks']} блоков  ({where})")
    s = ask("Номер, чтобы продолжить (Enter - назад): ").strip()
    if not (s.isdigit() and 1 <= int(s) <= len(items)):
        return
    d = items[int(s) - 1]
    if d["role"] == "receiver":
        print("Выберите «Принять» в меню и дождитесь, пока отправитель продолжит передачу.")
        return
    peer = disc.find(d["receiver"]["id"])
    if peer is None:
        ans = ask(f"«{d['receiver']['name']}» не видно в сети. Введите IP или Enter для отмены: ").strip()
        if not ans:
            return
        host, port = parse_hostport(ans)
        peer = {"id": d["receiver"]["id"], "name": d["receiver"]["name"], "ip": host, "port": port}
    if not os.path.exists(d["source_path"]):
        print(f"Источник не найден: {d['source_path']}")
        return
    send_flow(dev, disc, peer=peer, source=d["source_path"])


def interactive_menu(dev):
    disc = Discovery(dev).start()
    print("=== LAN Transfer ===")
    print(f"Имя: {dev.name}\nID:  {dev.id}\nIP:  {get_local_ip()}")
    try:
        while True:
            print("\n1. Отправить\n2. Принять\n3. Незавершённые передачи\n"
                  "4. Устройства в сети\n5. Сменить имя\n0. Выход")
            c = ask("Выберите: ").strip()
            try:
                if c == "1":
                    send_flow(dev, disc)
                elif c == "2":
                    receive_flow(dev, disc)
                elif c == "3":
                    unfinished_flow(dev, disc)
                elif c == "4":
                    show_devices(dev, disc)
                elif c == "5":
                    rename_flow(dev, disc)
                elif c == "0":
                    break
            except KeyboardInterrupt:
                print()
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        disc.close()


# ============================ КОМАНДНАЯ СТРОКА ============================


def build_parser():
    p = argparse.ArgumentParser(
        prog="lan_transfer",
        description="Передача файлов и папок по локальной сети. Без команды запускается меню.",
    )
    p.add_argument("--home", help="папка для device.json и манифестов")
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("devices", help="показать устройства в сети")
    d.add_argument("--wait", type=float, default=3.0, help="сколько секунд искать (по умолчанию 3)")
    d.add_argument("--json", action="store_true", help="вывод в JSON")

    s = sub.add_parser("send", help="отправить файл или папку")
    s.add_argument("source", help="путь к файлу или папке")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--to", help="имя, метка («Имя #abcd») или ID устройства")
    g.add_argument("--ip", help="IP получателя, можно с портом: 192.168.1.5:9000")
    s.add_argument("--wait", type=float, default=5.0, help="сколько секунд искать устройство")
    s.add_argument("--timeout", type=float, default=CONFIRM_TIMEOUT,
                   help="сколько секунд ждать подтверждения получателя")

    r = sub.add_parser("receive", help="принимать файлы")
    r.add_argument("--dir", help="папка сохранения")
    r.add_argument("--yes", action="store_true", help="принимать без вопросов")
    r.add_argument("--from", dest="only_from", help="принимать только от этого имени или ID")
    r.add_argument("--once", action="store_true", help="принять одну передачу и выйти")
    r.add_argument("--timeout", type=float, help="выйти, если никто не подключился за N секунд")

    n = sub.add_parser("name", help="показать или сменить имя устройства")
    n.add_argument("new_name", nargs="?")
    sub.add_parser("id", help="показать ID устройства")
    sub.add_parser("unfinished", help="показать незавершённые передачи")
    return p


def cli(argv=None):
    args = build_parser().parse_args(argv)
    dev = Device(args.home) if args.home else get_device()

    if args.cmd is None:
        interactive_menu(dev)
        return 0
    if args.cmd == "id":
        print(dev.id)
        return 0
    if args.cmd == "name":
        if args.new_name:
            dev.set_name(args.new_name)
        print(dev.name)
        return 0
    if args.cmd == "unfinished":
        items = list_unfinished(dev)
        for d in items:
            other = d["receiver"] if d["role"] == "sender" else d["sender"]
            print(f"{d['transfer_id']}  {d['role']:8}  {other['name']}  "
                  f"{d['chunks_done']}/{d['total_chunks']}")
        if not items:
            print("Незавершённых передач нет.")
        return 0
    if args.cmd == "devices":
        peers = discover(args.wait, device=dev)
        if args.json:
            print(json.dumps(peers, ensure_ascii=False, indent=2))
        else:
            if not peers:
                print("Устройств не найдено.")
            for p in peers:
                st = "ждёт файлы" if p["receiving"] else "не принимает"
                print(f"{p['label']}  [{p['id']}]  {p['ip']}:{p['port']}  {st}")
        return 0
    try:
        if args.cmd == "send":
            if not (args.to or args.ip):
                print("Укажите --to ИМЯ или --ip АДРЕС.", file=sys.stderr)
                return 2
            res = send(args.source, to=args.to, ip=args.ip, device=dev,
                       discover_timeout=args.wait, confirm_timeout=args.timeout)
            if res["status"] == "error" and not res["transfer_id"]:
                print(res["message"], file=sys.stderr)
            return 0 if res["ok"] else 1
        if args.cmd == "receive":
            results = receive(args.dir, device=dev, auto_accept=args.yes,
                              only_from=args.only_from, once=args.once, timeout=args.timeout)
            return 0 if all(r["ok"] for r in results) else 1
    except KeyboardInterrupt:
        print()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(cli())
