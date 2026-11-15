#!/usr/bin/env python3
"""SpaceGuard torrent watch — слой 2 защиты от торрентов (только наблюдение, без банов).

Два источника срабатываний:
  xray — в access-логе Xray строка `[... -> TORRENT]` (Xray распознал рукопожатие BitTorrent);
  ufw  — ядро отбросило исходящий пакет с подписью BitTorrent/DHT (слой 3, правила NFLOG
         group NFLOG_GROUP с префиксом `sg-tg:<подпись>` в /etc/ufw/before.rules; старые правила
         LOG в /dev/kmsg тоже понимаем). Пользователя ищем по адресу назначения:
         Xray пишет `accepted udp:<DST>:<PORT> ... email: <id>` при открытии сессии, а первый пакет
         DHT-сессии и есть отброшенный запрос. Совпадение ищется в окне INDEX_TTL секунд.

NFLOG отдаёт начало пакета, из него берём тип и цель (журнал ядра при этом не растёт):
  kind=dht     get_peers / announce_peer / find_node — поиск раздающих; info_hash из запроса;
  kind=tracker HTTP-анонс на трекер (info_hash=, peer_id=) — домен из Host и info_hash;
  kind=peer    рукопожатие BitTorrent (скачивание) — info_hash из рукопожатия.
info_hash идентифицирует торрент (magnet:?xt=urn:btih:<hash>).

Access-лог: core пишет его в /var/lib/<node>/xray-access.log (каталог смонтирован в контейнер
PasarGuard node). Метрики (textfile node exporter):

  spaceguard_torrent_events_total{node,user,inbound,ip,via}        счётчик срабатываний
  spaceguard_torrent_last_event_seconds{node,user,inbound,ip,via}  unix-время последнего
  spaceguard_torrent_unattributed_total{node,sig}                  ufw-дропы без найденного пользователя
  spaceguard_torrent_watch_up{node}                                1 — лог найден и читается
  spaceguard_torrent_detail_total{node,user,kind,tracker,info_hash}        что именно (user="-" —
  spaceguard_torrent_detail_last_seconds{node,user,kind,tracker,info_hash}  не определён); ≤ DETAILS_MAX рядов

Куда идут алерты (можно оба способа сразу):
  - Prometheus: метрики выше читает внешний алертер (у SpaceGuard — бот, app/watchers/torrent_alert.py);
  - Telegram напрямую с ноды: заданы TORRENT_WATCH_TG_TOKEN и TORRENT_WATCH_TG_CHAT — агент сам шлёт
    сообщение «пользователь X качает торрент», не чаще раза в TORRENT_WATCH_TG_COOLDOWN секунд на
    пользователя. С нод, где Telegram заблокирован, укажите прокси-зеркало в TORRENT_WATCH_TG_API.

Имя ноды в метриках и алертах: TORRENT_WATCH_NODE, иначе имя каталога /var/lib/<node>.
Лог агент сам обнуляет, дочитав до конца, когда он больше MAX_BYTES (Xray пишет с O_APPEND).
Модуль: modules/torrent-guard (README.md — установка на любую ноду PasarGuard).
У SpaceGuard ставится шагом `torrent_guard` (scripts/ops/spaceguard-node.sh), unit spaceguard-torrent-watch.
Только stdlib, Python 3.8+.
"""
from __future__ import annotations

import glob
import os
import re
import socket
import struct
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from urllib.parse import unquote_to_bytes

LOG_GLOB = os.environ.get("TORRENT_WATCH_GLOB", "/var/lib/*/xray-access.log")
OUT = os.environ.get("TORRENT_WATCH_OUT", "/var/lib/prometheus/node-exporter/spaceguard_torrent.prom")
KMSG = os.environ.get("TORRENT_WATCH_KMSG", "/dev/kmsg")
MAX_BYTES = int(os.environ.get("TORRENT_WATCH_MAX_BYTES", str(32 * 1024 * 1024)))
FLUSH_EVERY = 15
SERIES_TTL = 86400
INDEX_TTL = 600          # сколько помнить открытые Xray-сессии для сопоставления с ufw-дропами
INDEX_MAX = 300_000
PENDING_TTL = 30         # дроп может прийти раньше, чем мы дочитали строку access-лога
TAG = os.environ.get("TORRENT_WATCH_TAG", "TORRENT")
KMSG_PREFIX = "sg-tg:"
NFLOG_GROUP = int(os.environ.get("TORRENT_WATCH_NFLOG_GROUP", "7"))  # = --nflog-group в spaceguard-node.sh
NODE_NAME = os.environ.get("TORRENT_WATCH_NODE", "").strip()
# Алерты в Telegram прямо с ноды (необязательно; пустой токен — выключено)
TG_TOKEN = os.environ.get("TORRENT_WATCH_TG_TOKEN", "").strip()
TG_CHAT = os.environ.get("TORRENT_WATCH_TG_CHAT", "").strip()
TG_API = os.environ.get("TORRENT_WATCH_TG_API", "https://api.telegram.org").rstrip("/")
TG_COOLDOWN = int(os.environ.get("TORRENT_WATCH_TG_COOLDOWN", "3600"))
DETAILS_TTL = 6 * 3600
DETAILS_MAX = 300
SIG_KIND = {"bt": "peer", "announce": "dht", "getpeers": "dht", "findnode": "dht",
            "infohash": "tracker", "peerid": "tracker"}
_HOST_RE = re.compile(rb"\r\nHost:\s*([A-Za-z0-9.\-]{1,100})", re.I)
_HASH_Q_RE = re.compile(rb"[?&]info_hash=([^&\s]+)")

_ADDR = r"(\[[0-9a-fA-F:.]+\]|[0-9.]+|[^\s:]+)"
ACCEPT_RE = re.compile(
    r"from (?:tcp:|udp:)?" + _ADDR + r":\d+ accepted (tcp|udp):(\S+):(\d+) "
    r"\[(\S+) (?:->|>>) (\S+)\](?: email: (\S+))?"
)
KMSG_RE = re.compile(r"sg-tg:(\S+) .*?DST=(\S+) .*?PROTO=(TCP|UDP)(?: .*?DPT=(\d+))?")


def parse_accept(line: str):
    """(client_ip, proto, dst, port, inbound, outbound, user) для строки `accepted`, иначе None."""
    m = ACCEPT_RE.search(line)
    if not m:
        return None
    client, proto, dst, port, inbound, outbound, user = m.groups()
    return client.strip("[]"), proto, dst.strip("[]"), port, inbound, outbound, user or "-"


def parse_line(line: str):
    """(ip, inbound, user) для строки с outbound TAG, иначе None (совместимость с тестами)."""
    a = parse_accept(line)
    if not a or a[5] != TAG:
        return None
    return a[0], a[4], a[6]


def parse_kmsg(record: str):
    """(sig, proto, dst, port) из записи ядра с префиксом sg-tg:, иначе None."""
    if KMSG_PREFIX not in record:
        return None
    m = KMSG_RE.search(record)
    if not m:
        return None
    sig, dst, proto, port = m.groups()
    return sig, proto.lower(), dst, port or ""


def parse_ip(data: bytes):
    """(proto, dst, port, l4_payload) из IPv4/IPv6-пакета (TCP/UDP), иначе None."""
    try:
        ver = data[0] >> 4
        if ver == 4:
            ihl = (data[0] & 15) * 4
            proto, dst, l4 = data[9], socket.inet_ntop(socket.AF_INET, data[16:20]), data[ihl:]
        elif ver == 6:  # extension headers не разбираем — для UDP/TCP их обычно нет
            proto, dst, l4 = data[6], socket.inet_ntop(socket.AF_INET6, data[24:40]), data[40:]
        else:
            return None
        if proto == 6:
            return "tcp", dst, str(struct.unpack("!H", l4[2:4])[0]), l4[(l4[12] >> 4) * 4:]
        if proto == 17:
            return "udp", dst, str(struct.unpack("!H", l4[2:4])[0]), l4[8:]
    except (IndexError, struct.error, ValueError, OSError):
        return None
    return None


def classify(sig: str, body: bytes) -> tuple[str, str, str]:
    """(kind, tracker, info_hash) по подписи и началу полезной нагрузки."""
    kind, tracker, ih = SIG_KIND.get(sig, "other"), "", b""
    if kind == "peer":
        i = body.find(b"\x13BitTorrent protocol")
        if i >= 0:
            ih = body[i + 28:i + 48]
    elif kind == "dht":
        i = body.find(b"9:info_hash20:")
        if i >= 0:
            ih = body[i + 14:i + 34]
    elif kind == "tracker":
        m = _HOST_RE.search(body)
        tracker = m.group(1).decode("ascii").lower() if m else ""
        m = _HASH_Q_RE.search(body)
        if m:
            ih = unquote_to_bytes(m.group(1))
    return kind, tracker, ih.hex() if len(ih) == 20 else ""


def _nla(data: bytes):
    """Атрибуты netlink: {type: bytes}."""
    out, off = {}, 0
    while off + 4 <= len(data):
        ln, typ = struct.unpack_from("=HH", data, off)
        if ln < 4:
            break
        out[typ & 0x3FFF] = data[off + 4:off + ln]
        off += (ln + 3) & ~3
    return out


def parse_nflog(msg: bytes):
    """(sig, proto, dst, port, kind, tracker, info_hash) из NFULNL_MSG_PACKET, иначе None."""
    attrs = _nla(msg[4:])  # после nfgenmsg
    prefix = attrs.get(10, b"").split(b"\0")[0].decode("ascii", "replace")  # NFULA_PREFIX
    if not prefix.startswith(KMSG_PREFIX):
        return None
    sig = prefix[len(KMSG_PREFIX):].strip()
    ip = parse_ip(attrs.get(9, b""))  # NFULA_PAYLOAD
    if not ip:
        return None
    proto, dst, port, body = ip
    return (sig, proto, dst, port) + classify(sig, body)


class Nflog:
    """Подписка на NFLOG group через netlink (NETLINK_NETFILTER, подсистема ULOG)."""

    def __init__(self, group: int = NFLOG_GROUP):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
        self.sock.bind((0, 0))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self._config(group, struct.pack("=HHB3x", 5, 1, 1))                  # CMD BIND
        self._config(group, struct.pack("=HH", 10, 2) + struct.pack("!IBB2x", 1024, 2, 0))  # MODE COPY_PACKET
        self.sock.setblocking(False)

    def _config(self, group: int, attr: bytes) -> None:
        body = struct.pack("!BBH", socket.AF_UNSPEC, 0, group) + attr
        hdr = struct.pack("=IHHII", 16 + len(body), (4 << 8) | 1, 1, 0, 0)  # ULOG CONFIG, NLM_F_REQUEST
        self.sock.send(hdr + body)

    def packets(self, limit: int = 2000) -> list:
        out = []
        for _ in range(limit):
            try:
                data = self.sock.recv(65536)
            except BlockingIOError:
                break
            except OSError:  # ENOBUFS — переполнение буфера, часть записей потеряна
                continue
            off = 0
            while off + 16 <= len(data):
                ln, typ = struct.unpack_from("=IH", data, off)
                if ln < 16:
                    break
                if typ == (4 << 8):  # ULOG PACKET
                    p = parse_nflog(data[off + 16:off + ln])
                    if p:
                        out.append(p)
                off += (ln + 3) & ~3
        return out


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render(node: str, series: dict, up: bool, unattributed: dict | None = None,
           details: dict | None = None) -> str:
    n = _esc(node)
    out = ["# HELP spaceguard_torrent_events_total Torrent hits attributed to a user (via=xray|ufw).",
           "# TYPE spaceguard_torrent_events_total counter"]
    last = ["# HELP spaceguard_torrent_last_event_seconds Unix time of the last torrent hit.",
            "# TYPE spaceguard_torrent_last_event_seconds gauge"]
    for key, (count, ts) in sorted(series.items()):
        user, inbound, ip = key[:3]
        via = key[3] if len(key) > 3 else "xray"
        labels = (f'node="{n}",user="{_esc(user)}",inbound="{_esc(inbound)}",'
                  f'ip="{_esc(ip)}",via="{_esc(via)}"')
        out.append(f"spaceguard_torrent_events_total{{{labels}}} {count}")
        last.append(f"spaceguard_torrent_last_event_seconds{{{labels}}} {int(ts)}")
    out += last
    out += ["# TYPE spaceguard_torrent_unattributed_total counter"]
    for sig, count in sorted((unattributed or {}).items()):
        out.append(f'spaceguard_torrent_unattributed_total{{node="{n}",sig="{_esc(sig)}"}} {count}')
    out += ["# HELP spaceguard_torrent_detail_total Torrent hits by kind (dht|tracker|peer) and target.",
            "# TYPE spaceguard_torrent_detail_total counter"]
    dlast = ["# TYPE spaceguard_torrent_detail_last_seconds gauge"]
    for (user, kind, tracker, ih), (count, ts) in sorted((details or {}).items()):
        labels = (f'node="{n}",user="{_esc(user)}",kind="{_esc(kind)}",tracker="{_esc(tracker)}",'
                  f'info_hash="{_esc(ih)}"')
        out.append(f"spaceguard_torrent_detail_total{{{labels}}} {count}")
        dlast.append(f"spaceguard_torrent_detail_last_seconds{{{labels}}} {int(ts)}")
    out += dlast
    out += ["# TYPE spaceguard_torrent_watch_up gauge",
            f'spaceguard_torrent_watch_up{{node="{n}"}} {1 if up else 0}']
    return "\n".join(out) + "\n"


def write_atomic(path: str, text: str) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


class Follower:
    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, "rb")
        self.fh.seek(0, os.SEEK_END)  # история до старта не нужна
        self.ino = os.fstat(self.fh.fileno()).st_ino
        self.buf = b""

    def _reopen(self) -> None:
        self.fh.close()
        self.fh = open(self.path, "rb")
        self.ino = os.fstat(self.fh.fileno()).st_ino
        self.buf = b""

    def read_lines(self) -> list[bytes]:
        st = os.stat(self.path)
        if st.st_ino != self.ino:
            self._reopen()
        elif st.st_size < self.fh.tell():  # обнулили (мы или кто-то ещё)
            self.fh.seek(0)
            self.buf = b""
        data = self.fh.read()
        if not data:
            return []
        data = self.buf + data
        lines = data.split(b"\n")
        self.buf = lines.pop()
        return lines

    def maybe_truncate(self) -> None:
        if self.fh.tell() >= MAX_BYTES and not self.buf and os.stat(self.path).st_size == self.fh.tell():
            os.truncate(self.path, 0)
            self.fh.seek(0)


class Kmsg:
    """Неблокирующее чтение /dev/kmsg с конца (одна запись на read)."""

    def __init__(self, path: str = KMSG):
        self.fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        os.lseek(self.fd, 0, os.SEEK_END)

    def records(self, limit: int = 5000) -> list[str]:
        out = []
        for _ in range(limit):
            try:
                raw = os.read(self.fd, 8192)
            except BlockingIOError:
                break
            except BrokenPipeError:  # записи перезаписаны — пропускаем
                continue
            if not raw:
                break
            out.append(raw.decode("utf-8", "replace"))
        return out


class Watch:
    """Состояние агента без ввода-вывода — удобно тестировать."""

    def __init__(self):
        self.series: dict[tuple, list] = {}
        self.index: OrderedDict[str, tuple] = OrderedDict()  # "udp|dst|port" -> (user, inbound, ip, ts)
        self.pending: list[tuple] = []                       # (key, sig, ts, detail)
        self.unattributed: dict[str, int] = {}
        self.details: OrderedDict[tuple, list] = OrderedDict()  # (user, kind, tracker, hash) -> [n, ts]

    def hit(self, user, inbound, ip, via, now):
        item = self.series.setdefault((user, inbound, ip, via), [0, now])
        item[0] += 1
        item[1] = now

    def detail(self, user, detail, now):
        key = (user,) + tuple(detail)
        item = self.details.setdefault(key, [0, now])
        item[0] += 1
        item[1] = now
        self.details.move_to_end(key)
        while len(self.details) > DETAILS_MAX:
            self.details.popitem(last=False)

    def access_line(self, line: str, now: float) -> None:
        a = parse_accept(line)
        if not a:
            return
        client, proto, dst, port, inbound, outbound, user = a
        if outbound == TAG:
            self.hit(user, inbound, client, "xray", now)
            self.detail(user, ("peer", "", ""), now)
            return
        key = f"{proto}|{dst}|{port}"
        self.index[key] = (user, inbound, client, now)
        self.index.move_to_end(key)
        if len(self.index) > INDEX_MAX:
            self.index.popitem(last=False)

    def drop(self, sig: str, proto: str, dst: str, port: str, now: float, detail: tuple | None = None) -> None:
        detail = detail or (SIG_KIND.get(sig, "other"), "", "")
        self.pending.append((f"{proto}|{dst}|{port}", sig, now, detail))

    def resolve(self, now: float) -> None:
        keep = []
        for key, sig, ts, detail in self.pending:
            found = self.index.get(key)
            if found and now - found[3] <= INDEX_TTL:
                user, inbound, client, _ = found
                self.hit(user, inbound, client, "ufw", now)
                self.detail(user, detail, now)
            elif now - ts < PENDING_TTL:
                keep.append((key, sig, ts, detail))
            else:
                self.unattributed[sig] = self.unattributed.get(sig, 0) + 1
                self.detail("-", detail, now)
        self.pending = keep

    def expire(self, now: float) -> None:
        while self.index:
            key, val = next(iter(self.index.items()))
            if now - val[3] <= INDEX_TTL:
                break
            self.index.popitem(last=False)
        for key in [k for k, (_, ts) in self.series.items() if now - ts > SERIES_TTL]:
            del self.series[key]
        for key in [k for k, (_, ts) in self.details.items() if now - ts > DETAILS_TTL]:
            del self.details[key]


# ------------------------------------------------------------------ Telegram (необязательно)

KIND_TEXT = {"dht": "DHT-поиск раздающих", "tracker": "запрос к трекеру",
             "peer": "скачивание (обмен с пирами)", "other": "другое"}


def _html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Notifier:
    """Решает, о ком писать в Telegram. Без ввода-вывода: send() вызывает main.

    Пишем о пользователе, если его счётчик вырос с прошлой проверки и с прошлого алерта
    о нём прошло не меньше cooldown секунд. Пользователь "-" (не определён) не алертится —
    это видно в метрике spaceguard_torrent_unattributed_total."""

    def __init__(self, cooldown: int = TG_COOLDOWN):
        self.cooldown = cooldown
        self.seen: dict[str, int] = {}     # user -> сумма срабатываний на прошлой проверке
        self.sent: dict[str, float] = {}   # user -> время последнего алерта

    def due(self, node: str, series: dict, details: dict, now: float) -> list[str]:
        totals: dict[str, int] = {}
        for key, (count, _) in series.items():
            totals[key[0]] = totals.get(key[0], 0) + count
        out = []
        for user, total in sorted(totals.items()):
            grown = total - self.seen.get(user, 0)
            if user == "-" or grown <= 0:
                continue
            if user in self.sent and now - self.sent[user] < self.cooldown:
                continue
            self.sent[user] = now
            out.append(format_tg(node, user, series, details))
        # счётчики могли обнулиться по TTL — запоминаем текущие, а не максимум
        self.seen = totals
        return out


def format_tg(node: str, user: str, series: dict, details: dict) -> str:
    """Текст алерта (HTML): кто, где, чем пойман, что именно качал."""
    inbounds, ips, vias, hits = set(), set(), set(), 0
    for key, (count, _) in series.items():
        if key[0] != user:
            continue
        inbounds.add(key[1]); ips.add(key[2]); vias.add(key[3] if len(key) > 3 else "xray")
        hits += count
    kinds, trackers, hashes = {}, {}, {}
    for (u, kind, tracker, ih), (count, _) in details.items():
        if u != user:
            continue
        kinds[kind] = kinds.get(kind, 0) + count
        if tracker:
            trackers[tracker] = trackers.get(tracker, 0) + count
        if ih:
            hashes[ih] = hashes.get(ih, 0) + count
    top = lambda d: sorted(d, key=lambda k: -d[k])[:5]
    lines = [
        "🧲 <b>Торрент на ноде</b>",
        f"Пользователь: <code>{_html(user)}</code>",
        f"Нода: <code>{_html(node)}</code>",
        f"Вход: {_html(', '.join(sorted(inbounds)))}",
        f"IP: {_html(', '.join(sorted(ips)))}",
        f"Срабатываний: <b>{hits}</b> (через {_html(', '.join(sorted(vias)))})",
    ]
    if kinds:
        lines.append("Что: " + ", ".join(f"{KIND_TEXT.get(k, k)} ×{kinds[k]}" for k in top(kinds)))
    if trackers:
        lines.append("Трекеры: " + _html(", ".join(top(trackers))))
    if hashes:
        lines.append("Торренты: " + ", ".join(f"<code>{h}</code>" for h in top(hashes)))
    return "\n".join(lines)


def send_tg(text: str) -> None:
    """Отправить сообщение; ошибки только печатаем — агент не должен падать из-за Telegram."""
    data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": text, "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    try:
        urllib.request.urlopen(f"{TG_API}/bot{TG_TOKEN}/sendMessage", data=data, timeout=10).read()
    except Exception as exc:  # noqa: BLE001 — сеть, 4xx/5xx Telegram
        print(f"telegram send failed: {type(exc).__name__}", flush=True)


def main() -> None:
    w = Watch()
    follower: Follower | None = None
    try:
        kmsg: Kmsg | None = Kmsg()
    except OSError:
        kmsg = None
    try:
        nflog: Nflog | None = Nflog()
    except OSError as exc:
        print(f"nflog group {NFLOG_GROUP} unavailable: {exc}", flush=True)
        nflog = None
    node = NODE_NAME or "unknown"
    notifier = Notifier() if TG_TOKEN and TG_CHAT else None
    last_flush = 0.0
    while True:
        now = time.time()
        if follower is None:
            paths = sorted(glob.glob(LOG_GLOB))
            if paths:
                follower = Follower(paths[0])
                node = NODE_NAME or os.path.basename(os.path.dirname(paths[0]))
        if follower is not None:
            try:
                for raw in follower.read_lines():
                    if b" accepted " in raw:
                        w.access_line(raw.decode("utf-8", "replace"), now)
                follower.maybe_truncate()
            except FileNotFoundError:
                follower = None
        if kmsg is not None:
            for rec in kmsg.records():
                d = parse_kmsg(rec)
                if d:
                    w.drop(*d, now)
        if nflog is not None:
            for sig, proto, dst, port, *detail in nflog.packets():
                w.drop(sig, proto, dst, port, now, tuple(detail))
        w.resolve(now)
        if now - last_flush >= FLUSH_EVERY:
            w.expire(now)
            try:
                write_atomic(OUT, render(node, w.series, follower is not None, w.unattributed, w.details))
            except OSError:
                pass
            if notifier is not None:
                for text in notifier.due(node, w.series, w.details, now):
                    send_tg(text)
            last_flush = now
        time.sleep(1)


if __name__ == "__main__":
    main()
