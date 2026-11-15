#!/usr/bin/env python3
"""torrent-guard, слой 1: блокировка торрентов в core config Xray через API PasarGuard.

Работает с официальной PasarGuard (без патчей), только stdlib Python 3.8+. Запускается
где угодно, откуда доступен API панели (на самой панели, на ноутбуке админа).

Что делает с каждым core config:
  1. В начало routing.rules ставит два правила:
       protocol bittorrent         -> outbound TORRENT (blackhole)
       домены публичных трекеров   -> outbound BLOCK   (blackhole)
  2. Добавляет outbounds BLOCK и TORRENT (blackhole), если их нет. TORRENT — отдельный тег,
     чтобы агент на ноде (node/torrent-watch.py) видел срабатывания в access-логе.
  3. На клиентских inbound включает sniffing (routeOnly: true): без него Xray не узнаёт
     BitTorrent. routeOnly меняет только маршрутизацию, адрес соединения прежний.
  4. Включает access-лог Xray в файл для агента слоя 2 (--access-log none — не включать).

Схема:
    этот скрипт --(API PasarGuard: GET/PUT /api/core/{id})--> панель --> Xray на нодах

По умолчанию только показывает план. --apply записывает. Перед каждой записью исходный core
сохраняется в ./torrent-guard-backups/core-<id>-<время>.json (права 0600: внутри приватные
ключи Reality). Откат: python3 torrent_guard_core.py --restore <файл>.

Если меняются только routing/outbounds, PasarGuard применяет правку вживую. Правка inbounds
(sniffing) или log перезапускает Xray на нодах этого core — у клиентов короткий обрыв.

Настройки — переменные окружения или аргументы:
    PASARGUARD_URL       https://panel.example.com   (--url)
    PASARGUARD_USERNAME  логин админа панели          (--username)
    PASARGUARD_PASSWORD  пароль                       (--password)

Примеры:
    python3 torrent_guard_core.py                       # план по всем core
    python3 torrent_guard_core.py --core 1 --apply      # применить к core 1
    python3 torrent_guard_core.py --all --apply         # ко всем, где есть изменения
    python3 torrent_guard_core.py --core 1 --apply --no-sniffing --access-log none
                                                        # только routing, без рестарта Xray
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Путь access-лога ВНУТРИ контейнера ноды. Официальный установщик pg-node монтирует
# /var/lib/<имя установки> (по умолчанию pg-node) под тем же путём, поэтому файл виден и на хосте.
# {node} заменяется именем ноды PasarGuard, если у core ровно одна активная нода.
DEFAULT_ACCESS_LOG = "/var/lib/pg-node/xray-access.log"
PUT_KEYS = ("name", "type", "config", "exclude_inbound_tags", "fallbacks_inbound_tags")
BACKUP_DIR = Path(os.environ.get("TORRENT_GUARD_BACKUP_DIR", "torrent-guard-backups"))

# ------------------------------------------------------------------ правила
# Этот блок совпадает с app/services/xray_torrent_guard.py бота SpaceGuard — это проверяет
# tests/test_modules_torrent_guard.py. Меняете правила — меняйте в обоих местах.

TORRENT_TAG = "TORRENT"
BLOCK_TAG = "BLOCK"
TRACKER_DOMAINS = [
    "geosite:category-public-tracker",
    # явные домены — на случай устаревшей geo-базы на ноде
    "domain:opentrackr.org", "domain:explodie.org", "domain:open.stealth.si",
    "domain:tracker.torrent.eu.org", "domain:bttracker.de", "domain:tracker.internetwarriors.net",
]
SNIFF_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "hysteria", "socks", "http"}
SNIFF_DEST = ["http", "tls", "quic"]


def _bt_rule() -> dict:
    return {"type": "field", "protocol": ["bittorrent"], "outboundTag": TORRENT_TAG}


def _tracker_rule() -> dict:
    return {"type": "field", "domain": list(TRACKER_DOMAINS), "outboundTag": BLOCK_TAG}


def _is_bt_rule(rule: dict) -> bool:
    """Правило «только bittorrent → куда-то» (другие условия — не наше, не трогаем)."""
    return (rule.get("protocol") == ["bittorrent"]
            and set(rule) <= {"type", "protocol", "outboundTag", "ruleTag"})


def _is_tracker_rule(rule: dict) -> bool:
    """Правило «только домены трекеров → BLOCK»: все домены из нашего списка."""
    doms = rule.get("domain")
    return (isinstance(doms, list) and doms and set(doms) <= set(TRACKER_DOMAINS)
            and rule.get("outboundTag") == BLOCK_TAG
            and set(rule) <= {"type", "domain", "outboundTag", "ruleTag"})


def _ensure_blackhole(outbounds: list, tag: str, changes: list) -> None:
    for ob in outbounds:
        if ob.get("tag") == tag:
            if ob.get("protocol") != "blackhole":
                raise ValueError(f"outbound {tag} уже есть, но это {ob.get('protocol')}, а не blackhole")
            return
    outbounds.append({"tag": tag, "protocol": "blackhole"})
    changes.append(f"+ outbound {tag} (blackhole)")


def apply_torrent_guard(config: dict, *, sniffing: bool = True,
                        access_log: str | None = None) -> tuple[dict, list[str]]:
    """Вернуть (новый config, список изменений). Пустой список — уже соответствует.

    access_log — путь access-лога Xray для агента spaceguard-torrent-watch (слой 2, алерты);
    None — секцию log не трогать."""
    cfg = copy.deepcopy(config)
    changes: list[str] = []
    if access_log:
        log = cfg.setdefault("log", {})
        if log.get("access") != access_log:
            log["access"] = access_log
            changes.append(f"log.access = {access_log}")
    outbounds = cfg.setdefault("outbounds", [])
    _ensure_blackhole(outbounds, BLOCK_TAG, changes)
    _ensure_blackhole(outbounds, TORRENT_TAG, changes)

    routing = cfg.setdefault("routing", {})
    rules = routing.get("rules") or []
    wanted = [_bt_rule(), _tracker_rule()]
    if rules[:2] != wanted:
        rest = [r for r in rules if not (_is_bt_rule(r) or _is_tracker_rule(r))]
        removed = len(rules) - len(rest)
        changes.append(f"routing: правила bittorrent→{TORRENT_TAG} и трекеры→{BLOCK_TAG} в начало"
                       + (f" (заменено старых: {removed})" if removed else ""))
        rules = wanted + rest
    routing["rules"] = rules

    if sniffing:
        for ib in cfg.get("inbounds", []):
            if ib.get("protocol") not in SNIFF_PROTOCOLS:
                continue
            sn = ib.get("sniffing")
            if not isinstance(sn, dict) or not sn.get("enabled"):
                ib["sniffing"] = {"enabled": True, "destOverride": list(SNIFF_DEST), "routeOnly": True}
                changes.append(f"inbound {ib.get('tag')}: sniffing включён (routeOnly)")
    return cfg, changes


def needs_restart(before: dict, after: dict) -> bool:
    """PasarGuard применяет вживую только routing/outbounds; любая другая правка — Stop+Start Xray."""
    strip = lambda c: json.dumps({k: v for k, v in c.items() if k not in ("routing", "outbounds")},
                                 sort_keys=True)
    return strip(before) != strip(after)


# ------------------------------------------------------------------ API PasarGuard


class PasarGuard:
    """Минимальный клиент официального API PasarGuard (вход по логину и паролю админа)."""

    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip("/")
        self.username, self.password = username, password
        self.token = ""

    def _call(self, method: str, path: str, body: dict | None = None, form: dict | None = None):
        headers = {"Accept": "application/json"}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")[:300]
            raise SystemExit(f"PasarGuard {method} {path}: HTTP {exc.code} {text}") from None

    def login(self) -> None:
        reply = self._call("POST", "/api/admin/token",
                           form={"username": self.username, "password": self.password})
        self.token = (reply or {}).get("access_token") or ""
        if not self.token:
            raise SystemExit("PasarGuard: не получили access_token (проверьте логин и пароль)")

    def cores(self) -> list:
        reply = self._call("GET", "/api/cores/simple")
        return list((reply or {}).get("cores") or []) if isinstance(reply, dict) else []

    def core(self, core_id: int) -> dict:
        return self._call("GET", f"/api/core/{int(core_id)}")

    def put_core(self, core_id: int, payload: dict) -> None:
        # restart_nodes=true обязателен: без него правка не уходит на ноды. Routing/outbounds
        # PasarGuard применяет вживую, при правке inbounds/log — Stop+Start Xray.
        self._call("PUT", f"/api/core/{int(core_id)}?restart_nodes=true", body=payload)

    def nodes(self) -> list:
        reply = self._call("GET", "/api/nodes")
        if isinstance(reply, list):
            return reply
        return list((reply or {}).get("nodes") or [])


def backup(core: dict) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    path = BACKUP_DIR / f"core-{core['id']}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(core, fh, ensure_ascii=False, indent=2)
    return path


def payload_for(core: dict, config: dict) -> dict:
    """Тело PUT /api/core/{id}: поля core как есть, config — новый."""
    payload = {k: core.get(k) for k in PUT_KEYS if core.get(k) is not None}
    payload["config"] = config
    return payload


def resolve_access_log(template: str, live_nodes: list) -> tuple:
    """(путь или None, предупреждение или ""). {node} подставляется, только если нода одна."""
    if template.lower() == "none":
        return None, ""
    if "{node}" not in template:
        return template, ""
    if len(live_nodes) == 1:
        return template.replace("{node}", live_nodes[0]), ""
    return None, f"! access-лог не включён: в пути есть {{node}}, а активных нод у core {len(live_nodes)}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("PASARGUARD_URL", ""))
    ap.add_argument("--username", default=os.environ.get("PASARGUARD_USERNAME", ""))
    ap.add_argument("--password", default=os.environ.get("PASARGUARD_PASSWORD", ""))
    ap.add_argument("--core", type=int, action="append", default=[], help="id core (можно несколько)")
    ap.add_argument("--all", action="store_true", help="с --apply: все core с изменениями")
    ap.add_argument("--apply", action="store_true", help="записать в PasarGuard (иначе только план)")
    ap.add_argument("--no-sniffing", action="store_true", help="не трогать inbounds")
    ap.add_argument("--access-log", default=os.environ.get("TORRENT_GUARD_ACCESS_LOG", DEFAULT_ACCESS_LOG),
                    help=f"путь access-лога внутри контейнера ноды; none — не включать "
                         f"(по умолчанию {DEFAULT_ACCESS_LOG}; можно /var/lib/{{node}}/xray-access.log)")
    ap.add_argument("--restore", metavar="FILE", help="откат: записать core из backup-файла")
    args = ap.parse_args(argv)
    if not (args.url and args.username and args.password):
        ap.error("нужны --url/--username/--password или PASARGUARD_URL/USERNAME/PASSWORD")
    if args.apply and not (args.core or args.all):
        ap.error("--apply требует --core ID или --all")

    pg = PasarGuard(args.url, args.username, args.password)
    pg.login()

    if args.restore:
        core = json.loads(Path(args.restore).read_text(encoding="utf-8"))
        pg.put_core(int(core["id"]), payload_for(core, core["config"]))
        print(f"core {core['id']}: восстановлен из {args.restore}")
        return 0

    # какие ноды у какого core: для подписи в плане и подстановки {node}
    live_by_core: dict = {}
    names_by_core: dict = {}
    for n in pg.nodes():
        cid = n.get("core_config_id")
        if not cid:
            continue
        names_by_core.setdefault(int(cid), []).append(f"{n.get('name')}({n.get('status')})")
        if n.get("status") != "disabled":
            live_by_core.setdefault(int(cid), []).append(str(n.get("name")))

    ids = args.core or [int(c["id"]) for c in pg.cores()]
    pending = 0
    for cid in ids:
        core = pg.core(cid)
        access, warning = resolve_access_log(args.access_log, live_by_core.get(cid, []))
        try:
            new_cfg, changes = apply_torrent_guard(core["config"], sniffing=not args.no_sniffing,
                                                   access_log=access)
        except ValueError as exc:
            print(f"core {cid} {core.get('name')}: ПРОПУСК — {exc}")
            continue
        nodes = ", ".join(names_by_core.get(cid, [])) or "нет нод"
        if not changes:
            print(f"core {cid} {core.get('name')} [{nodes}]: ok" + (f"\n   {warning}" if warning else ""))
            continue
        pending += 1
        mode = "рестарт Xray" if needs_restart(core["config"], new_cfg) else "вживую, без рестарта"
        print(f"core {cid} {core.get('name')} [{nodes}]: {mode}")
        for line in changes + ([warning] if warning else []):
            print(f"   {line}")
        if args.apply:
            path = backup(core)
            pg.put_core(cid, payload_for(core, new_cfg))
            print(f"   ✔ применено, backup {path}")
    if not args.apply and pending:
        print(f"\nИзменений: {pending}. Применить: --apply --core ID (или --all).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
