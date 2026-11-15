# torrent-guard — защита нод PasarGuard от торрентов

Режет BitTorrent на VPN-нодах и сообщает админу, **кто** из пользователей качал,
**на какой ноде** и **что именно** (DHT, трекер, info_hash торрента).

Работает с официальной [PasarGuard](https://github.com/PasarGuard) без патчей.
Зависимости: Python 3.8+ (только стандартная библиотека), iptables. Docker,
Prometheus и node exporter не обязательны.

## Как устроено

Три слоя. Каждый следующий ловит то, что пропустил предыдущий:

```
клиент ──► Xray на ноде ──────────────────► интернет
            │ слой 1: routing core config
            │   bittorrent → blackhole TORRENT
            │   публичные трекеры → blackhole BLOCK
            ▼
          исходящий пакет ──► слой 3: iptables/ufw
                                DROP пакетов с подписями BitTorrent/DHT
                                копия пакета → NFLOG group 7
                                      │
          access-лог Xray ────────────┤
                                      ▼
                         слой 2: агент torrent-watch
                           кто отправил (сопоставление с access-логом)
                           что это (DHT / трекер / скачивание, info_hash)
                              │                     │
                              ▼                     ▼
                       сообщение в Telegram   метрики Prometheus
```

| Слой | Где | Файл модуля |
|---|---|---|
| 1. Правила Xray | core config в панели (через API) | `panel/torrent_guard_core.py` |
| 2. Агент алертов | systemd на каждой ноде | `node/torrent-watch.py` |
| 3. Файрвол | ufw или iptables на каждой ноде | `node/torrent-guard.sh` |

Банов нет, только блокировка и алерт. Банить по IP ненадёжно: за nginx/Reality
в логе `127.0.0.1`, у мобильных операторов один IP на тысячи абонентов.

## Установка

### 1. Слой 1: правила в core config (один раз, с любой машины с доступом к API панели)

```bash
export PASARGUARD_URL=https://panel.example.com
export PASARGUARD_USERNAME=admin
export PASARGUARD_PASSWORD='...'

python3 panel/torrent_guard_core.py                    # план: что изменится в каждом core
python3 panel/torrent_guard_core.py --core 1 --apply   # применить к core 1
```

- Перед записью исходный core сохраняется в `./torrent-guard-backups/` (права 0600:
  внутри приватные ключи Reality). Откат: `--restore torrent-guard-backups/core-1-....json`.
- Правка routing применяется вживую. Включение sniffing и access-лога перезапускает Xray
  на нодах этого core, у клиентов будет короткий обрыв. Только routing, без рестарта:
  `--no-sniffing --access-log none`.
- Access-лог пишется в `/var/lib/pg-node/xray-access.log` внутри контейнера ноды.
  Официальный установщик `pg-node` монтирует `/var/lib/<имя установки>` под тем же путём.
  Если вы ставили ноду с `--name другое-имя`, укажите
  `--access-log /var/lib/другое-имя/xray-access.log`. Если у core одна нода и каталог
  назван как нода в панели: `--access-log '/var/lib/{node}/xray-access.log'`.

### 2. Слои 2 и 3: на каждой ноде (root)

```bash
scp -r node/ root@NODE:/root/torrent-guard/
ssh root@NODE
bash /root/torrent-guard/torrent-guard.sh install \
     --tg-token 123456:ABC... --tg-chat 111222333     # без --tg-* — только метрики
```

- Если ufw включён, правила встают блоком в `/etc/ufw/before.rules` (backup в
  `/root/torrent-guard-backups/`). Если ufw нет, создаётся своя цепочка `TORRENT_GUARD`
  в OUTPUT и unit `torrent-guard-firewall`, который поднимает её после перезагрузки.
- Агент: unit `torrent-guard-watch`, настройки в `/etc/torrent-guard/watch.env`
  (описание полей — `node/watch.env.example`).
- Нода в РФ, где Telegram API недоступен: `--tg-api https://ваш-прокси-telegram-api`.
  Или не задавайте Telegram и забирайте метрики в свой Prometheus.

### Проверка и удаление

```bash
bash torrent-guard.sh check       # PASS/WARN/FAIL по каждому слою
bash torrent-guard.sh uninstall   # убирает правила и агент; backup остаются
```

## Пример алерта

```
🧲 Торрент на ноде
Пользователь: 42.alice
Нода: de-1
Вход: VLESS TCP REALITY
IP: 203.0.113.7
Срабатываний: 18 (через ufw, xray)
Что: DHT-поиск раздающих ×15, запрос к трекеру ×3
Трекеры: tracker.example.org
Торренты: 3f1c…
```

Пользователь — `email` из access-лога Xray (в PasarGuard это `<id>.<username>`).
О каждом пользователе не чаще раза в час (`TORRENT_WATCH_TG_COOLDOWN`).

## Метрики (textfile node exporter)

| Метрика | Что |
|---|---|
| `spaceguard_torrent_events_total{node,user,inbound,ip,via}` | срабатывания по пользователю (`via=xray\|ufw`) |
| `spaceguard_torrent_last_event_seconds{...}` | время последнего срабатывания |
| `spaceguard_torrent_detail_total{node,user,kind,tracker,info_hash}` | что именно (`kind=dht\|tracker\|peer`) |
| `spaceguard_torrent_unattributed_total{node,sig}` | дропы, для которых пользователь не найден |
| `spaceguard_torrent_watch_up{node}` | 1 — агент читает access-лог |

Файл: `/var/lib/prometheus/node-exporter/spaceguard_torrent.prom`. Node exporter
подхватит его с флагом `--collector.textfile.directory=/var/lib/prometheus/node-exporter`.

## Что не ловится

- Полностью шифрованный BitTorrent (MSE/PE). Но DHT и анонсы трекерам обычно открыты,
  без них клиент не находит пиров.
- HTTPS-трекеры на слое 3: TLS скрывает содержимое. Их режет слой 1 по домену.
- UDP-сессии Hysteria2 Xray часто не пишет в access-лог. Такие дропы попадают в
  `unattributed`: торрент заблокирован, но пользователь не определён.
- Только IPv4 на слое 3.
