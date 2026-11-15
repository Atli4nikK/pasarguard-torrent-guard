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

## Требования

- Панель: официальная PasarGuard, логин и пароль админа.
- Машина, с которой ставится слой 1: Python 3.8+ и доступ к адресу панели (подойдёт сама панель).
- Каждая нода: официальная `pg-node`, доступ root, Debian/Ubuntu, `python3` и `iptables`
  (на Debian/Ubuntu обычно уже стоят), `git` или возможность скопировать папку через `scp`.
- Для алертов в Telegram: бот и chat id.
  - Токен — у [@BotFather](https://t.me/BotFather), команда `/newbot`.
  - Chat id — напишите боту любое сообщение и откройте
    `https://api.telegram.org/bot<ТОКЕН>/getUpdates`, число в `"chat":{"id":...}`.
    Для группы: добавьте бота в группу, id будет отрицательным.

## Установка

Порядок: сначала шаг 1 (один раз на панель), потом шаг 2 на каждой ноде.

```bash
git clone https://github.com/Atli4nikK/pasarguard-torrent-guard.git
cd pasarguard-torrent-guard
```

### 1. Слой 1: правила в core config (один раз, с любой машины с доступом к API панели)

```bash
export PASARGUARD_URL=https://panel.example.com
export PASARGUARD_USERNAME=admin
export PASARGUARD_PASSWORD='...'

python3 panel/torrent_guard_core.py                    # план: что изменится в каждом core
python3 panel/torrent_guard_core.py --core 1 --apply   # применить к core 1
```

- Номер core и его ноды видны в первой строке плана: `core 1 main [de-1(connected), ...]`.
  Применить ко всем сразу: `--all --apply`.
- Перед записью исходный core сохраняется в `./torrent-guard-backups/` (права 0600:
  внутри приватные ключи Reality). Откат: `--restore torrent-guard-backups/core-1-....json`.
- Правка routing применяется вживую. Включение sniffing и access-лога перезапускает Xray
  на нодах этого core, у клиентов будет короткий обрыв. Только routing, без рестарта:
  `--no-sniffing --access-log none`.
- Журнал соединений Xray пишется в `/tmp/xray-access.log` **внутри контейнера** ноды.
  `/tmp` есть в контейнере любой ноды, с каким бы `--name` её ни ставили, поэтому один core
  можно отдавать нодам с разными именами. Агент на хосте читает файл через
  `/proc/<pid>/root/tmp/`.
- Журнал обнуляет агент (шаг 2), когда файл больше 32 МБ. **Поставьте агент на все ноды
  core**: без него журнал растёт без ограничений. Не нужен журнал — `--access-log none`
  (блокировка работает, но не будет известно, кто качал).
- Свой путь: `--access-log /путь/в/контейнере`. Каталог должен существовать на **каждой**
  ноде core, иначе Xray там не запустится.

### 2. Слои 2 и 3: на каждой ноде (root)

На ноде под root:

```bash
git clone https://github.com/Atli4nikK/pasarguard-torrent-guard.git
bash pasarguard-torrent-guard/node/torrent-guard.sh install \
     --tg-token 123456:ABC... --tg-chat 111222333     # без --tg-* — только метрики
```

Без `git` на ноде — скопируйте папку со своей машины:
`scp -r node/ root@NODE:/root/torrent-guard/`, затем `bash /root/torrent-guard/torrent-guard.sh install ...`.

В конце `install` сам запускает проверку, все строки должны быть `PASS`.
Xray и нода не перезапускаются, клиенты ничего не замечают.

- Если ufw включён, правила встают блоком в `/etc/ufw/before.rules` (backup в
  `/root/torrent-guard-backups/`). Если ufw нет, создаётся своя цепочка `TORRENT_GUARD`
  в OUTPUT и unit `torrent-guard-firewall`, который поднимает её после перезагрузки.
- Агент: unit `torrent-guard-watch`, настройки в `/etc/torrent-guard/watch.env`
  (описание полей — `node/watch.env.example`).
- Нода в РФ, где Telegram API недоступен: `--tg-api https://ваш-прокси-telegram-api`.
  Или не задавайте Telegram и забирайте метрики в свой Prometheus.

### Новая нода

- Нода подключена к core, к которому шаг 1 уже применён: **на панели ничего делать не надо**.
  Панель сама отправит ноде конфиг с правилами. Выполните на ноде только шаг 2.
- Нода на новом core: шаг 1 для этого core (`--core N --apply`), затем шаг 2 на ноде.
- Если `check` на ноде пишет `WARN access-лог Xray`, к core этой ноды не применён шаг 1
  или нода ещё не получила новый конфиг (проверьте, что она `connected` в панели).

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
