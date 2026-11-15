#!/usr/bin/env bash
# torrent-guard на ноде PasarGuard: слой 3 (файрвол) + слой 2 (агент алертов).
#
#   bash torrent-guard.sh install   [--node NAME] [--tg-token TOKEN --tg-chat CHAT_ID] [--tg-api URL]
#                                   [--no-firewall] [--no-agent]
#   bash torrent-guard.sh check
#   bash torrent-guard.sh uninstall
#
# Запускать на ноде от root, рядом должен лежать torrent-watch.py (вся папка node/ модуля).
# Повторный install безопасен: ничего не дублирует, только приводит к нужному виду.
#
# Схема:
#   клиент → Xray (слой 1: правила в core, ставит panel/torrent_guard_core.py)
#          → исходящий пакет → файрвол (слой 3: DROP пакетов с подписями BitTorrent/DHT,
#                                       копия пакета в NFLOG group 7 для агента)
#   агент torrent-watch (слой 2): access-лог Xray + NFLOG → кто качает → метрики Prometheus
#                                 и/или сообщение в Telegram
#
# Файрвол:
#   ufw включён   → блок между маркерами в /etc/ufw/before.rules (до правила ESTABLISHED),
#                   backup в /root/torrent-guard-backups/, проверка iptables-restore --test, откат
#                   при ошибке ufw reload;
#   ufw нет       → своя цепочка iptables TORRENT_GUARD, подключается первой в OUTPUT;
#                   восстанавливается после перезагрузки unit-ом torrent-guard-firewall.
# Только IPv4 (как и в production SpaceGuard). Чужие правила не трогаются.
#
# Требования: Debian/Ubuntu, root, python3 ≥ 3.8, iptables с модулями string/hashlimit/NFLOG
# (есть в стандартном ядре). node exporter не обязателен.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB=/usr/local/lib/torrent-guard
CONF_DIR=/etc/torrent-guard
ENV_FILE=$CONF_DIR/watch.env
BACKUPS=/root/torrent-guard-backups
WATCH_UNIT=torrent-guard-watch.service
FW_UNIT=torrent-guard-firewall.service
CHAIN=TORRENT_GUARD
PROM_DIR=/var/lib/prometheus/node-exporter
PROM_FILE=$PROM_DIR/spaceguard_torrent.prom

# Подписи в первых 300 байтах исходящего пакета. Совпадают с шагом torrent_guard в
# scripts/ops/spaceguard-node.sh (проверяет tests/test_modules_torrent_guard.py).
TORRENT_SIGNATURES=("BitTorrent protocol" "announce_peer" "get_peers" "find_node" "info_hash=" "peer_id=")
TORRENT_SIG_KEYS=(bt announce getpeers findnode infohash peerid)  # для LOG-префикса sg-tg:<key>
NFLOG_GROUP=7  # = TORRENT_WATCH_NFLOG_GROUP агента
BEGIN_MARK="# BEGIN torrent-guard module"
END_MARK="# END torrent-guard"

log() { printf '\n== %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "запускать от root"

MODE="${1:-}"; shift || true
NODE="" TG_TOKEN="" TG_CHAT="" TG_API="" FIREWALL=1 AGENT=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node) NODE="$2"; shift ;;
    --tg-token) TG_TOKEN="$2"; shift ;;
    --tg-chat) TG_CHAT="$2"; shift ;;
    --tg-api) TG_API="$2"; shift ;;
    --no-firewall) FIREWALL=0 ;;
    --no-agent) AGENT=0 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) die "неизвестный аргумент: $1" ;;
  esac
  shift
done

ufw_active() { command -v ufw >/dev/null && ufw status 2>/dev/null | head -1 | grep -q 'Status: active'; }

# Правила для одной цепочки: перед каждым DROP — NFLOG (агенту: кто, куда, что за торрент).
# hashlimit: не больше 1 копии на dst:port в минуту и 120/мин на подпись — без потока событий.
rules_for() { # rules_for CHAIN
  local i s k m
  for i in "${!TORRENT_SIGNATURES[@]}"; do
    s=${TORRENT_SIGNATURES[$i]}; k=${TORRENT_SIG_KEYS[$i]}
    m="-m string --algo bm --from 0 --to 300 --string \"$s\""
    printf -- '-A %s %s -m hashlimit --hashlimit-upto 1/min --hashlimit-burst 1 --hashlimit-mode dstip,dstport --hashlimit-name sgtg_%s -m limit --limit 120/min --limit-burst 120 -j NFLOG --nflog-group %s --nflog-prefix "sg-tg:%s" --nflog-size 1024\n' "$1" "$m" "$k" "$NFLOG_GROUP" "$k"
    printf -- '-A %s %s -j DROP\n' "$1" "$m"
  done
}

live_drops() { iptables -S 2>/dev/null | grep -- '-m string' | grep -c -- '-j DROP' || true; }

# ------------------------------------------------------------------ слой 3: ufw

fw_ufw_install() {
  local f=/etc/ufw/before.rules want cur tmp bak
  [[ -f "$f" ]] || die "$f не найден"
  grep -q '^# End required lines' "$f" || die "$f: нет маркера '# End required lines'"
  want="$BEGIN_MARK"$'\n'"$(rules_for ufw-before-output)"$'\n'"$END_MARK"
  # текущий блок между маркерами (awk index — без regex, маркеры могут содержать спецсимволы)
  cur=$(B="$BEGIN_MARK" E="$END_MARK" awk '
    index($0, ENVIRON["B"]) == 1 {on=1}
    on {print}
    on && index($0, ENVIRON["E"]) == 1 {on=0}' "$f")
  if [[ "$cur" == "$want" ]] && (( $(live_drops) >= ${#TORRENT_SIGNATURES[@]} )); then
    echo "ufw: уже применено"; return
  fi
  install -d -m 700 "$BACKUPS"
  bak=$BACKUPS/before.rules.$(date +%Y%m%d-%H%M%S)
  cp -a "$f" "$bak"
  tmp=$(mktemp)
  # убрать прежний блок и вставить актуальный сразу после маркера ufw
  TG_BLOCK="$want" B="$BEGIN_MARK" E="$END_MARK" awk '
    index($0, ENVIRON["B"]) == 1 {skip=1; next}
    skip && index($0, ENVIRON["E"]) == 1 {skip=0; next}
    skip {next}
    {print}
    /^# End required lines/ {print ENVIRON["TG_BLOCK"]}
  ' "$f" >"$tmp"
  if ! iptables-restore --test <"$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"; die "новый before.rules не проходит iptables-restore --test (файл не изменён)"
  fi
  install -m 640 "$tmp" "$f"; rm -f "$tmp"
  if ! ufw reload >/dev/null; then
    cp -a "$bak" "$f"; ufw reload >/dev/null || true
    die "ufw reload не прошёл — восстановлен $bak"
  fi
  echo "ufw: применено, правил DROP: $(live_drops); backup $bak"
}

fw_ufw_remove() {
  local f=/etc/ufw/before.rules bak
  [[ -f "$f" ]] && grep -qF "$BEGIN_MARK" "$f" || return 0
  install -d -m 700 "$BACKUPS"
  bak=$BACKUPS/before.rules.$(date +%Y%m%d-%H%M%S)
  cp -a "$f" "$bak"
  B="$BEGIN_MARK" E="$END_MARK" awk '
    index($0, ENVIRON["B"]) == 1 {skip=1; next}
    skip && index($0, ENVIRON["E"]) == 1 {skip=0; next}
    !skip {print}' "$bak" >"$f"
  ufw_active && ufw reload >/dev/null
  echo "ufw: блок удалён; backup $bak"
}

# ------------------------------------------------------------------ слой 3: iptables без ufw

fw_chain_install() {
  install -d -m 755 "$LIB"
  {
    echo '#!/usr/bin/env bash'
    echo "# Сгенерировано torrent-guard.sh. Цепочка $CHAIN первой в OUTPUT."
    echo 'set -e'
    echo "iptables -N $CHAIN 2>/dev/null || iptables -F $CHAIN"
    rules_for "$CHAIN" | sed 's/^/iptables /'
    echo "iptables -C OUTPUT -j $CHAIN 2>/dev/null || iptables -I OUTPUT 1 -j $CHAIN"
  } >"$LIB/firewall.sh"
  chmod 750 "$LIB/firewall.sh"
  cat >/etc/systemd/system/$FW_UNIT <<EOF
[Unit]
Description=torrent-guard: iptables chain $CHAIN (BitTorrent/DHT signatures)
After=network-pre.target
Before=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$LIB/firewall.sh
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable $FW_UNIT >/dev/null 2>&1
  systemctl restart $FW_UNIT
  echo "iptables: цепочка $CHAIN, правил DROP: $(live_drops)"
}

fw_chain_remove() {
  if [[ -f /etc/systemd/system/$FW_UNIT ]]; then
    systemctl disable --now $FW_UNIT >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/$FW_UNIT; systemctl daemon-reload
  fi
  while iptables -D OUTPUT -j $CHAIN 2>/dev/null; do :; done
  iptables -F $CHAIN 2>/dev/null && iptables -X $CHAIN 2>/dev/null && echo "iptables: цепочка $CHAIN удалена" || true
  rm -f "$LIB/firewall.sh"
}

# ------------------------------------------------------------------ слой 2: агент

set_env() { # set_env KEY VALUE — заменить или дописать строку в $ENV_FILE
  local k=$1 v=$2
  if grep -q "^$k=" "$ENV_FILE"; then
    KV="$k=$v" awk -v k="$k" 'index($0, k"=") == 1 {print ENVIRON["KV"]; next} {print}' "$ENV_FILE" >"$ENV_FILE.tmp"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
  else
    echo "$k=$v" >>"$ENV_FILE"
  fi
}

agent_install() {
  [[ -f "$HERE/torrent-watch.py" ]] || die "$HERE/torrent-watch.py не найден"
  command -v python3 >/dev/null || die "нужен python3"
  install -d -m 755 "$LIB" "$PROM_DIR"
  install -d -m 700 "$CONF_DIR"
  install -m 755 "$HERE/torrent-watch.py" "$LIB/torrent-watch.py"
  if [[ ! -f "$ENV_FILE" ]]; then
    install -m 600 "$HERE/watch.env.example" "$ENV_FILE"
    set_env TORRENT_WATCH_NODE "$(hostname -s)"
  fi
  chmod 600 "$ENV_FILE"
  [[ -n "$NODE" ]] && set_env TORRENT_WATCH_NODE "$NODE"
  [[ -n "$TG_TOKEN" ]] && set_env TORRENT_WATCH_TG_TOKEN "$TG_TOKEN"
  [[ -n "$TG_CHAT" ]] && set_env TORRENT_WATCH_TG_CHAT "$TG_CHAT"
  [[ -n "$TG_API" ]] && set_env TORRENT_WATCH_TG_API "$TG_API"
  cat >/etc/systemd/system/$WATCH_UNIT <<EOF
[Unit]
Description=torrent-guard: watch Xray access log + NFLOG, alerts
After=docker.service
[Service]
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/python3 $LIB/torrent-watch.py
Restart=always
RestartSec=10
Nice=10
MemoryMax=256M
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable $WATCH_UNIT >/dev/null 2>&1
  systemctl restart $WATCH_UNIT
  echo "агент: $(systemctl is-active $WATCH_UNIT), настройки $ENV_FILE"
  ls /var/lib/*/xray-access.log >/dev/null 2>&1 \
    || echo "  access-лога Xray пока нет — примените слой 1 (panel/torrent_guard_core.py --apply)"
}

agent_remove() {
  if [[ -f /etc/systemd/system/$WATCH_UNIT ]]; then
    systemctl disable --now $WATCH_UNIT >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/$WATCH_UNIT; systemctl daemon-reload
  fi
  rm -f "$LIB/torrent-watch.py" "$PROM_FILE"
  echo "агент удалён (настройки $ENV_FILE оставлены — удалите вручную, если не нужны)"
}

# ------------------------------------------------------------------ check

FAILS=0; WARNS=0
pass() { printf '  PASS  %-30s %s\n' "$1" "${2:-}"; }
warn() { printf '  WARN  %-30s %s\n' "$1" "${2:-}"; WARNS=$((WARNS + 1)); }
fail() { printf '  FAIL  %-30s %s\n' "$1" "${2:-}"; FAILS=$((FAILS + 1)); }

run_check() {
  log "torrent-guard check"
  local n; n=$(live_drops)
  (( n >= ${#TORRENT_SIGNATURES[@]} )) && pass "файрвол (слой 3)" "$n правил DROP" \
    || fail "файрвол (слой 3)" "правил DROP: $n — запустите install"
  systemctl is-active --quiet $WATCH_UNIT && pass "агент (слой 2)" \
    || fail "агент (слой 2)" "$WATCH_UNIT не запущен"
  ls /var/lib/*/xray-access.log >/dev/null 2>&1 && pass "access-лог Xray" "$(ls /var/lib/*/xray-access.log | head -1)" \
    || warn "access-лог Xray" "нет — слой 1 не применён к core этой ноды"
  grep -q '^spaceguard_torrent_watch_up{.*} 1$' "$PROM_FILE" 2>/dev/null && pass "агент читает лог" \
    || warn "агент читает лог" "spaceguard_torrent_watch_up != 1"
  if [[ -f "$ENV_FILE" ]] && grep -q '^TORRENT_WATCH_TG_TOKEN=.\+' "$ENV_FILE" && grep -q '^TORRENT_WATCH_TG_CHAT=.\+' "$ENV_FILE"; then
    pass "алерты в Telegram" "включены"
  else
    warn "алерты в Telegram" "выключены (только метрики)"
  fi
  echo; echo "итого: FAIL=$FAILS WARN=$WARNS"
  (( FAILS == 0 ))
}

case "$MODE" in
  install)
    if (( FIREWALL )); then
      log "слой 3: файрвол"
      if ufw_active; then fw_ufw_install; else fw_chain_install; fi
    fi
    if (( AGENT )); then log "слой 2: агент"; agent_install; fi
    run_check || true
    ;;
  check) run_check ;;
  uninstall)
    log "удаление"
    agent_remove
    fw_ufw_remove
    fw_chain_remove
    ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
