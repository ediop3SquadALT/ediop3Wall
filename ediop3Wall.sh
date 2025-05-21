 #!/bin/bash
set -euo pipefail
IFS=$'\n\t'

[ "$(id -u)" -ne 0 ] && { echo "Must be run as root"; exit 1; }

LOCKFILE="/var/lock/firewall.lock"
LOGFILE="/var/log/firewall_activity.log"
BLACKLIST="/etc/firewall/blacklist"
WHITELIST="/etc/firewall/whitelist"
IPSET_BLOCK="blocked_ips"
IPSET_TOR="tor_exits"
IPSET_ET="emerging_threats"
RULESFILE="/etc/iptables/rules.v4"
RULESFILE6="/etc/iptables/rules.v6"
GEOIP_DB="/usr/share/GeoIP/GeoIPCountryWhois.csv"
GEOIP6_DB="/usr/share/GeoIP/GeoIPv6.csv"
SYSTEMD_SERVICE="/etc/systemd/system/firewall.service"
SURICATA_RULES="/etc/suricata/rules"
SNORT_RULES="/etc/snort/rules"
THREAT_FEEDS=(
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    "https://check.torproject.org/torbulkexitlist"
    "https://www.spamhaus.org/drop/drop.txt"
    "https://www.spamhaus.org/drop/edrop.txt"
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    "https://reputation.alienvault.com/reputation.data"
)
SIEM_SERVER="siem.yourdomain.com:514"
ML_MODEL="/etc/firewall/traffic_model.dat"

declare -A ALLOWED_PORTS=( [22]="tcp" [80]="tcp" [443]="tcp" [53]="udp" )
declare -A RATE_LIMITS=()
declare -A TRAFFIC_PATTERNS=()

HOSTILE_COUNTRIES=("CN" "RU" "KP" "IR" "SY" "VE" "SD" "CU" "MM")
HOSTILE_COUNTRIES6=("CN" "RU" "KP" "IR")

mkdir -p /etc/firewall /etc/suricata /etc/snort
touch "$LOGFILE" "$BLACKLIST" "$WHITELIST"
chmod 600 "$LOGFILE" "$BLACKLIST" "$WHITELIST"

install_deps() {
    DEPS=(iptables ipset geoiplookup curl jq systemctl grep tail sed awk suricata snort fail2ban mlpack arping conntrack rsyslog)
    for dep in "${DEPS[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            apt-get update -qq
            apt-get install -y -qq "$dep" geoip-bin iptables-persistent geoipupdate || exit 1
        fi
    done
    if [ ! -f "/usr/local/bin/ip2asn" ]; then
        curl -sSL "https://github.com/nitefood/asn/releases/download/v1.0.0/ip2asn" -o /usr/local/bin/ip2asn
        chmod +x /usr/local/bin/ip2asn
    fi
}

download_geoip_db() {
    geoipupdate || true
}

setup_ipsets() {
    ipset create "$IPSET_BLOCK" hash:ip timeout 3600 2>/dev/null || true
    ipset create "$IPSET_TOR" hash:ip timeout 86400 2>/dev/null || true
    ipset create "$IPSET_ET" hash:ip timeout 86400 2>/dev/null || true
    for c in "${HOSTILE_COUNTRIES[@]}"; do
        ipset create "geoip-$c" hash:net timeout 3600 2>/dev/null || true
    done
    for c in "${HOSTILE_COUNTRIES6[@]}"; do
        ipset create "geoip6-$c" hash:net family inet6 timeout 3600 2>/dev/null || true
    done
}

update_threat_feeds() {
    for feed in "${THREAT_FEEDS[@]}"; do
        case "$feed" in
            *torproject.org*)
                curl -sSL "$feed" | while read -r ip; do
                    ipset add "$IPSET_TOR" "$ip" 2>/dev/null || true
                done
                ;;
            *emergingthreats*)
                curl -sSL "$feed" | while read -r ip; do
                    ipset add "$IPSET_ET" "$ip" 2>/dev/null || true
                done
                ;;
            *spamhaus.org*)
                curl -sSL "$feed" | grep -v '^;' | cut -d' ' -f1 | while read -r net; do
                    ipset add "$IPSET_BLOCK" "$net" 2>/dev/null || true
                done
                ;;
            *abuse.ch*)
                curl -sSL "$feed" | grep -v '^#' | cut -d' ' -f1 | while read -r ip; do
                    ipset add "$IPSET_BLOCK" "$ip" 2>/dev/null || true
                done
                ;;
            *alienvault.com*)
                curl -sSL "$feed" | grep -v '^#' | cut -d' ' -f1 | while read -r ip; do
                    ipset add "$IPSET_BLOCK" "$ip" 2>/dev/null || true
                done
                ;;
        esac
    done
}

block_country() {
    for country in "${HOSTILE_COUNTRIES[@]}"; do
        if [ -f "$GEOIP_DB" ]; then
            grep "^$country," "$GEOIP_DB" | cut -d',' -f2-3 | tr -d '"' | while read -r ipnet; do
                ipset add "geoip-$country" "$ipnet" 2>/dev/null || true
            done
        fi
        if ! iptables -C INPUT -m set --match-set "geoip-$country" src -j DROP &>/dev/null; then
            iptables -I INPUT -m set --match-set "geoip-$country" src -j DROP
        fi
    done
    for country in "${HOSTILE_COUNTRIES6[@]}"; do
        if [ -f "$GEOIP6_DB" ]; then
            grep "^$country," "$GEOIP6_DB" | cut -d',' -f2-3 | tr -d '"' | while read -r ipnet; do
                ipset add "geoip6-$country" "$ipnet" 2>/dev/null || true
            done
        fi
        if ! ip6tables -C INPUT -m set --match-set "geoip6-$country" src -j DROP &>/dev/null; then
            ip6tables -I INPUT -m set --match-set "geoip6-$country" src -j DROP
        fi
    done
}

block_ip() {
    local ip=$1
    ipset add "$IPSET_BLOCK" "$ip" 2>/dev/null || true
    echo "$(date +'%Y-%m-%d %H:%M:%S') BLOCKED IP $ip" >> "$LOGFILE"
    logger -p authpriv.warning -t firewall "Blocked malicious IP: $ip"
}

setup_firewall() {
    iptables -F
    iptables -X
    ip6tables -F
    ip6tables -X

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT ACCEPT

    iptables -A INPUT -m set --match-set "$IPSET_BLOCK" src -j DROP
    iptables -A INPUT -m set --match-set "$IPSET_TOR" src -j DROP
    iptables -A INPUT -m set --match-set "$IPSET_ET" src -j DROP
    ip6tables -A INPUT -j DROP

    iptables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT

    for port in "${!ALLOWED_PORTS[@]}"; do
        iptables -A INPUT -p "${ALLOWED_PORTS[$port]}" --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    done

    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
    iptables -A INPUT -p icmp -j DROP

    iptables -N TCP_SCAN 2>/dev/null || true
    iptables -F TCP_SCAN || true
    iptables -A TCP_SCAN -j LOG --log-prefix "[TCP_SCAN] " --log-level 4
    iptables -A TCP_SCAN -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j TCP_SCAN
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j TCP_SCAN
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j TCP_SCAN
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j TCP_SCAN

    iptables -N SYN_FLOOD 2>/dev/null || true
    iptables -F SYN_FLOOD || true
    iptables -A SYN_FLOOD -m recent --name synflood --update --seconds 60 --hitcount 15 -j DROP
    iptables -A SYN_FLOOD -m recent --name synflood --set -j ACCEPT
    iptables -A INPUT -p tcp --syn -j SYN_FLOOD

    iptables -A INPUT -p tcp -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP

    iptables -A INPUT -m hashlimit --hashlimit-name tcp_rate --hashlimit-above 20/sec --hashlimit-mode srcip --hashlimit-burst 40 -j DROP

    iptables -N DNS_AMPLIFICATION 2>/dev/null || true
    iptables -F DNS_AMPLIFICATION || true
    iptables -A DNS_AMPLIFICATION -j LOG --log-prefix "[DNS_AMP] " --log-level 4
    iptables -A DNS_AMPLIFICATION -j DROP
    iptables -A INPUT -p udp --dport 53 -m length --length 512:65535 -j DNS_AMPLIFICATION

    iptables -N PORT_SCAN 2>/dev/null || true
    iptables -F PORT_SCAN || true
    iptables -A PORT_SCAN -m recent --name portscan --remove -j DROP
    iptables -A INPUT -m recent --name portscan --set -j PORT_SCAN

    iptables -A INPUT -j LOG --log-prefix "[DROP_INPUT] " --log-level 4
    iptables -A INPUT -j DROP
}

setup_suricata() {
    if [ ! -f "/etc/suricata/suricata.yaml" ]; then
        suricata-update
        cat > "/etc/suricata/suricata.yaml" <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "any"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      type: file
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls

logging:
  default-log-level: info
  outputs:
    - console:
        enabled: no
    - file:
        enabled: yes
        filename: /var/log/suricata/suricata.log
        append: yes

threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

mpm-algo: ac

detect-engine:
  - rule-reload: true
  - profile: medium

app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    ssh:
      enabled: yes
    dns:
      enabled: yes
      memcap: 16mb
      detect-protocol-errors: yes
    ftp:
      enabled: yes
    smtp:
      enabled: yes
EOF
        systemctl enable suricata
        systemctl start suricata
    fi
}

setup_snort() {
    if [ ! -f "/etc/snort/snort.conf" ]; then
        snort -c /etc/snort/snort.conf --dump-dynamic-rules /etc/snort/rules
        systemctl enable snort
        systemctl start snort
    fi
}

setup_fail2ban() {
    if [ ! -f "/etc/fail2ban/jail.local" ]; then
        cat > "/etc/fail2ban/jail.local" <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log

[apache]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports[name=recidive]
       %(action_mwl)s
bantime = 1w
findtime = 1d
maxretry = 3
EOF
        systemctl enable fail2ban
        systemctl start fail2ban
    fi
}

setup_siem() {
    if ! grep -q "SIEM forwarding" /etc/rsyslog.conf; then
        cat >> /etc/rsyslog.conf <<EOF
*.* @$SIEM_SERVER
EOF
        systemctl restart rsyslog
    fi
}

analyze_traffic() {
    local log_data=$(iptables -L -n -v | grep -E "Chain (INPUT|FORWARD)" | awk '{print $1,$2,$3,$4,$5,$6,$7,$8,$9,$10}')
    local ml_input=$(echo "$log_data" | mlpack_preprocess --input-file - --output-file -)
    local prediction=$(echo "$ml_input" | mlpack_predict --model-file "$ML_MODEL")
    if [[ "$prediction" == *"anomaly"* ]]; then
        logger -p authpriv.alert -t firewall "Traffic anomaly detected: $log_data"
        iptables -A INPUT -m hashlimit --hashlimit-name anomaly --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip -j DROP
    fi
}

save_rules() {
    iptables-save > "$RULESFILE"
    ip6tables-save > "$RULESFILE6"
    ipset save > /etc/firewall/ipsets.save
}

load_rules() {
    iptables-restore < "$RULESFILE"
    ip6tables-restore < "$RULESFILE6"
    ipset restore < /etc/firewall/ipsets.save 2>/dev/null || true
}

monitor_syslog() {
    tail -Fn0 /var/log/syslog | grep --line-buffered -E "(DROP_INPUT|TCP_SCAN|DNS_AMP)" | while read -r line; do
        ip=$(echo "$line" | grep -oP '(?<=SRC=)[\d\.]+')
        [ -z "$ip" ] && continue
        echo "$ip" >> "$BLACKLIST"
        count=$(grep -c "^$ip$" "$BLACKLIST")
        if (( count > 5 )); then
            block_ip "$ip"
        fi
    done
}

monitor_suricata() {
    tail -Fn0 /var/log/suricata/fast.log | while read -r line; do
        if [[ "$line" == *"ET "* ]]; then
            ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
            [ -z "$ip" ] && continue
            block_ip "$ip"
        fi
    done
}

audit_rules() {
    local current_hash=$(sha256sum "$RULESFILE" | awk '{print $1}')
    local last_hash=$(cat /etc/firewall/last_audit.hash 2>/dev/null || echo "")
    if [ "$current_hash" != "$last_hash" ]; then
        logger -p authpriv.alert -t firewall "Firewall rules changed unexpectedly!"
        echo "$current_hash" > /etc/firewall/last_audit.hash
    fi
}

setup_systemd_service() {
    if [ ! -f "$SYSTEMD_SERVICE" ]; then
        cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=Ultra Firewall Service
After=network.target suricata.service snort.service fail2ban.service

[Service]
Type=forking
ExecStart=$(realpath "$0") --start
ExecReload=$(realpath "$0") --reload
ExecStop=$(realpath "$0") --stop
PIDFile=/var/run/firewall.pid
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable firewall.service
        systemctl start firewall.service
    fi
}

main() {
    exec 200>"$LOCKFILE"
    flock -n 200 || exit 1
    trap 'flock -u 200; rm -f "$LOCKFILE"; exit' INT TERM EXIT

    install_deps
    download_geoip_db
    setup_ipsets
    update_threat_feeds
    block_country
    setup_firewall
    setup_suricata
    setup_snort
    setup_fail2ban
    setup_siem
    save_rules
    echo "$(date +'%Y-%m-%d %H:%M:%S') - Firewall started on $(hostname)" >> "$LOGFILE"

    monitor_syslog &
    monitor_suricata &

    setup_systemd_service

    while true; do
        update_threat_feeds
        analyze_traffic
        audit_rules
        save_rules
        sleep 3600
    done
}

case "${1:-}" in
    --start)
        main
        ;;
    --reload)
        load_rules
        ;;
    --stop)
        iptables -F
        iptables -X
        ip6tables -F
        ip6tables -X
        ;;
    *)
        main
        ;;
esac
