#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root!"
    exit 1
fi

SSH_PORT=22
HTTP_PORT=80
HTTPS_PORT=443

LOG_FILE="/var/log/firewall_activity.log"

configure_firewall() {
    echo "Configuring firewall..."

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $HTTP_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $HTTPS_PORT -j ACCEPT

    iptables -A INPUT -p icmp -j DROP

    iptables -A INPUT -j LOG --log-prefix "INPUT DROP: " --log-level 4
    iptables -A OUTPUT -j LOG --log-prefix "OUTPUT DROP: " --log-level 4

    iptables-save > /etc/iptables/rules.v4

    echo "Firewall configured successfully."
}

detect_and_block_attackers() {
    tail -F /var/log/syslog | grep --line-buffered "INPUT DROP:" | while read line; do
        IP=$(echo $line | grep -oP '(?<=SRC=)[\d.]+')
        ATTEMPT_COUNT=$(grep -c "$IP" /var/log/syslog)

        if [ "$ATTEMPT_COUNT" -gt 10 ]; then
            echo "Suspicious activity detected from $IP. Blocking IP..."
            iptables -A INPUT -s $IP -j DROP
            echo "$(date): Blocked IP $IP after $ATTEMPT_COUNT failed attempts" >> $LOG_FILE
            break
        fi
    done
}

enable_persistence() {
    iptables-save > /etc/iptables/rules.v4
}

main() {
    configure_firewall

    detect_and_block_attackers &

    enable_persistence

    while true; do
        sleep 60  
    done
}

main
