#!/bin/bash

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root!"
    exit 1
fi

# Define the ports to allow (SSH, HTTP, HTTPS)
SSH_PORT=22
HTTP_PORT=80
HTTPS_PORT=443

# Set the log file for suspicious activity
LOG_FILE="/var/log/firewall_activity.log"

# Function to configure the firewall
configure_firewall() {
    echo "Configuring firewall..."

    # Set default policies (DROP all incoming, ACCEPT outgoing)
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback traffic (local communication)
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow SSH, HTTP, and HTTPS ports
    iptables -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $HTTP_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $HTTPS_PORT -j ACCEPT

    # Block incoming ICMP (ping) to reduce discoverability
    iptables -A INPUT -p icmp -j DROP

    # Log dropped packets (for IDS purpose)
    iptables -A INPUT -j LOG --log-prefix "INPUT DROP: " --log-level 4
    iptables -A OUTPUT -j LOG --log-prefix "OUTPUT DROP: " --log-level 4

    # Save iptables rules (for persistence after reboot)
    iptables-save > /etc/iptables/rules.v4

    echo "Firewall configured successfully."
}

# Function to detect and block attackers (simple version)
detect_and_block_attackers() {
    # Monitor the log file for suspicious activity
    tail -F /var/log/syslog | grep --line-buffered "INPUT DROP:" | while read line; do
        # Example: Check for multiple failed connection attempts from the same IP
        IP=$(echo $line | grep -oP '(?<=SRC=)[\d.]+')
        ATTEMPT_COUNT=$(grep -c "$IP" /var/log/syslog)

        if [ "$ATTEMPT_COUNT" -gt 10 ]; then
            echo "Suspicious activity detected from $IP. Blocking IP..."
            iptables -A INPUT -s $IP -j DROP
            echo "$(date): Blocked IP $IP after $ATTEMPT_COUNT failed attempts" >> $LOG_FILE

            # Optionally, trigger an IP change mechanism (VPN, etc.)
            # Example: vpn_change_ip_function  # You'd need a VPN setup for this

            # Exit loop if we want to stop monitoring
            break
        fi
    done
}

# Function to ensure persistence of firewall rules
enable_persistence() {
    # Save rules for system startup (persistent across reboots)
    iptables-save > /etc/iptables/rules.v4
}

# Main function to configure and monitor firewall
main() {
    # Configure firewall
    configure_firewall

    # Start attack detection and blocking (run in background)
    detect_and_block_attackers &

    # Enable persistence to save firewall rules
    enable_persistence

    # Keep script running to monitor traffic
    while true; do
        sleep 60  # Run indefinitely to keep monitoring
    done
}

# Run the main function
main
