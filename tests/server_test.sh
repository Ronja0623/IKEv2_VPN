#!/bin/bash
# Run installVPN.sh non-interactively and check the resulting server setup.
# It changes packages, /etc and the firewall, so it only runs on a throwaway CI machine.
set -euo pipefail

[[ ${CI:-} == true ]] || { echo 'Refusing to run outside CI (CI=true): this script modifies the system'; exit 1; }
[[ $# -eq 3 ]] || { echo "Usage: $0 SERVER_IP VPN_USER VPN_PASS"; exit 1; }
SERVER_IP=$1
VPN_USER=$2
VPN_PASS=$3

cd "$(dirname "$0")/../server"

# Install the installer's packages up front, non-interactively, so apt/debconf
# can't consume the user name and password piped into the installer below.
sudo apt-get update -qq
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw strongswan strongswan-pki \
    libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libtss2-tcti-tabrmd0

# Files installVPN.sh backs up before changing them; remember their original content.
BACKED_UP=(/etc/ipsec.conf /etc/ipsec.secrets /etc/ufw/before.rules /etc/ufw/sysctl.conf)
original_sums=$(sudo sha256sum "${BACKED_UP[@]}")

# installVPN.sh reads the server IP and SSH port from SSH_CONNECTION
# ("client_ip client_port server_ip server_port").
export SSH_CONNECTION="192.0.2.1 50000 $SERVER_IP 22"
printf '%s\n%s\n' "$VPN_USER" "$VPN_PASS" | bash installVPN.sh

# Back up again, as a re-run of the installer would. The .bak files must keep the originals.
# shellcheck source=../server/utils/functions
source utils/functions
for f in "${BACKED_UP[@]}"; do
    backup "$f"
done
backup_sums=$(sudo sha256sum "${BACKED_UP[@]/%/.bak}" | sed 's/\.bak$//')

failures=0
check() {
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        failures=$((failures + 1))
    fi
}

check 'strongSwan is running' sudo systemctl is-active --quiet strongswan-starter
check 'ikev2-vpn connection is loaded' grep -q 'ikev2-vpn:.*IKEv2' <(sudo ipsec statusall)
check 'server certificate is issued for the server IP' \
    grep -q "IP Address:$SERVER_IP" <(sudo openssl x509 -in /etc/ipsec.d/certs/server-cert.pem -noout -text)
check 'VPN user is in ipsec.secrets' sudo grep -q "^$VPN_USER : EAP " /etc/ipsec.secrets
check 'backups hold the original files, even after backing up again' test "$backup_sums" = "$original_sums"
check 'ufw is active' grep -q '^Status: active' <(sudo ufw status)
check 'ufw allows IKE (500,4500/udp)' grep -Eq '^500,4500/udp +ALLOW' <(sudo ufw status)
check 'ufw allows the SSH port (22/tcp)' grep -Eq '^22/tcp +ALLOW' <(sudo ufw status)
check 'VPN clients are NATed' grep -Eq -- '-s 10.10.10.0/24 -o .* -j MASQUERADE' <(sudo iptables -t nat -S POSTROUTING)
check 'IP forwarding is on' test "$(sysctl -n net.ipv4.ip_forward)" = 1
check 'CA certificate was exported' test -s CA/ca-cert.pem

echo "$failures check(s) failed"
[[ $failures -eq 0 ]]
