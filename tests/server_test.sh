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
    libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libtss2-tcti-tabrmd0 \
    inotify-tools

# Files installVPN.sh backs up before changing them; remember their original content.
BACKED_UP=(/etc/ipsec.conf /etc/ipsec.secrets /etc/ufw/before.rules /etc/ufw/sysctl.conf)
original_sums=$(sudo sha256sum "${BACKED_UP[@]}")

# installVPN.sh reads the server IP and SSH port from SSH_CONNECTION
# ("client_ip client_port server_ip server_port").
export SSH_CONNECTION="192.0.2.1 50000 $SERVER_IP 22"

# Log every permission change on before.rules while the installer runs: it must never chmod it
# (it used to make it world-writable while editing it). Also note existing mktemp dirs in /tmp.
# The log goes in a private dir: root may not open a file another user owns in sticky /tmp.
attrib_log=$(mktemp -d)/attrib.log
tmp_before=$(ls -d /tmp/tmp.* 2>/dev/null || true)
sudo inotifywait -m -q -e attrib -o "$attrib_log" /etc/ufw/before.rules &
sleep 1

printf '%s\n%s\n' "$VPN_USER" "$VPN_PASS" | bash installVPN.sh
sudo pkill -x inotifywait
tmp_after=$(ls -d /tmp/ipsec.conf /tmp/rule_sec* /tmp/tmp.* 2>/dev/null || true)

# Back up again, as a re-run of the installer would. The .bak files must keep the originals.
# shellcheck source=../server/utils/functions
source utils/functions
for f in "${BACKED_UP[@]}"; do
    backup "$f"
done
backup_sums=$(sudo sha256sum "${BACKED_UP[@]/%/.bak}" | sed 's/\.bak$//')

# addUser.sh must ask again for an invalid name and an existing name. A name that is only
# part of an existing one (e.g. "ci-use") is a new name. Its password is stored as an NT hash;
# "password" has the well-known NT hash 8846f7eaee8fb117ad06bdd830b7586c.
NEW_USER=${VPN_USER%?}
printf '%s\n' 'bad name' "$VPN_USER" "$NEW_USER" 'password' | bash addUser.sh
# ...and stop at the end of input instead of asking forever.
add_user_eof=0
printf 'bad name\n' | timeout 10 bash addUser.sh || add_user_eof=$?

# addUser.sh restarts strongSwan: wait until it has loaded the connection again
for _ in {1..30}; do
    sudo ipsec statusall 2>/dev/null | grep -q 'ikev2-vpn:.*IKEv2' && break
    sleep 1
done

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
check 'CA private key is not installed in /etc/ipsec.d' sudo test ! -e /etc/ipsec.d/private/ca-key.pem
check 'installed server key is owner-only' test "$(sudo stat -c %a /etc/ipsec.d/private/server-key.pem)" = 600
check 'generated private keys are owner-only' \
    test "$(stat -c %a ~/pki/private/ca-key.pem ~/pki/private/server-key.pem | sort -u)" = 600
check 'VPN user is in ipsec.secrets as an NT hash' sudo grep -Eq "^$VPN_USER : NTLM 0x[0-9a-f]{32}$" /etc/ipsec.secrets
check 'no password is stored in plain text' \
    test "$(sudo grep -cF -e ' : EAP ' -e "$VPN_PASS" /etc/ipsec.secrets)" = 0
check 'addUser.sh did not add an existing user again' test "$(sudo grep -c "^$VPN_USER : " /etc/ipsec.secrets)" = 1
check 'addUser.sh added a new user whose name is part of an existing one' \
    sudo grep -qxF "$NEW_USER : NTLM 0x8846f7eaee8fb117ad06bdd830b7586c" /etc/ipsec.secrets
check 'addUser.sh wrote no invalid name' test "$(sudo grep -c 'bad name' /etc/ipsec.secrets)" = 0
check 'addUser.sh stops at end of input' test "$add_user_eof" = 1
check 'backups hold the original files, even after backing up again' test "$backup_sums" = "$original_sums"
check 'before.rules permissions were never changed during install' test ! -s "$attrib_log"
check 'before.rules is still root-owned with mode 640' test "$(sudo stat -c '%U %a' /etc/ufw/before.rules)" = 'root 640'
check 'no installer temp files left in /tmp' test "$tmp_after" = "$tmp_before"
check 'ufw is active' grep -q '^Status: active' <(sudo ufw status)
check 'ufw allows IKE (500,4500/udp)' grep -Eq '^500,4500/udp +ALLOW' <(sudo ufw status)
check 'ufw allows the SSH port (22/tcp)' grep -Eq '^22/tcp +ALLOW' <(sudo ufw status)
check 'VPN clients are NATed' grep -Eq -- '-s 10.10.10.0/24 -o .* -j MASQUERADE' <(sudo iptables -t nat -S POSTROUTING)
check 'IP forwarding is on' test "$(sysctl -n net.ipv4.ip_forward)" = 1
check 'CA certificate was exported' test -s CA/ca-cert.pem

echo "$failures check(s) failed"
[[ $failures -eq 0 ]]
