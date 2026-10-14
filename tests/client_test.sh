#!/bin/bash
# Connect to the VPN server as an EAP (username/password) client and send traffic
# through the tunnel. Runs as root inside a throwaway privileged container.
set -euo pipefail

[[ $# -eq 4 ]] || { echo "Usage: $0 SERVER_IP VPN_USER VPN_PASS CA_CERT"; exit 1; }
SERVER_IP=$1
VPN_USER=$2
VPN_PASS=$3
CA_CERT=$4

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq strongswan libcharon-extra-plugins curl iproute2 >/dev/null

cp "$CA_CERT" /etc/ipsec.d/cacerts/vpn-ca.pem
cat > /etc/ipsec.conf <<EOF
conn ikev2-vpn
    keyexchange=ikev2
    right=$SERVER_IP
    rightid=$SERVER_IP
    rightauth=pubkey
    rightsubnet=0.0.0.0/0
    leftauth=eap-mschapv2
    leftsourceip=%config
    eap_identity=$VPN_USER
    auto=add
EOF

set_password() {
    echo "$VPN_USER : EAP \"$1\"" > /etc/ipsec.secrets
    ipsec rereadsecrets
}
# `ipsec up` exits 0 even when the connection fails, so check its output instead.
connect() {
    ipsec up ikev2-vpn > /tmp/ipsec-up.log 2>&1 || true
    cat /tmp/ipsec-up.log
    grep -q 'established successfully' /tmp/ipsec-up.log
}

trap '[[ $? -eq 0 ]] || ipsec statusall' EXIT

ipsec start
for _ in {1..30}; do
    ipsec statusall 2>/dev/null | grep -q 'ikev2-vpn:' && break
    sleep 1
done

echo '--- a wrong password must be rejected'
set_password 'wrong-password'
if connect; then
    echo 'FAIL: connected with a wrong password'
    exit 1
fi
echo 'PASS: wrong password rejected'

echo '--- the right password must connect and carry traffic'
set_password "$VPN_PASS"
connect || { echo 'FAIL: could not connect with the right password'; exit 1; }
ip -4 addr show | grep -q 'inet 10\.10\.10\.' || { echo 'FAIL: no virtual IP from 10.10.10.0/24'; exit 1; }
echo 'PASS: got a virtual IP'
# Use an IP literal so the check doesn't depend on DNS.
curl -sS --max-time 20 --retry 3 https://1.1.1.1/cdn-cgi/trace >/dev/null
ipsec statusall | grep -Eq '[1-9][0-9]* bytes_o' || { echo 'FAIL: no traffic went through the tunnel'; exit 1; }
echo 'PASS: internet traffic goes through the tunnel'
