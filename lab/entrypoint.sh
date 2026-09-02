#!/bin/sh
set -eu

certificate_algorithm="${CERTIFICATE_ALGORITHM:-RSA}"
tls_groups="${TLS_GROUPS:-X25519MLKEM768:X25519}"
server_name="${SERVER_NAME:-pqc-forge.local}"

mkdir -p /opt/nginx/certs /opt/nginx/conf /opt/nginx/logs
test -r "$OPENSSL_CONF"

if [ "$certificate_algorithm" = "RSA" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /opt/nginx/certs/server.key
else
  openssl genpkey -algorithm "$certificate_algorithm" -out /opt/nginx/certs/server.key
fi

openssl req -new -x509 -key /opt/nginx/certs/server.key -subj "/CN=${server_name}" -days 1 -out /opt/nginx/certs/server.crt

sed \
  -e "s|__TLS_GROUPS__|${tls_groups}|g" \
  -e "s|__SERVER_NAME__|${server_name}|g" \
  /opt/nginx/conf/nginx.template.conf > /opt/nginx/conf/nginx.conf

exec nginx -g 'daemon off;'
