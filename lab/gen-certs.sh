#!/bin/sh
set -eu

# Standalone cert-gen entrypoint for services whose TLS termination is not
# this image's own nginx build (currently: the Envoy lab services, which use
# the official envoyproxy/envoy image and cannot generate their own
# certificates). Writes into a shared volume that those services mount.

certificate_algorithm="${CERTIFICATE_ALGORITHM:-RSA}"
server_name="${SERVER_NAME:-pqc-forge.local}"
out_dir="${CERT_DIR:-/certs}"

mkdir -p "$out_dir"
test -r "$OPENSSL_CONF"

if [ "$certificate_algorithm" = "RSA" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$out_dir/server.key"
else
  openssl genpkey -algorithm "$certificate_algorithm" -out "$out_dir/server.key"
fi

openssl req -new -x509 -key "$out_dir/server.key" -subj "/CN=${server_name}" -days 1 -out "$out_dir/server.crt"
