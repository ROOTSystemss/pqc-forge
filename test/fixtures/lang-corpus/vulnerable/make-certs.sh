#!/bin/sh
set -e
openssl genrsa -out server.key 2048
openssl ecparam -name prime256v1 -genkey -out ec.key
openssl req -new -newkey rsa:3072 -nodes -keyout k.pem -out r.csr -subj "/CN=x"