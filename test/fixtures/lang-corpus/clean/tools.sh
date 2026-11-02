#!/bin/sh
# openssl genrsa -out old.key 2048   (commented out)
openssl rand -hex 32
openssl dgst -sha256 file.txt