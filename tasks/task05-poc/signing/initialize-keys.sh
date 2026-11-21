#!/bin/sh
set -eu

if [ ! -s /private/signing-private.pem ] || [ ! -s /trust/signing-public.pem ]; then
    umask 077
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /private/signing-private.pem
    chmod 0400 /private/signing-private.pem
    openssl pkey -in /private/signing-private.pem -pubout -out /trust/signing-public.pem
    chmod 0444 /trust/signing-public.pem
fi
