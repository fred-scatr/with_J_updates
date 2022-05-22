#!/bin/sh

gcc -o libgcrypt_test_chacha `libgcrypt-config --cflags --libs` stun.c chacha20_libgcrypt.c  -L/usr/lib/x86_64-linux-gnu  -lgcrypt   -lgpg-error -lm
#-Xlinker --verbose

