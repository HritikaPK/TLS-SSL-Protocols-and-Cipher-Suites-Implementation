#!/bin/sh

# connect / accept with RSA

rm *.log

CLIENT="main_client2"
SERVER="main_server"

set -e
set -v

(cd ../../src/ssl && make clean && make)

make clean
make $SERVER
make $CLIENT

./$SERVER &

sleep 2

./$CLIENT 1 &
sleep 1
./$CLIENT 2

sleep 8

pkill $SERVER &
pkill $CLIENT






