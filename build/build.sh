#!/bin/bash
#
# Copyright (c) Johannes Feichtner <johannes@web-wack.at>
#
# Script to build letsencrypt-esxi VIB using VIB Author

LOCALDIR=$(dirname "$(readlink -f "$0")")
cd "${LOCALDIR}/.." || exit

docker rmi -f letsencrypt-esxi 2> /dev/null
rm -rf artifacts
docker build -t letsencrypt-esxi -f build/Dockerfile .
docker run -i -v "${PWD}"/artifacts:/artifacts letsencrypt-esxi sh << COMMANDS
cp letsencrypt-esxi/build/w2c-letsencrypt-esxi* /artifacts
COMMANDS
