#!/bin/bash
#
# Copyright (c) Johannes Feichtner <johannes@web-wack.at>
#
# Script to build acme-esxi VIB using VIB Author

LOCALDIR=$(dirname "$(readlink -f "$0")")
cd "${LOCALDIR}/.." || exit

docker rmi -f acme-esxi 2> /dev/null
rm -rf artifacts
docker build -t acme-esxi -f build/Dockerfile .
docker run -i -v "${PWD}"/artifacts:/artifacts acme-esxi sh << COMMANDS
cp acme-esxi/build/acme-esxi* /artifacts
COMMANDS
