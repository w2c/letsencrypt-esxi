#!/bin/bash
#
# Copyright (c) Johannes Feichtner <johannes@web-wack.at>
#
# Script to build acme-esxi VIB using VIB Author

LOCALDIR=$(dirname "$(readlink -f "$0")")
TEMP_DIR=/tmp/acme-esxi-$$

# Ensure prerequisites are installed
git version > /dev/null 2>&1
if [ $? -eq 1 ]; then
  echo "git not installed, exiting..."
  exit 1
fi

vibauthor --version > /dev/null 2>&1
if [ $? -eq 1 ]; then
  echo "vibauthor not installed, exiting .."
  exit 1
fi

# Define VIB metadata
cd "${LOCALDIR}" || exit

VIB_DATE=$(date --date="$(git log -n1 --format="%cd" --date="iso")" '+%Y-%m-%dT%H:%I:%S')
VIB_TAG=$(git describe --tags --abbrev=0 --match '[0-9]*.[0-9]*.[0-9]*' 2> /dev/null || echo 0.0.1)

# Setting up VIB spec confs
VIB_DESC_FILE=${TEMP_DIR}/descriptor.xml
VIB_PAYLOAD_DIR=${TEMP_DIR}/payloads/payload1

# Create acme-esxi temp dir
mkdir -p ${TEMP_DIR}
# Create VIB spec payload directory
mkdir -p ${VIB_PAYLOAD_DIR}

# Create acme-esxi VIB descriptor.xml
cat > ${VIB_DESC_FILE} << __W2C__
<vib version="5.0">
  <type>bootbank</type>
  <name>acme-esxi</name>
  <version>${VIB_TAG}-0.0.0</version>
  <vendor>natethesage</vendor>
  <summary>ACME and Let's Encrypt for ESXi</summary>
  <description>ACME and Let's Encrypt for ESXi</description>
  <release-date>${VIB_DATE}</release-date>
  <urls>
    <url key="acme-esxi">https://github.com/NateTheSage/acme-esxi</url>
  </urls>
  <relationships>
    <depends/>
    <conflicts/>
    <replaces/>
    <provides/>
    <compatibleWith/>
  </relationships>
  <software-tags/>
  <system-requires>
    <maintenance-mode>false</maintenance-mode>
  </system-requires>
  <file-list>
  </file-list>
  <acceptance-level>community</acceptance-level>
  <live-install-allowed>true</live-install-allowed>
  <live-remove-allowed>true</live-remove-allowed>
  <cimom-restart>false</cimom-restart>
  <stateless-ready>true</stateless-ready>
  <overlay>false</overlay>
  <payloads>
    <payload name="payload1" type="vgz"></payload>
  </payloads>
</vib>
__W2C__

# Create target directory
BIN_DIR=${VIB_PAYLOAD_DIR}/opt/acme-esxi
INIT_DIR=${VIB_PAYLOAD_DIR}/etc/init.d
mkdir -p ${BIN_DIR} ${INIT_DIR}

# Copy files to the corresponding locations
cp ../* ${BIN_DIR} 2>/dev/null
cp ../acme-esxi ${INIT_DIR}

# Ensure that shell scripts are executable
chmod +x ${INIT_DIR}/acme-esxi ${BIN_DIR}/renew.sh

# Create acme-esxi VIB + offline bundle
vibauthor -C -t ${TEMP_DIR} -v acme-esxi.vib -O acme-esxi-offline-bundle.zip -f

# Show some details about what we have just created
vibauthor -i -v acme-esxi.vib

# Remove acme-esxi temp dir
rm -rf ${TEMP_DIR}
