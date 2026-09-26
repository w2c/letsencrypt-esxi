#!/bin/bash
#
# Copyright (c) Johannes Feichtner <johannes@web-wack.at>
#
# Script to build letsencrypt-esxi VIB using VIB Author

LOCALDIR=$(dirname "$(readlink -f "$0")")
TEMP_DIR=/tmp/letsencrypt-esxi-$$

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

# Create letsencrypt-esxi temp dir
mkdir -p ${TEMP_DIR}
# Create VIB spec payload directory
mkdir -p ${VIB_PAYLOAD_DIR}

# Create target directory
BIN_DIR=${VIB_PAYLOAD_DIR}/opt/w2c-letsencrypt
INIT_DIR=${VIB_PAYLOAD_DIR}/etc/init.d
mkdir -p ${BIN_DIR} ${INIT_DIR}

# Copy files to the corresponding locations
cp -r ../* ${BIN_DIR} 2>/dev/null
cp ../w2c-letsencrypt ${INIT_DIR}

# Ensure that shell scripts are executable
chmod +x ${INIT_DIR}/w2c-letsencrypt ${BIN_DIR}/renew.sh ${BIN_DIR}/dnsapi/dns_api.sh

# Create tgz with payload
tar czf ${TEMP_DIR}/payload1 -C ${VIB_PAYLOAD_DIR} etc opt

# Create letsencrypt-esxi VIB descriptor.xml
PAYLOAD_FILES=$(tar tf ${TEMP_DIR}/payload1 | grep -v -E '/$' | sed -e 's/^/    <file>/' -e 's/$/<\/file>/')
PAYLOAD_SIZE=$(stat -c %s ${TEMP_DIR}/payload1)
PAYLOAD_SHA256=$(sha256sum ${TEMP_DIR}/payload1 | awk '{print $1}')
PAYLOAD_SHA256_ZCAT=$(zcat ${TEMP_DIR}/payload1 | sha256sum | awk '{print $1}')
PAYLOAD_SHA1_ZCAT=$(zcat ${TEMP_DIR}/payload1 | sha1sum | awk '{print $1}')

cat > ${VIB_DESC_FILE} << __W2C__
<vib version="5.0">
  <type>bootbank</type>
  <name>w2c-letsencrypt-esxi</name>
  <version>${VIB_TAG}-0.0.0</version>
  <vendor>web-wack-creations</vendor>
  <summary>Let's Encrypt for ESXi</summary>
  <description>Let's Encrypt for ESXi</description>
  <release-date>${VIB_DATE}</release-date>
  <urls>
    <url key="letsencrypt-esxi">https://github.com/w2c/letsencrypt-esxi</url>
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
${PAYLOAD_FILES}
  </file-list>
  <acceptance-level>community</acceptance-level>
  <live-install-allowed>true</live-install-allowed>
  <live-remove-allowed>true</live-remove-allowed>
  <cimom-restart>false</cimom-restart>
  <stateless-ready>true</stateless-ready>
  <overlay>false</overlay>
  <payloads>
    <payload name="payload1" type="tgz" size="${PAYLOAD_SIZE}">
        <checksum checksum-type="sha-256">${PAYLOAD_SHA256}</checksum>
        <checksum checksum-type="sha-256" verify-process="gunzip">${PAYLOAD_SHA256_ZCAT}</checksum>
        <checksum checksum-type="sha-1" verify-process="gunzip">${PAYLOAD_SHA1_ZCAT}</checksum>
    </payload>
  </payloads>
</vib>
__W2C__

# Create letsencrypt-esxi VIB
touch ${TEMP_DIR}/sig.pkcs7
ar r w2c-letsencrypt-esxi.vib ${TEMP_DIR}/descriptor.xml ${TEMP_DIR}/sig.pkcs7 ${TEMP_DIR}/payload1

# Create the offline bundle
PYTHONPATH=/opt/vmware/vibtools-6.0.0-847598/bin python -c "import vibauthorImpl; vibauthorImpl.CreateOfflineBundle('w2c-letsencrypt-esxi.vib', 'w2c-letsencrypt-esxi-offline-bundle.zip', True)"

# Show some details about what we have just created
vibauthor -i -v w2c-letsencrypt-esxi.vib

# Remove letsencrypt-esxi temp dir
rm -rf ${TEMP_DIR}
