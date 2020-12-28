#!/bin/bash
# Get the full path of this script so we can access the correct log directories

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SURICATA_LOGS="${DIR}/logs/suricata/eve.json"
ZEEK_LOGS="${DIR}/logs/zeek/*.log"
ZEEK_FILES="${DIR}/logs/zeek/extracted_files/*.*"
echo "Deleting ${SURICATA_LOGS}"
rm -f ${SURICATA_LOGS}
echo "Deleting ${ZEEK_LOGS}"
rm -f ${ZEEK_LOGS}
echo "Deleting ${ZEEK_FILES}"
rm -f ${ZEEK_FILES}