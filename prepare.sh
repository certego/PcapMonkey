#!/bin/sh

sudo chown 1000:1000 ./config/filebeat/filebeat.yml 
sudo chown -R 1000:1000 ./config/filebeat/modules.d/

sudo chmod 644 ./config/filebeat/filebeat.yml
sudo chmod 644 ./config/filebeat/modules.d/*

if [[ "$1" == "win" ]]; then
    sed -i -e 's/\/var\/lib\/suricata\/rules\//\/var\/lib\/suricata\/rules/g' ./docker-compose.yaml
fi
