#!/bin/bash
export USER="nobody"
export GROUP="nogroup"
id -u $USER &>/dev/null || useradd $USER
id -g $USER &>/dev/null || groupadd $GROUP
chown $USER:$GROUP /opt/yubiserv/etc/yubiserv.yaml
systemctl daemon-reload
