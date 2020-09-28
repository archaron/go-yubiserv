#!/bin/bash
systemctl daemon-reload
if [ "`systemctl is-active yubiserv`" != "active" ]
then
    systemctl restart yubiserv
fi
