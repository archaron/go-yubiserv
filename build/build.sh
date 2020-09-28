#!/bin/bash
set -ex

mkdir -p {$RELEASEDIR/,$RELEASEDIR/build/,$RELEASEDIR/rpm/,$RELEASEDIR/deb/}
rm -rf {$RELEASEDIR/build/*,$RELEASEDIR/rpm/*,$RELEASEDIR/deb/*}
mkdir -p {$RELEASEDIR/build/opt/yubiserv/bin/,$RELEASEDIR/build/opt/yubiserv/etc/,$RELEASEDIR/build/opt/yubiserv/var/db/,$RELEASEDIR/deb/conf,$RELEASEDIR/build/$UNITDIR}

make build

cp ./bin/yubiserv $RELEASEDIR/build/opt/yubiserv/bin
cp ./contrib/yubiserv.yaml.example $RELEASEDIR/build/opt/yubiserv/etc
cp ./contrib/system.d/yubiserv.service $RELEASEDIR/build/$UNITDIR
cp ./contrib/debian-repo-config $RELEASEDIR/deb/conf/distributions
cp ./contrib/yumrepo.repo $RELEASEDIR/rpm/yubiserv.repo

touch $RELEASEDIR/build/opt/yubiserv/etc/yubiserv.yaml



# Build packages
fpm -s dir -t deb -n yubiserv --deb-user="nobody" --deb-group="nogroup" --license=MIT --architecture="amd64" --vendor="Alexander Tischenko <tsm@fiberside.ru>" --deb-systemd=$RELEASEDIR/build/$UNITDIR/yubiserv.service --config-files=/opt/yubiserv/etc --version $VERSION --iteration $BUILD --depends libsqlite3-0 --description "YubiServ - Cloud-free YubiKey verification service." --before-install $BUILD_DIR/contrib/beforeinstall.sh --after-install $BUILD_DIR/contrib/afterinstall.sh --before-remove $BUILD_DIR/contrib/beforeremove.sh --after-upgrade $BUILD_DIR/contrib/afterupgrade.sh -p $RELEASEDIR/deb -C $RELEASEDIR/build .