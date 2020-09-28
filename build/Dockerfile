FROM ubuntu:latest
LABEL maintainer="Alexander Tischenko (tsm@fiberside.ru)"



VOLUME /src
ENV BUILD_DIR="/src"
ENV RELEASEDIR=$BUILD_DIR/release
ENV UNITDIR="/usr/lib/systemd/system/"

RUN set -x \
  && apt update \
  && DEBIAN_FRONTEND="noninteractive" apt install -y golang ca-certificates upx git make ruby-dev build-essential \
  && gem install fpm

WORKDIR /src

CMD ["/src/build/build.sh"]