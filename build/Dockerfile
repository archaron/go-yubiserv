FROM golang:1.25-bookworm
LABEL maintainer="Alexander Tischenko (tsm@fiberside.ru)"

VOLUME /src
ENV BUILD_DIR="/src"
ENV RELEASEDIR=$BUILD_DIR/release
ENV UNITDIR="/usr/lib/systemd/system/"

RUN set -x \
  && apt update \
  && DEBIAN_FRONTEND="noninteractive" apt install -y wget ca-certificates git make ruby-dev build-essential

RUN  cd /tmp \
  && wget https://github.com/upx/upx/releases/download/v4.2.3/upx-4.2.3-amd64_linux.tar.xz \
  && tar -xf upx-4.2.3-amd64_linux.tar.xz
RUN cp /tmp/upx-4.2.3-amd64_linux/upx /sbin \
    && chmod +x /sbin/upx
RUN gem install fpm

WORKDIR /src

CMD ["/src/build/build.sh"]