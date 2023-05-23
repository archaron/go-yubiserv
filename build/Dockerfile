FROM ubuntu:latest
LABEL maintainer="Alexander Tischenko (tsm@fiberside.ru)"



VOLUME /src
ENV BUILD_DIR="/src"
ENV RELEASEDIR=$BUILD_DIR/release
ENV UNITDIR="/usr/lib/systemd/system/"

RUN set -x \
  && apt update \
  && DEBIAN_FRONTEND="noninteractive" apt install -y wget ca-certificates upx git make ruby-dev build-essential \
  && mkdir temp \
  && cd temp \
  && wget https://dl.google.com/go/go1.20.linux-amd64.tar.gz \
  && tar -xvf go1.20.linux-amd64.tar.gz \
  && mv go /usr/local \
  && export GOROOT=/usr/local/go \
  && export GOPATH=$HOME/go \
  && export PATH=$GOPATH/bin:$GOROOT/bin:$PATH \
  && gem install fpm

WORKDIR /src

CMD ["/src/build/build.sh"]