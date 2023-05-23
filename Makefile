VERSION ?= `git describe --tags 2>/dev/null || git rev-parse --short HEAD`
PACKAGE="github.com/archaron/go-yubiserv"
BUILD=`date -u +%s%N`

.PHONY: build vendor
build: vendor

	@echo " 🛠  Building binary..."
	GOOS=linux CGO_ENABLED=0  go build -buildvcs=false -ldflags="-s -w -X ${PACKAGE}/misc.Version=${VERSION} -X ${PACKAGE}/misc.Build=${BUILD}" -o ./bin/yubiserv ./cmd/go-yubiserv && upx -9 ./bin/yubiserv

vendor:
	go mod tidy
	go mod vendor




docker-build:
	/usr/bin/docker run --rm -i -t -e VERSION=${VERSION} -e BUILD=${BUILD} -v `pwd`:/src -w /src archaron/yubiserv-builder:latest

docker-build-shell: vendor
	/usr/bin/docker run --rm -i -t -e VERSION=${VERSION} -e BUILD=${BUILD} -v `pwd`:/src -w /src archaron/yubiserv-builder:latest /bin/bash


docker-builder:
	/usr/bin/docker build ./build -t archaron/yubiserv-builder:latest