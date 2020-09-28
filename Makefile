VERSION ?= `git describe --tags 2>/dev/null || git rev-parse --short HEAD`
PACKAGE="github.com/archaron/go-yubiserv"
BUILD=`date -u +%s%N`

.PHONY: build vendor
build:
	@echo " 🛠  Building binary..."
	GOOS=linux go build -ldflags="-s -w -X ${PACKAGE}/misc.Version=${VERSION} -X ${PACKAGE}/misc.Build=${BUILD}" -o ./bin/yubiserv ./cmd/go-yubiserv && upx -9 ./bin/yubiserv

vendor:
	go mod tidy
	go mod vendor




docker-build:
	docker run --rm -i -t -e VERSION=${VERSION} -e BUILD=${BUILD} -v `pwd`:/src -w /src archaron/yubiserv-builder:latest

docker-build-shell: vendor
	docker run --rm -i -t -e VERSION=${VERSION} -e BUILD=${BUILD} -v `pwd`:/src -w /src archaron/yubiserv-builder:latest /bin/bash


docker-builder:
	docker build ./build -t archaron/yubiserv-builder:latest