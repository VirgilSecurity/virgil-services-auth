PROJECT =virgil-auth
IMAGENAME=$(PROJECT)
DOCKERHUB_REPOSITORY=virgilsecurity/$(IMAGENAME)
BINTRAY_REPOSITORY=virgilsecurity-docker-core.bintray.io/services/$(IMAGENAME)
GO_GET=github.com/VirgilSecurity/virgil-services-auth
TARGET_OS ?= $(shell go env GOOS)
VERSION=$(shell git describe --tags --always)

ifeq ($(TARGET_OS),darwin)
ARTF_OS_NAME?=macosx
else
ARTF_OS_NAME?=$(TARGET_OS)
endif

ifeq ($(TARGET_OS),windows)
BINARY?=$(PROJECT).exe
C_CRYPTO=false
else
BINARY?=$(PROJECT)
C_CRYPTO?=true
endif


LDF_FLAGS=-X main.Version=$(VERSION)
ifneq ($(TARGET_OS),darwin)
LDF_FLAGS+= -extldflags "-static"
endif

BUILD_ARGS=--ldflags '$(LDF_FLAGS)'
ifeq ($(C_CRYPTO),true)
BUILD_ARGS+=-tags=c_crypto
endif

.DEFAULT_GOAL := build

define tag_docker
  @if [ "$(GIT_BRANCH)" = "master" ]; then \
    docker tag $(IMAGENAME) $(1):latest; \
  fi
  @if [ "$(GIT_BRANCH)" != "master" ]; then \
    docker tag $(IMAGENAME) $(1):$(GIT_BRANCH); \
  fi
endef

# TEST SECTION
.PHONY: test test_all

test:
	go test -v ./...

test-all:
	go test -v ./... -tags=integration


# BUILD SECTION
.PHONY: clean get build build_in_docker-env

clean:
	rm $(BINARY)

$(GOPATH)/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/virgil_crypto_go.go:
ifeq ($(C_CRYPTO),true)
	go get -d gopkg.in/virgilsecurity/virgil-crypto-go.v4
	cd $$GOPATH/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4 ;	 make
endif

get: $(GOPATH)/src/gopkg.in/virgilsecurity/virgil-crypto-go.v4/virgil_crypto_go.go
	go get -v -d -t -tags docker  ./...

build: get
	CGO_ENABLED=1 GOOS=$(TARGET_OS) go build  $(BUILD_ARGS) -o $(BINARY)

$(BINARY):
	CGO_ENABLED=1 GOOS=$(TARGET_OS) go build  $(BUILD_ARGS) -o $(BINARY)


build-in-docker:
	docker pull virgilsecurity/virgil-crypto-go-env
	docker run -it --rm -v "$$PWD":/go/src/$(GO_GET) -w /go/src/$(GO_GET) virgilsecurity/virgil-crypto-go-env make


# DOCKER SECTION
.PHONY: docker-rebuild docker-build docker-publish docker-dockerhub-publish docker-bintray-publish docker-inspect

docker-rebuild: build docker-build

docker-build: $(BINARY)
	docker build -t $(IMAGENAME) --build-arg VERSION=$(VERSION) .

docker-publish: docker-dockerhub-publish docker-bintray-publish

docker-dockerhub-publish:
	$(call tag_docker, $(DOCKERHUB_REPOSITORY))
	docker push $(DOCKERHUB_REPOSITORY)

docker-bintray-publish:
		$(call tag_docker, $(BINTRAY_REPOSITORY))
		docker push $(DOCKERHUB_REPOSITORY)

docker-inspect:
	docker inspect -f '{{index .ContainerConfig.Labels "version"}}' $(IMAGENAME)

# ARTIFACTS SECTION
.PHONY: build_artifacts

build-artifacts: clean-artifacts $(BINARY)
	mkdir -p artf/src/$(PROJECT)
	mv $(BINARY) artf/src/$(PROJECT)/

ifeq ($(TARGET_OS),windows)
	cd artf/src &&	zip -r ../$(ARTF_OS_NAME)-amd64.zip . &&	cd ../..
else
	tar -zcvf artf/$(ARTF_OS_NAME)-amd64.tar.gz -C artf/src .
endif

	rm -rf artf/src

clean-artifacts:
	rm -rf artf
