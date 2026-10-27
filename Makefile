# Image name including registry/user, e.g. IMAGE=myuser/linode-ddns or
# IMAGE=ghcr.io/myuser/linode-ddns. Required for push.
IMAGE     ?= linode-ddns
# Image version tag, read from the VERSION file.
VERSION   ?= $(shell cat VERSION)
# Every platform the distroless runtime image is published for.
PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7,linux/ppc64le,linux/s390x
BUILDER   ?= multiarch

BUILDX = docker buildx build --builder $(BUILDER) --platform $(PLATFORMS) \
	-t $(IMAGE):$(VERSION) -t $(IMAGE):latest

.PHONY: help test bin image builder build push clean

help:
	@echo "make test     run go vet and tests"
	@echo "make bin      build ./linode-ddns for this machine"
	@echo "make image    build $(IMAGE):latest for this machine into local docker"
	@echo "make build    build all platforms ($(PLATFORMS)) into the buildx cache"
	@echo "make push     push $(IMAGE):$(VERSION) and :latest for all platforms (run build first)"
	@echo "make clean    remove ./linode-ddns and the buildx builder"
	@echo
	@echo "Variables: IMAGE=$(IMAGE) VERSION=$(VERSION) BUILDER=$(BUILDER)"

test:
	go vet ./...
	go test -race ./...

bin:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o linode-ddns ./cmd/linode-ddns

image:
	docker build -t $(IMAGE):latest .

builder:
	@docker buildx inspect $(BUILDER) >/dev/null 2>&1 || \
		docker buildx create --name $(BUILDER) --driver docker-container

# Multi-platform images can't be loaded into the local docker image store, so
# build leaves the result in the builder's cache and push reuses it.
build: builder
	$(BUILDX) .

push: builder
	@case "$(IMAGE)" in */*) ;; *) \
		echo "IMAGE must include a registry or user, e.g. make push IMAGE=myuser/linode-ddns"; exit 1;; esac
	$(BUILDX) --push .

clean:
	rm -f linode-ddns
	-docker buildx rm $(BUILDER)
