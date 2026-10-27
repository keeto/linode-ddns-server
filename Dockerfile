# The build stage runs on the build host's platform and cross-compiles for the
# target, so multi-platform builds don't need emulation.
# Base images are pinned by digest; to update one, take the new digest from
# `docker buildx imagetools inspect <image>:<tag>`.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN if [ "$TARGETARCH" = arm ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/linode-ddns ./cmd/linode-ddns

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/linode-ddns /linode-ddns
EXPOSE 8080
ENTRYPOINT ["/linode-ddns"]
CMD ["--config=/config/linode-ddns.yaml"]
