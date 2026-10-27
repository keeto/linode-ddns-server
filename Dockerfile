# The build stage runs on the build host's platform and cross-compiles for the
# target, so multi-platform builds don't need emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN if [ "$TARGETARCH" = arm ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/linode-ddns ./cmd/linode-ddns

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/linode-ddns /linode-ddns
EXPOSE 8080
ENTRYPOINT ["/linode-ddns"]
CMD ["--config=/config/linode-ddns.yaml"]
