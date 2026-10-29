# syntax=docker/dockerfile:1

# phantomfleet: simulated osquery hosts for an osquery TLS server.
#
# Build from the repository root:
#   docker build -t phantomfleet --build-arg VERSION=$(git describe --tags --always --dirty) .
#
# LICENSE, NOTICE and the third-party licences are in /licenses.
# The final image is distroless/static, runs as an unprivileged user (65532),
# and uses /data as its working directory so the default state file
# (phantomfleet_state.json) lands on a mountable volume.

# Keep in step with the toolchain line in go.mod (CI and release binaries
# are built with that toolchain).
ARG GO_VERSION=1.26.10

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

# Module graph first so dependency downloads are cached across source changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/phantomfleet . \
 && mkdir -p /out/data /out/licenses \
 && cp LICENSE NOTICE /out/licenses/

# Licence and notice files of every module linked into the binary.
RUN --mount=type=cache,target=/go/pkg/mod \
    sh scripts/third-party-licenses.sh /out/licenses/THIRD_PARTY_LICENSES

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="phantomfleet" \
      org.opencontainers.image.description="Simulated osquery hosts for osquery TLS servers (osctrl, Fleet, ...)" \
      org.opencontainers.image.source="https://github.com/huntbase-io/phantomfleet" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/phantomfleet /usr/local/bin/phantomfleet
COPY --from=build /out/licenses /licenses
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/phantomfleet"]
