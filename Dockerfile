# syntax=docker/dockerfile:1.7
#
# Multi-stage Dockerfile for LemurPouch.
#
#   Stage 1 (portal-build):  Node compiles the React bundle to portal/dist/.
#   Stage 2 (go-build):   Go cross-compiles the relay binary; the
#                         //go:embed directive in main.go bakes in
#                         the dist/ from stage 1.
#   Stage 3 (runtime):    distroless/static — ~2 MB base, no shell,
#                         no package manager, runs as nonroot.
#
# Final image is ~10–15 MB compressed across both archs.

# ---- Stage 1: build the React bundle -----------------------------------
#
# --platform=$BUILDPLATFORM forces this stage to run natively on the
# build host even when the target platform differs (the JS output is
# platform-independent so there is no point running it under qemu).

FROM --platform=$BUILDPLATFORM node:24-alpine AS portal-build
WORKDIR /src/portal

# Copy lockfile + manifest first so the install layer is cached when
# only source files change.
COPY portal/package.json portal/package-lock.json ./
RUN npm ci

COPY portal/ ./
RUN npm run build


# ---- Stage 2: build the Go binary --------------------------------------
#
# --platform=$BUILDPLATFORM keeps the toolchain on the native host;
# Go's GOOS/GOARCH does the cross-compile so we don't pay qemu cost.

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS go-build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Drop the build-host's portal/dist (a .gitkeep stub) and substitute the
# dist/ produced in stage 1, so the //go:embed picks up the real bundle.
RUN rm -rf portal/dist
COPY --from=portal-build /src/portal/dist ./portal/dist

ARG TARGETOS
ARG TARGETARCH
# CGO_ENABLED=0: produce a fully-static binary so we can use
# distroless/static (or scratch) in the runtime stage.
# -ldflags="-s -w": strip the symbol table + DWARF debug info to shave
# a few MB off the final image; the relay never needs them at runtime.
ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/lemurpouch .


# ---- Stage 3: runtime --------------------------------------------------
#
# distroless/static-debian12 has no shell, no package manager, only
# CA certs + tzdata + /etc/passwd entries for root and nonroot. The
# `:nonroot` tag pre-creates the nonroot user (UID 65532); we still
# need to USER it explicitly because the tag doesn't set it.

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=go-build /out/lemurpouch /lemurpouch

USER nonroot:nonroot
EXPOSE 8080

# Tell the binary it's running inside the LemurPouch container image.
# main.go reads this on startup and appends a note to the
# URL-enumeration block clarifying that the listed interface IPs are
# container-internal (bridge addresses, not host LAN). We use a
# project-specific ENV instead of probing /.dockerenv so the hint
# only fires for OUR image — a user `docker cp`-ing the binary out
# and running it bare on the host won't see the in-container note.
ENV LEMURPOUCH_IN_CONTAINER=1

# Default to listening on all interfaces; container users can override
# via `docker run … --listen 127.0.0.1:8080` etc.
ENTRYPOINT ["/lemurpouch"]
CMD ["--listen", ":8080"]

# OCI labels — these flow through to ghcr.io's package page so anyone
# pulling the image can navigate back to the source.
LABEL org.opencontainers.image.title="LemurPouch"
LABEL org.opencontainers.image.description="LemurPouch — LAN file-sharing relay (Go + React), outbound TCP only, end-to-end encrypted between paired peers."
LABEL org.opencontainers.image.source="https://github.com/steelbrain/LemurPouch"
LABEL org.opencontainers.image.licenses="MIT"
