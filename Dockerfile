# syntax=docker/dockerfile:1

FROM alpine:latest AS builder

# install build dependencies (musl is Alpine's default libc)
RUN apk add --no-cache make file gcc musl-dev patch cmake wget tar

COPY . /src
WORKDIR /src

ARG APP_VERSION="0.0.0"

# build the binaries using gcc (Alpine already uses musl AFAIK)
RUN set -x \
    && make CC=gcc APP_VERSION="$APP_VERSION" \
    && ./httpcheck --help \
    && ./httpscheck --help \
    && ./portcheck --help \
    && ./parallel --help \
    && ./pidcheck --help \
    && ls -lh .

WORKDIR /tmp/rootfs

# prepare the rootfs for scratch
RUN set -x \
    && mkdir -p ./bin ./etc \
    && mv /src/httpcheck ./bin/httpcheck \
    && mv /src/httpscheck ./bin/httpscheck \
    && mv /src/portcheck ./bin/portcheck \
    && mv /src/parallel ./bin/parallel \
    && mv /src/pidcheck ./bin/pidcheck \
    && echo 'nobody:x:10001:10001::/nonexistent:/sbin/nologin' > ./etc/passwd \
    && echo 'nogroup:x:10001:' > ./etc/group

# use empty filesystem
FROM scratch AS runtime

ARG APP_VERSION="0.0.0"

LABEL \
    # Docs: <https://github.com/opencontainers/image-spec/blob/master/annotations.md>
    org.opencontainers.image.title="microcheck" \
    org.opencontainers.image.description="Lightweight health check utilities for Docker containers" \
    org.opencontainers.image.url="https://github.com/tarampampam/microcheck" \
    org.opencontainers.image.source="https://github.com/tarampampam/microcheck" \
    org.opencontainers.image.vendor="tarampampam" \
    org.opencontainers.version="$APP_VERSION" \
    org.opencontainers.image.licenses="MIT"

# use the unprivileged user
USER 10001:10001

# import from builder
COPY --from=builder /tmp/rootfs /
