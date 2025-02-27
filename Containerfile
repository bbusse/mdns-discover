ARG IMAGE_VERSION=edge
FROM alpine:${IMAGE_VERSION}
LABEL maintainer="Björn Busse <bj.rn@baerlin.eu>"
LABEL org.opencontainers.image.source=https://github.com/bbusse/mdns-discover

ENV ARCH="x86_64" \
    USER="mdns"

COPY --from=ghcr.io/bbusse/mdns-discover-build:latest /tmp/mdns-discover/mdns-discover /usr/local/bin/

# Add application user
RUN addgroup -S $USER && adduser -S $USER -G $USER

USER $USER

# Add entrypoint
ENTRYPOINT ["mdns-discover"]
