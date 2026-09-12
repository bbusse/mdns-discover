ARG GO_VERSION=1.25
ARG IMAGE_VERSION=edge

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/mdns-discover .

FROM alpine:${IMAGE_VERSION}
LABEL maintainer="Björn Busse <bj.rn@baerlin.eu>"
LABEL org.opencontainers.image.source=https://github.com/bbusse/mdns-discover

ENV USER="mdns"

COPY --from=build /out/mdns-discover /usr/local/bin/

# Add application user
RUN addgroup -S $USER && adduser -S $USER -G $USER

USER $USER

# Add entrypoint
ENTRYPOINT ["mdns-discover"]
