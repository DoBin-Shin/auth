FROM --platform=linux/arm64 golang:1.22.3-alpine3.20 as build
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=arm64

RUN apk add --no-cache make git

WORKDIR /go/src/github.com/DoBin-Shin/auth

# Pulling dependencies
COPY ./Makefile ./go.* ./
RUN make deps

# Building stuff
COPY . /go/src/github.com/DoBin-Shin/auth

# Make sure you change the RELEASE_VERSION value before publishing an image.
RUN RELEASE_VERSION=sha512 make build

# Always use alpine:3 so the latest version is used. This will keep CA certs more up to date.
FROM --platform=linux/arm64 alpine:3
RUN adduser -D -u 1000 dobin

RUN apk add --no-cache ca-certificates
COPY --from=build /go/src/github.com/DoBin-Shin/auth/auth /usr/local/bin/auth
COPY --from=build /go/src/github.com/DoBin-Shin/auth/migrations /usr/local/etc/auth/migrations/
RUN ln -s /usr/local/bin/auth /usr/local/bin/gotrue

ENV GOTRUE_DB_MIGRATIONS_PATH /usr/local/etc/auth/migrations
ENV AUTH_PASSWORD_HASH_ALGORITHM sha512

USER dobinshin
CMD ["auth"]