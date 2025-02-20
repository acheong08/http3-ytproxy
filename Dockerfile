FROM golang:alpine3.21 AS build

WORKDIR /app/
RUN go env -w GOMODCACHE=/root/.cache/go-build

RUN apk add --no-cache build-base libwebp-dev git

COPY .git .git
COPY . .

RUN  --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags "-s -w -X 'main.version=$(date '+%Y-%m-%d')-$(git rev-list --abbrev-commit -1 HEAD)'" ./cmd/http3-ytproxy

FROM alpine:3.21

RUN adduser -u 10001 -S appuser

RUN apk add --no-cache libwebp

WORKDIR /app/

COPY --from=build /app/http3-ytproxy /app/http3-ytproxy

# Switch to non-privileged user
USER appuser

ENTRYPOINT ["/app/http3-ytproxy"]