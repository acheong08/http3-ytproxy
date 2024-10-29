FROM golang:alpine AS build

WORKDIR /app/

RUN apk add --no-cache build-base libwebp-dev

COPY . .

RUN  --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags "-s -w -X 'main.version=$(date '+%Y-%m-%d')-$(git rev-list --abbrev-commit -1 HEAD)'"

FROM alpine:edge

RUN apk add --no-cache libwebp

WORKDIR /app/

COPY --from=build /app/http3-ytproxy /app/http3-ytproxy

CMD ./http3-ytproxy -l 0.0.0.0
