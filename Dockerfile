# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/lanmonitor ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache libcap ca-certificates
WORKDIR /app
COPY --from=build /out/lanmonitor /app/lanmonitor
# Grant raw-socket capabilities so the binary can send/receive ARP frames
# without running the container as root.
RUN setcap cap_net_raw,cap_net_admin+eip /app/lanmonitor

EXPOSE 8080
VOLUME ["/app/data"]
ENTRYPOINT ["/app/lanmonitor", "-db", "/app/data/lanmonitor.db"]
