FROM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/web/dist ./internal/web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/panel ./cmd/panel

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/panel /panel
# The image is itself a distributed copy of the software -- Elastic
# License 2.0 requires anyone who gets a copy to also get the terms, and
# the git repo's LICENSE file doesn't travel with a pulled image on its
# own. Served at GET /license.txt (internal/api/api_common.go).
COPY LICENSE /LICENSE
# 8080: the panel's own listener -- HTTPS by default (self-signed at
# minimum, see internal/webtls), plain HTTP only in "proxy" TLS mode.
EXPOSE 8080
# 80: only needed if ACME mode is configured with the http-01 challenge
# (see the Сертификаты page) -- unused and safe to leave unpublished
# otherwise (TLS-ALPN-01, the default ACME challenge, needs no extra port).
EXPOSE 80
ENTRYPOINT ["/panel"]
