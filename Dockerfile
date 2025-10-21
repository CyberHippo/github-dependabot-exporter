FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -v -o /usr/local/bin/dependabot_prom_exporter ./...

FROM gcr.io/distroless/static:nonroot
WORKDIR /

COPY --from=builder /usr/local/bin/dependabot_prom_exporter /usr/local/bin/dependabot_prom_exporter
USER 65532:65532

ENTRYPOINT ["dependabot_prom_exporter"]
