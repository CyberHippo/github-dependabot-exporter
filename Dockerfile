FROM golang:1.24-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -v -o /usr/local/bin/dependabot_prom_exporter ./...

FROM golang:1.24-alpine AS main

RUN addgroup -S app && adduser -u 1000 -S app -G app

USER app

COPY --chown=app:app --from=build /usr/local/bin/dependabot_prom_exporter /usr/local/bin/dependabot_prom_exporter

CMD ["dependabot_prom_exporter"]
