# ── Stage 1: Build ──────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install dependencies first (cache layer)
COPY go.mod ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o docflow-api ./main.go

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM alpine:3.20

# CA certs for HTTPS/SMTP TLS
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary and migrations
COPY --from=builder /build/docflow-api .
COPY migrations/ ./migrations/

# Create volume directories
RUN mkdir -p /app/uploads /app/archives /app/logs /app/themes

EXPOSE 8080
CMD ["./docflow-api"]
