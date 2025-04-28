# ---- Build Stage ----
FROM golang:1.24-alpine3.20 AS builder
WORKDIR /app

# Install git (for go mod download if needed)
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source
COPY . .

# Build the Go app (static binary)
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-server ./cmd/app/main.go

# ---- Run Stage ----
FROM alpine:latest
WORKDIR /app

# Copy binary and necessary files
COPY --from=builder /app/auth-server ./auth-server
COPY .env .env
COPY migrations ./migrations
COPY docs ./docs

EXPOSE 8080

# Run the app
CMD ["./auth-server"]
