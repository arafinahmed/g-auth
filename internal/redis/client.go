package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/arafinahmed/g-auth/internal/config"
	"github.com/redis/go-redis/v9"
)

// NewRedisClient initializes and returns a Redis client connection.
func NewRedisClient(cfg *config.Config) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword, // no password set if empty
		DB:       cfg.RedisDB,       // use default DB if 0
	}

	rdb := redis.NewClient(opts)

	// Verify the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status := rdb.Ping(ctx)
	if err := status.Err(); err != nil {
		rdb.Close() // Close the connection if ping fails
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	fmt.Println("Successfully connected to Redis!")
	return rdb, nil
}
