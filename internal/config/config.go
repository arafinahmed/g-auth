package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv" // To load .env file
)

// Config holds the application configuration.
// Values are typically loaded from environment variables or a .env file.
type Config struct {
	// Server configuration
	ServerPort string `env:"SERVER_PORT"`

	// Database configuration (PostgreSQL)
	DBHost     string `env:"DB_HOST"`
	DBPort     string `env:"DB_PORT"`
	DBUser     string `env:"DB_USER"`
	DBPassword string `env:"DB_PASSWORD"`
	DBName     string `env:"DB_NAME"`
	DBSslMode  string `env:"DB_SSLMODE"` // e.g., "disable", "require", "verify-full"

	// Redis configuration
	RedisAddr     string `env:"REDIS_ADDR"`
	RedisPassword string `env:"REDIS_PASSWORD"` // Empty if no password
	RedisDB       int    `env:"REDIS_DB"`       // e.g., 0

	// JWT configuration
	JWTSecret               string `env:"JWT_SECRET"`
	JWTAccessTokenExpiryMin int    `env:"JWT_ACCESS_TOKEN_EXPIRY_MIN"`
	JWTRefreshTokenExpiryDays int    `env:"JWT_REFRESH_TOKEN_EXPIRY_DAYS"`
}

// LoadConfig loads configuration from environment variables.
// It prioritizes environment variables over a .env file if both exist.
func LoadConfig(envFilePath string) (*Config, error) {
	// Attempt to load .env file if path is provided
	if envFilePath != "" {
		_ = godotenv.Load(envFilePath) // Ignore error if .env doesn't exist
	}

	cfg := &Config{}
	var err error

	// Load server config
	cfg.ServerPort = getEnv("SERVER_PORT", "8080")

	// Load DB config
	cfg.DBHost = getEnv("DB_HOST", "localhost")
	cfg.DBPort = getEnv("DB_PORT", "5432")
	cfg.DBUser = getEnv("DB_USER", "")
	cfg.DBPassword = getEnv("DB_PASSWORD", "")
	cfg.DBName = getEnv("DB_NAME", "")
	cfg.DBSslMode = getEnv("DB_SSLMODE", "disable")

	// Load Redis config
	cfg.RedisAddr = getEnv("REDIS_ADDR", "localhost:6379")
	cfg.RedisPassword = getEnv("REDIS_PASSWORD", "")
	cfg.RedisDB, err = getEnvAsInt("REDIS_DB", 0)
	if err != nil {
		return nil, errors.New("invalid REDIS_DB value: " + err.Error())
	}

	// Load JWT config
	cfg.JWTSecret = getEnv("JWT_SECRET", "")
	if cfg.JWTSecret == "" {
		return nil, errors.New("JWT_SECRET environment variable is required")
	}
	cfg.JWTAccessTokenExpiryMin, err = getEnvAsInt("JWT_ACCESS_TOKEN_EXPIRY_MIN", 15)
	if err != nil {
		return nil, errors.New("invalid JWT_ACCESS_TOKEN_EXPIRY_MIN value: " + err.Error())
	}
	cfg.JWTRefreshTokenExpiryDays, err = getEnvAsInt("JWT_REFRESH_TOKEN_EXPIRY_DAYS", 7)
	if err != nil {
		return nil, errors.New("invalid JWT_REFRESH_TOKEN_EXPIRY_DAYS value: " + err.Error())
	}

	// Basic validation
	if cfg.DBUser == "" || cfg.DBName == "" {
		// Allow empty password, but user and db name are usually required
		// You might adjust this validation based on your setup
		println("Warning: DB_USER or DB_NAME environment variables are not set.")
	}

	return cfg, nil
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsInt retrieves an environment variable as an integer or returns a default value.
func getEnvAsInt(key string, defaultValue int) (int, error) {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue, fmt.Errorf("invalid integer value for %s: %w", key, err)
	}
	return value, nil
}
