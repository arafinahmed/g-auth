package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/arafinahmed/g-auth/internal/config" // Import the config package
	_ "github.com/lib/pq"                           // PostgreSQL driver
)

// NewPostgresDB initializes and returns a PostgreSQL database connection pool.
func NewPostgresDB(cfg *config.Config) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBName,
		cfg.DBSslMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Set connection pool settings (optional but recommended)
	db.SetMaxOpenConns(25)                 // Example value
	db.SetMaxIdleConns(25)                 // Example value
	db.SetConnMaxLifetime(5 * time.Minute) // Example value

	// Verify the connection is working
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		db.Close() // Close the connection if ping fails
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	fmt.Println("Successfully connected to PostgreSQL database!")
	return db, nil
}
