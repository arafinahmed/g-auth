package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/arafinahmed/g-auth/internal/models"
	"github.com/google/uuid"
)

// postgresUserRepository implements the UserRepository interface for PostgreSQL.
type postgresUserRepository struct {
	db *sql.DB
}

// NewPostgresUserRepository creates a new instance of postgresUserRepository.
func NewPostgresUserRepository(db *sql.DB) UserRepository {
	return &postgresUserRepository{db: db}
}

// CreateUser adds a new user to the PostgreSQL database.
func (r *postgresUserRepository) CreateUser(ctx context.Context, user *models.User) error {
	query := `INSERT INTO users (id, email, password_hash, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5)`

	now := time.Now().UTC()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := r.db.ExecContext(ctx, query, user.ID, user.Email, user.Password, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		// Potential improvement: Check for unique constraint violation on email
		return fmt.Errorf("error creating user: %w", err)
	}
	return nil
}

// GetUserByEmail retrieves a user by their email address from PostgreSQL.
func (r *postgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at
			 FROM users WHERE email = $1`

	user := &models.User{}
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password, // gets the hash
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound // Use the custom error
		}
		return nil, fmt.Errorf("error getting user by email: %w", err)
	}
	return user, nil
}

// GetUserByID retrieves a user by their ID from PostgreSQL.
func (r *postgresUserRepository) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	// Validate the UUID format before querying
	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	query := `SELECT id, email, password_hash, created_at, updated_at
			 FROM users WHERE id = $1`

	user := &models.User{}
	err = r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.Password, // gets the hash
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound // Use the custom error
		}
		return nil, fmt.Errorf("error getting user by ID: %w", err)
	}
	return user, nil
}
