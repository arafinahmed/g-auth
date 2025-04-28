package repository

import (
	"context"
	"errors"

	"github.com/arafinahmed/g-auth/internal/models"
)

// ErrUserNotFound is returned when a user is not found in the repository.
var ErrUserNotFound = errors.New("user not found")

// UserRepository defines the interface for interacting with user data storage.
type UserRepository interface {
	// CreateUser adds a new user to the storage.
	CreateUser(ctx context.Context, user *models.User) error

	// GetUserByEmail retrieves a user by their email address.
	// It should return ErrUserNotFound if the user does not exist.
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)

	// GetUserByID retrieves a user by their ID (useful for token validation, etc.).
	// It should return ErrUserNotFound if the user does not exist.
	GetUserByID(ctx context.Context, id string) (*models.User, error) // Added GetUserByID as it's often useful
}
