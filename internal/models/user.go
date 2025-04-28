package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system.
type User struct {
	ID        uuid.UUID `json:"id" db:"id"`                       // Use UUID for primary key
	Email     string    `json:"email" db:"email"`                   // Unique email
	Password  string    `json:"-" db:"password_hash"`             // Store password hash, omit from JSON responses
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
