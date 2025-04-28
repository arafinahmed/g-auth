package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/arafinahmed/g-auth/internal/service"
	"github.com/arafinahmed/g-auth/pkg/auth" // For auth errors like ErrTokenRevoked
)

// contextKey is a type used for context keys to avoid collisions.
type contextKey string

// UserIDKey is the key used to store the user ID in the request context.
const UserIDKey contextKey = "userID"

// JWTMiddleware creates a middleware handler that validates JWT tokens.
func JWTMiddleware(authService service.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Get the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondWithError(w, http.StatusUnauthorized, "Authorization header required")
				return
			}

			// 2. Check if it's a Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				respondWithError(w, http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
				return
			}
			tokenString := parts[1]

			// 3. Validate the token using the auth service
			claims, err := authService.ValidateAccessToken(tokenString)
			if err != nil {
				status := http.StatusUnauthorized
				message := "Invalid or expired token"
				if errors.Is(err, auth.ErrTokenRevoked) {
					message = "Token has been revoked"
				}
				// Consider logging the internal error if it's not a standard token validation error
				respondWithError(w, status, message)
				return
			}

			// 4. Token is valid, add user ID to context
			ctx := context.WithValue(r.Context(), UserIDKey, claims.Subject)

			// 5. Call the next handler with the updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper to send JSON error responses (could be moved to a shared utils package)
func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// Consider a more structured error response
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
